#!/usr/bin/env python3
"""
Benchmark UA2F and UA3F traffic handling modes.

This script creates a temporary network namespace as the benchmark client and
runs the HTTP origin server, UA2F/UA3F, and netfilter rules in the host
namespace. Transparent modes are tested through PREROUTING on a veth pair, so
NFQUEUE, REDIRECT, and TPROXY are exercised in the same packet path they use on
a router.

Example:
    sudo python3 scripts/benchmark.py \
        --ua2f ./build/ua2f \
        --ua3f ./ref/UA3F/ua3f \
        --requests 5000 \
        --concurrency 32
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import http.server
import json
import os
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


UA2F_QUEUE = 10010
UA3F_QUEUE = 10201
TPROXY_MARK = "0x1c9"
TPROXY_TABLE = "0x1c9"
UA2F_MODES = ("NFQUEUE", "REDIRECT", "TPROXY")
UA3F_MODES = ("NFQUEUE", "REDIRECT", "TPROXY", "HTTP", "SOCKS5")
TRANSPARENT_MODES = {"NFQUEUE", "REDIRECT", "TPROXY"}
EXPLICIT_PROXY_MODES = {"HTTP", "SOCKS5"}


CLIENT_CODE = r"""
import argparse
import json
import socket
import struct
import threading
import time


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--kind", required=True, choices=["direct", "http-proxy", "socks5"])
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--proxy-host", default="")
    p.add_argument("--proxy-port", default=0, type=int)
    p.add_argument("--requests", required=True, type=int)
    p.add_argument("--concurrency", required=True, type=int)
    p.add_argument("--timeout", required=True, type=float)
    p.add_argument("--path-prefix", default="/bench")
    return p.parse_args()


def connect_socket(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return sock


def socks5_connect(proxy_host, proxy_port, target_host, target_port, timeout):
    sock = connect_socket(proxy_host, proxy_port, timeout)
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise OSError("SOCKS5 auth negotiation failed: %r" % (resp,))

    try:
        addr = socket.inet_aton(target_host)
        req = b"\x05\x01\x00\x01" + addr + struct.pack("!H", target_port)
    except OSError:
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise OSError("SOCKS5 target host is too long")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", target_port)
    sock.sendall(req)

    head = sock.recv(4)
    if len(head) != 4 or head[1] != 0:
        raise OSError("SOCKS5 connect failed: %r" % (head,))
    atyp = head[3]
    if atyp == 1:
        remain = 4 + 2
    elif atyp == 3:
        remain = sock.recv(1)[0] + 2
    elif atyp == 4:
        remain = 16 + 2
    else:
        raise OSError("SOCKS5 unknown address type: %r" % (atyp,))
    while remain > 0:
        chunk = sock.recv(remain)
        if not chunk:
            raise OSError("SOCKS5 short connect response")
        remain -= len(chunk)
    return sock


def open_connection(args):
    if args.kind == "direct":
        return connect_socket(args.host, args.port, args.timeout)
    if args.kind == "http-proxy":
        return connect_socket(args.proxy_host, args.proxy_port, args.timeout)
    if args.kind == "socks5":
        return socks5_connect(args.proxy_host, args.proxy_port, args.host, args.port, args.timeout)
    raise AssertionError(args.kind)


def read_response(sock, pending):
    data = pending
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise OSError("connection closed before response headers")
        data += chunk

    head, data = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    content_length = None
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.lower() == b"content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise OSError("response has no Content-Length")

    while len(data) < content_length:
        chunk = sock.recv(65536)
        if not chunk:
            raise OSError("connection closed before response body")
        data += chunk

    body = data[:content_length]
    rest = data[content_length:]
    return status, len(head) + 4 + len(body), rest


def make_request(args, sock, pending, index):
    path = "%s/%d" % (args.path_prefix, index)
    target = path
    if args.kind == "http-proxy":
        target = "http://%s:%d%s" % (args.host, args.port, path)
    ua = "UA-BENCH/%d" % index
    req = (
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ) % (target, args.host, args.port, ua)
    raw = req.encode("ascii")
    sock.sendall(raw)
    status, recv_bytes, pending = read_response(sock, pending)
    return status, len(raw), recv_bytes, pending


def worker(args, worker_id, count, start_index, out):
    latencies = []
    status_counts = {}
    errors = 0
    samples = []
    bytes_sent = 0
    bytes_recv = 0
    sock = None
    pending = b""

    try:
        sock = open_connection(args)
        for i in range(count):
            idx = start_index + i
            begin = time.perf_counter()
            try:
                status, sent, received, pending = make_request(args, sock, pending, idx)
                elapsed = time.perf_counter() - begin
                latencies.append(elapsed)
                status_counts[str(status)] = status_counts.get(str(status), 0) + 1
                bytes_sent += sent
                bytes_recv += received
            except Exception as exc:
                errors += 1
                if len(samples) < 10:
                    samples.append(str(exc))
                try:
                    if sock is not None:
                        sock.close()
                except OSError:
                    pass
                pending = b""
                try:
                    sock = open_connection(args)
                except Exception as reopen_exc:
                    if len(samples) < 10:
                        samples.append("reopen: %s" % reopen_exc)
                    time.sleep(0.01)
                    sock = None
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass

    out[worker_id] = {
        "latencies": latencies,
        "status_counts": status_counts,
        "errors": errors,
        "error_samples": samples,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
    }


def main():
    args = parse_args()
    total = args.requests
    concurrency = max(1, min(args.concurrency, total if total > 0 else 1))
    counts = [total // concurrency] * concurrency
    for i in range(total % concurrency):
        counts[i] += 1

    starts = []
    n = 0
    for c in counts:
        starts.append(n)
        n += c

    outputs = [None] * concurrency
    begin = time.perf_counter()
    threads = [
        threading.Thread(target=worker, args=(args, i, counts[i], starts[i], outputs))
        for i in range(concurrency)
        if counts[i] > 0
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.perf_counter() - begin

    latencies = []
    status_counts = {}
    errors = 0
    samples = []
    bytes_sent = 0
    bytes_recv = 0
    for item in outputs:
        if not item:
            continue
        latencies.extend(item["latencies"])
        errors += item["errors"]
        bytes_sent += item["bytes_sent"]
        bytes_recv += item["bytes_recv"]
        samples.extend(item["error_samples"])
        for key, value in item["status_counts"].items():
            status_counts[key] = status_counts.get(key, 0) + value

    print(json.dumps({
        "requests": total,
        "completed": len(latencies),
        "errors": errors,
        "error_samples": samples[:20],
        "duration_sec": duration,
        "latencies_sec": latencies,
        "status_counts": status_counts,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "bytes_total": bytes_sent + bytes_recv,
    }))


if __name__ == "__main__":
    main()
"""


class BenchmarkError(RuntimeError):
    pass


@dataclass
class ServerStats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    requests: int = 0
    user_agents: collections.Counter[str] = field(default_factory=collections.Counter)

    def reset(self) -> None:
        with self.lock:
            self.requests = 0
            self.user_agents.clear()

    def record(self, user_agent: str) -> None:
        with self.lock:
            self.requests += 1
            self.user_agents[user_agent] += 1

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "requests": self.requests,
                "user_agents": dict(self.user_agents.most_common(10)),
            }


def make_handler(stats: ServerStats, body: bytes) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            stats.record(self.headers.get("User-Agent", ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


class ReusableThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


@dataclass
class Netns:
    name: str
    host_if: str
    ns_if: str
    server_ip: str
    client_ip: str
    cidr_prefix: int


@dataclass
class Case:
    tool: str
    mode: str
    binary: Path | None = None


@dataclass
class ProcessHandle:
    proc: subprocess.Popen[Any]
    log_path: Path


def run_cmd(args: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, Any] = {"text": True}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    result = subprocess.run(args, **kwargs)
    if check and result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        stdout = result.stdout.strip() if result.stdout else ""
        detail = stderr or stdout
        raise BenchmarkError(f"{' '.join(args)} failed with {result.returncode}: {detail}")
    return result


def run_ignore(args: list[str]) -> None:
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def require_root() -> None:
    if os.name != "posix":
        raise SystemExit("This benchmark must run on Linux.")
    if os.geteuid() != 0:
        raise SystemExit("This benchmark requires root privileges because it creates netns and netfilter rules.")


def require_commands(commands: list[str]) -> None:
    missing = [cmd for cmd in commands if shutil.which(cmd) is None]
    if missing:
        raise SystemExit(f"Missing required command(s): {', '.join(missing)}")


def resolve_binary(explicit: str | None, candidates: list[str]) -> Path | None:
    paths = [explicit] if explicit else []
    paths.extend(candidates)
    for item in paths:
        if not item:
            continue
        path = Path(item).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def setup_netns(ns: Netns) -> None:
    cleanup_netns(ns)
    run_cmd(["ip", "netns", "add", ns.name])
    run_cmd(["ip", "link", "add", ns.host_if, "type", "veth", "peer", "name", ns.ns_if])
    run_cmd(["ip", "link", "set", ns.ns_if, "netns", ns.name])
    run_cmd(["ip", "addr", "add", f"{ns.server_ip}/{ns.cidr_prefix}", "dev", ns.host_if])
    run_cmd(["ip", "link", "set", ns.host_if, "up"])
    run_cmd(["ip", "netns", "exec", ns.name, "ip", "addr", "add", f"{ns.client_ip}/{ns.cidr_prefix}", "dev", ns.ns_if])
    run_cmd(["ip", "netns", "exec", ns.name, "ip", "link", "set", "lo", "up"])
    run_cmd(["ip", "netns", "exec", ns.name, "ip", "link", "set", ns.ns_if, "up"])
    run_cmd(["ip", "netns", "exec", ns.name, "ip", "route", "add", "default", "via", ns.server_ip])


def cleanup_netns(ns: Netns) -> None:
    run_ignore(["ip", "netns", "delete", ns.name])
    run_ignore(["ip", "link", "delete", ns.host_if])


def cleanup_firewall(chain_suffix: str, ns: Netns, server_port: int) -> None:
    mangle_chain = f"UA_BENCH_M_{chain_suffix}"
    nat_chain = f"UA_BENCH_N_{chain_suffix}"
    for _ in range(8):
        run_ignore([
            "iptables", "-t", "mangle", "-D", "PREROUTING",
            "-i", ns.host_if, "-p", "tcp", "--dport", str(server_port), "-j", mangle_chain,
        ])
        run_ignore([
            "iptables", "-t", "nat", "-D", "PREROUTING",
            "-i", ns.host_if, "-p", "tcp", "--dport", str(server_port), "-j", nat_chain,
        ])
    run_ignore(["iptables", "-t", "mangle", "-F", mangle_chain])
    run_ignore(["iptables", "-t", "mangle", "-X", mangle_chain])
    run_ignore(["iptables", "-t", "nat", "-F", nat_chain])
    run_ignore(["iptables", "-t", "nat", "-X", nat_chain])
    run_ignore(["ip", "rule", "del", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE])
    run_ignore(["ip", "route", "flush", "table", TPROXY_TABLE])


def setup_firewall(mode: str, queue_num: int, proxy_port: int, chain_suffix: str, ns: Netns, server_port: int) -> None:
    cleanup_firewall(chain_suffix, ns, server_port)
    mangle_chain = f"UA_BENCH_M_{chain_suffix}"
    nat_chain = f"UA_BENCH_N_{chain_suffix}"

    if mode == "NFQUEUE":
        run_cmd(["iptables", "-t", "mangle", "-N", mangle_chain])
        run_cmd([
            "iptables", "-t", "mangle", "-I", "PREROUTING", "1",
            "-i", ns.host_if, "-p", "tcp", "--dport", str(server_port), "-j", mangle_chain,
        ])
        run_cmd([
            "iptables", "-t", "mangle", "-A", mangle_chain,
            "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass",
        ])
        return

    if mode == "REDIRECT":
        run_cmd(["iptables", "-t", "nat", "-N", nat_chain])
        run_cmd([
            "iptables", "-t", "nat", "-I", "PREROUTING", "1",
            "-i", ns.host_if, "-p", "tcp", "--dport", str(server_port), "-j", nat_chain,
        ])
        run_cmd([
            "iptables", "-t", "nat", "-A", nat_chain,
            "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(proxy_port),
        ])
        return

    if mode == "TPROXY":
        run_ignore(["ip", "rule", "add", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE])
        run_ignore(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE])
        run_cmd(["iptables", "-t", "mangle", "-N", mangle_chain])
        run_cmd([
            "iptables", "-t", "mangle", "-I", "PREROUTING", "1",
            "-i", ns.host_if, "-p", "tcp", "--dport", str(server_port), "-j", mangle_chain,
        ])
        run_cmd([
            "iptables", "-t", "mangle", "-A", mangle_chain,
            "-p", "tcp", "-j", "TPROXY",
            "--on-ip", "127.0.0.1", "--on-port", str(proxy_port),
            "--tproxy-mark", f"{TPROXY_MARK}/0xffffffff",
        ])
        return

    raise BenchmarkError(f"Unsupported transparent mode: {mode}")


def wait_for_port(host: str, port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise BenchmarkError(f"Timed out waiting for {host}:{port}: {last_error}")


def start_process(case: Case, proxy_port: int, output_dir: Path) -> ProcessHandle:
    assert case.binary is not None
    log_path = output_dir / f"{case.tool.lower()}-{case.mode.lower()}.log"
    log_file = log_path.open("wb")
    env = os.environ.copy()

    if case.tool == "ua2f":
        cmd = [
            str(case.binary),
            "--mode", case.mode,
            "--listen-port", str(proxy_port),
        ]
        cwd = case.binary.parent
    elif case.tool == "ua3f":
        cmd = [
            str(case.binary),
            "--mode", case.mode,
            "--bind", "0.0.0.0",
            "--port", str(proxy_port),
            "--rewrite-mode", "GLOBAL",
            "--ua", "FFF",
            "--log-level", "error",
            "--include-lan-routes",
        ]
        cwd = case.binary.parent
        env = sanitized_ua3f_env(env)
    else:
        raise BenchmarkError(f"Unsupported tool: {case.tool}")

    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
    log_file.close()
    handle = ProcessHandle(proc=proc, log_path=log_path)

    if case.mode in {"REDIRECT", "TPROXY", "HTTP", "SOCKS5"}:
        wait_for_port("127.0.0.1", proxy_port, 5.0)
    else:
        time.sleep(0.5)

    if proc.poll() is not None:
        raise BenchmarkError(f"{case.tool} {case.mode} exited early with {proc.returncode}; see {log_path}")
    return handle


def sanitized_ua3f_env(env: dict[str, str]) -> dict[str, str]:
    """Avoid false OpenWrt detection from local uci/opkg/apk shims on WSL."""
    if Path("/etc/openwrt_release").exists():
        return env
    try:
        if "openwrt" in Path("/etc/os-release").read_text(errors="ignore").lower():
            return env
    except OSError:
        pass

    path_entries = env.get("PATH", "").split(os.pathsep)
    filtered = []
    for entry in path_entries:
        if not entry:
            continue
        directory = Path(entry)
        if any((directory / probe).exists() for probe in ("uci", "opkg", "apk")):
            continue
        filtered.append(entry)
    env = dict(env)
    env["PATH"] = os.pathsep.join(filtered)
    return env


def stop_process(handle: ProcessHandle | None) -> None:
    if handle is None:
        return
    proc = handle.proc
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def read_proc_cpu(pid: int) -> float | None:
    try:
        clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        stat = Path(f"/proc/{pid}/stat").read_text().split()
        return (int(stat[13]) + int(stat[14])) / float(clk_tck)
    except (OSError, KeyError, IndexError, ValueError):
        return None


def run_client(
    client_script: Path,
    ns: Netns,
    kind: str,
    requests: int,
    concurrency: int,
    timeout: float,
    server_port: int,
    proxy_port: int,
) -> dict[str, Any]:
    if requests <= 0:
        return {
            "requests": 0,
            "completed": 0,
            "errors": 0,
            "duration_sec": 0.0,
            "latencies_sec": [],
            "status_counts": {},
            "bytes_sent": 0,
            "bytes_recv": 0,
            "bytes_total": 0,
        }

    cmd = [
        "ip", "netns", "exec", ns.name,
        sys.executable, str(client_script),
        "--kind", kind,
        "--host", ns.server_ip,
        "--port", str(server_port),
        "--proxy-host", ns.server_ip,
        "--proxy-port", str(proxy_port),
        "--requests", str(requests),
        "--concurrency", str(concurrency),
        "--timeout", str(timeout),
    ]
    result = run_cmd(cmd, check=False)
    if result.returncode != 0:
        raise BenchmarkError(f"client failed with {result.returncode}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"client produced invalid JSON: {exc}: {result.stdout[:200]}") from exc


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def summarize_client(client: dict[str, Any]) -> dict[str, Any]:
    latencies = [float(x) for x in client.get("latencies_sec", [])]
    duration = float(client.get("duration_sec", 0.0))
    completed = int(client.get("completed", 0))
    total_bytes = int(client.get("bytes_total", 0))
    rps = completed / duration if duration > 0 else 0.0
    mbps = (total_bytes * 8.0 / duration / 1_000_000.0) if duration > 0 else 0.0
    return {
        "duration_sec": duration,
        "completed": completed,
        "errors": int(client.get("errors", 0)),
        "rps": rps,
        "mbps": mbps,
        "avg_ms": statistics.fmean(latencies) * 1000.0 if latencies else None,
        "p50_ms": percentile(latencies, 0.50) * 1000.0 if latencies else None,
        "p95_ms": percentile(latencies, 0.95) * 1000.0 if latencies else None,
        "p99_ms": percentile(latencies, 0.99) * 1000.0 if latencies else None,
        "max_ms": max(latencies) * 1000.0 if latencies else None,
        "status_counts": client.get("status_counts", {}),
        "bytes_total": total_bytes,
        "error_samples": client.get("error_samples", []),
    }


def ua_check(tool: str, snapshot: dict[str, Any]) -> tuple[bool, str]:
    agents = snapshot.get("user_agents", {})
    if not agents:
        return False, "no requests reached server"

    observed = list(agents.keys())
    if tool == "baseline":
        ok = all(ua.startswith("UA-BENCH/") for ua in observed)
        return ok, "original UA" if ok else f"unexpected UA: {observed[:3]}"

    if tool == "ua2f":
        def is_ua2f_value(value: str) -> bool:
            stripped = value.strip(" ")
            return bool(stripped) and set(stripped) == {"F"}

        ok = all(is_ua2f_value(ua) for ua in observed)
        return ok, "rewritten to F padding" if ok else f"not fully rewritten: {observed[:3]}"

    if tool == "ua3f":
        def is_ua3f_value(value: str) -> bool:
            return value == "FFF" or (value.startswith("FFF") and set(value[3:]) <= {" "})

        ok = all(is_ua3f_value(ua) for ua in observed)
        return ok, "rewritten to FFF" if ok else f"not rewritten to FFF: {observed[:3]}"

    return False, f"unknown tool {tool}"


def run_case(
    case: Case,
    args: argparse.Namespace,
    ns: Netns,
    stats: ServerStats,
    client_script: Path,
    output_dir: Path,
    chain_suffix: str,
) -> dict[str, Any]:
    print(f"[bench] {case.tool} {case.mode}")
    stats.reset()
    handle: ProcessHandle | None = None
    proc_cpu_before: float | None = None
    proc_cpu_after: float | None = None
    started_at = time.time()
    result: dict[str, Any] = {
        "tool": case.tool,
        "mode": case.mode,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "binary": str(case.binary) if case.binary else None,
    }

    try:
        if case.tool != "baseline":
            if case.binary is None:
                raise BenchmarkError(f"{case.tool} binary was not found")
            handle = start_process(case, args.proxy_port, output_dir)
            proc_cpu_before = read_proc_cpu(handle.proc.pid)
            if case.mode in TRANSPARENT_MODES:
                queue = UA2F_QUEUE if case.tool == "ua2f" else UA3F_QUEUE
                setup_firewall(case.mode, queue, args.proxy_port, chain_suffix, ns, args.server_port)

        kind = "direct"
        if case.mode == "HTTP":
            kind = "http-proxy"
        elif case.mode == "SOCKS5":
            kind = "socks5"

        if args.warmup > 0:
            _ = run_client(
                client_script, ns, kind, args.warmup, min(args.concurrency, args.warmup),
                args.timeout, args.server_port, args.proxy_port,
            )

        stats.reset()
        client = run_client(
            client_script, ns, kind, args.requests, args.concurrency,
            args.timeout, args.server_port, args.proxy_port,
        )
        server_snapshot = stats.snapshot()
        summary = summarize_client(client)
        ua_ok, ua_detail = ua_check(case.tool, server_snapshot)

        if handle is not None:
            proc_cpu_after = read_proc_cpu(handle.proc.pid)

        result.update({
            "ok": summary["errors"] == 0 and ua_ok and summary["completed"] == args.requests,
            "client": client,
            "summary": summary,
            "server": server_snapshot,
            "ua_ok": ua_ok,
            "ua_detail": ua_detail,
            "process_cpu_sec": (
                proc_cpu_after - proc_cpu_before
                if proc_cpu_before is not None and proc_cpu_after is not None
                else None
            ),
            "log_path": str(handle.log_path) if handle else None,
        })
    except Exception as exc:  # Keep the report useful when one mode fails.
        result.update({
            "ok": False,
            "error": str(exc),
            "summary": {
                "duration_sec": time.time() - started_at,
                "completed": 0,
                "errors": args.requests,
                "rps": 0.0,
                "mbps": 0.0,
                "avg_ms": None,
                "p50_ms": None,
                "p95_ms": None,
                "p99_ms": None,
                "max_ms": None,
                "status_counts": {},
                "bytes_total": 0,
                "error_samples": [str(exc)],
            },
            "server": stats.snapshot(),
            "ua_ok": False,
            "ua_detail": str(exc),
            "log_path": str(handle.log_path) if handle else None,
        })
        if args.fail_fast:
            raise
    finally:
        cleanup_firewall(chain_suffix, ns, args.server_port)
        stop_process(handle)

    return result


def fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def markdown_report(results: list[dict[str, Any]], args: argparse.Namespace, ns: Netns) -> str:
    generated = dt.datetime.now(dt.timezone.utc).isoformat()
    lines = [
        "# UA2F / UA3F Benchmark Report",
        "",
        f"- Generated: `{generated}`",
        f"- Host: `{platform.node()}`",
        f"- Kernel: `{platform.platform()}`",
        f"- Python: `{platform.python_version()}`",
        f"- CPU count: `{os.cpu_count()}`",
        f"- Client netns: `{ns.name}`",
        f"- Server endpoint: `{ns.server_ip}:{args.server_port}`",
        f"- Requests per case: `{args.requests}`",
        f"- Concurrency: `{args.concurrency}`",
        f"- Response body bytes: `{args.body_bytes}`",
        "",
        "Transparent modes use a veth client namespace and host PREROUTING rules. "
        f"UA2F NFQUEUE uses queue `{UA2F_QUEUE}`; UA3F NFQUEUE uses queue `{UA3F_QUEUE}`.",
        "",
        "## Results",
        "",
        "| Tool | Mode | OK | Completed | Errors | Req/s | Mbps | Avg ms | P50 ms | P95 ms | P99 ms | Proc CPU s | UA check |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    for item in results:
        summary = item.get("summary", {})
        lines.append(
            "| {tool} | {mode} | {ok} | {completed} | {errors} | {rps} | {mbps} | "
            "{avg} | {p50} | {p95} | {p99} | {cpu} | {ua} |".format(
                tool=item.get("tool"),
                mode=item.get("mode"),
                ok="yes" if item.get("ok") else "no",
                completed=summary.get("completed", 0),
                errors=summary.get("errors", 0),
                rps=fmt(summary.get("rps")),
                mbps=fmt(summary.get("mbps")),
                avg=fmt(summary.get("avg_ms")),
                p50=fmt(summary.get("p50_ms")),
                p95=fmt(summary.get("p95_ms")),
                p99=fmt(summary.get("p99_ms")),
                cpu=fmt(item.get("process_cpu_sec")),
                ua=item.get("ua_detail", "-").replace("|", "\\|"),
            )
        )

    failures = [item for item in results if not item.get("ok")]
    if failures:
        lines.extend(["", "## Failures", ""])
        for item in failures:
            lines.append(f"### {item.get('tool')} {item.get('mode')}")
            if item.get("error"):
                lines.append(f"- Error: `{item['error']}`")
            samples = item.get("summary", {}).get("error_samples") or []
            if samples:
                lines.append(f"- Error samples: `{samples[:5]}`")
            if item.get("log_path"):
                lines.append(f"- Log: `{item['log_path']}`")
            lines.append("")

    lines.extend([
        "",
        "## Raw UA Samples",
        "",
    ])
    for item in results:
        agents = item.get("server", {}).get("user_agents", {})
        lines.append(f"- `{item.get('tool')} {item.get('mode')}`: `{agents}`")

    return "\n".join(lines) + "\n"


def parse_modes(value: str, valid: tuple[str, ...]) -> list[str]:
    if value.strip().lower() in {"", "none", "-"}:
        return []
    modes = [part.strip().upper() for part in value.split(",") if part.strip()]
    invalid = [mode for mode in modes if mode not in valid]
    if invalid:
        raise argparse.ArgumentTypeError(f"invalid mode(s): {', '.join(invalid)}; valid: {', '.join(valid)}")
    return modes


def build_cases(args: argparse.Namespace, ua2f: Path | None, ua3f: Path | None) -> list[Case]:
    cases: list[Case] = []
    if not args.no_baseline:
        cases.append(Case("baseline", "DIRECT", None))
    if "ua2f" in args.tools:
        for mode in args.ua2f_modes:
            cases.append(Case("ua2f", mode, ua2f))
    if "ua3f" in args.tools:
        for mode in args.ua3f_modes:
            cases.append(Case("ua3f", mode, ua3f))
    return cases


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark UA2F and UA3F modes and generate Markdown/JSON reports.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--ua2f", default=os.environ.get("UA2F_BIN"), help="Path to ua2f binary")
    parser.add_argument("--ua3f", default=os.environ.get("UA3F_BIN"), help="Path to ua3f binary")
    parser.add_argument("--tools", default="ua2f,ua3f", help="Comma-separated tools to run: ua2f,ua3f")
    parser.add_argument("--ua2f-modes", default=",".join(UA2F_MODES), help="Comma-separated UA2F modes")
    parser.add_argument("--ua3f-modes", default=",".join(UA3F_MODES), help="Comma-separated UA3F modes")
    parser.add_argument("--no-baseline", action="store_true", help="Skip direct baseline")
    parser.add_argument("--requests", type=int, default=2000, help="Measured requests per case")
    parser.add_argument("--warmup", type=int, default=200, help="Warmup requests per case")
    parser.add_argument("--concurrency", type=int, default=16, help="Concurrent client workers")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-socket timeout in seconds")
    parser.add_argument("--body-bytes", type=int, default=4096, help="Origin response body size")
    parser.add_argument("--server-port", type=int, default=18080, help="Origin HTTP server port")
    parser.add_argument("--proxy-port", type=int, default=10010, help="Transparent/proxy listener port")
    parser.add_argument("--server-ip", default="10.250.0.1", help="Host-side veth IP")
    parser.add_argument("--client-ip", default="10.250.0.2", help="Client namespace veth IP")
    parser.add_argument("--cidr-prefix", type=int, default=24, help="Veth CIDR prefix")
    parser.add_argument("--output-dir", default="scripts/benchmark-results", help="Report/log output directory")
    parser.add_argument("--report", default="", help="Markdown report path; default is timestamped under output-dir")
    parser.add_argument("--json-output", default="", help="JSON result path; default is timestamped under output-dir")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first failed case")
    parser.add_argument("--dry-run", action="store_true", help="Print benchmark plan without touching netns/firewall")
    parsed = parser.parse_args()

    parsed.tools = [item.strip().lower() for item in parsed.tools.split(",") if item.strip()]
    invalid_tools = [tool for tool in parsed.tools if tool not in {"ua2f", "ua3f"}]
    if invalid_tools:
        parser.error(f"invalid tool(s): {', '.join(invalid_tools)}")
    parsed.ua2f_modes = parse_modes(parsed.ua2f_modes, UA2F_MODES)
    parsed.ua3f_modes = parse_modes(parsed.ua3f_modes, UA3F_MODES)
    if parsed.requests < 1:
        parser.error("--requests must be positive")
    if parsed.concurrency < 1:
        parser.error("--concurrency must be positive")
    if parsed.warmup < 0:
        parser.error("--warmup cannot be negative")
    if parsed.body_bytes < 0:
        parser.error("--body-bytes cannot be negative")
    return parsed


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    ua2f = resolve_binary(args.ua2f, ["./build-codex-wsl/ua2f", "./build-codex/ua2f", "./build/ua2f"])
    ua3f = resolve_binary(args.ua3f, ["./ref/UA3F/ua3f", "./ref/UA3F/build/ua3f"])
    cases = build_cases(args, ua2f, ua3f)

    suffix = str(os.getpid())[-5:]
    ns = Netns(
        name=f"ua-bench-{suffix}",
        host_if=f"uab{suffix}h",
        ns_if=f"uab{suffix}c",
        server_ip=args.server_ip,
        client_ip=args.client_ip,
        cidr_prefix=args.cidr_prefix,
    )

    print("Benchmark plan:")
    for case in cases:
        binary = str(case.binary) if case.binary else "-"
        print(f"  - {case.tool} {case.mode} ({binary})")

    if args.dry_run:
        return 0

    require_root()
    require_commands(["ip", "iptables", sys.executable])
    if any(case.tool == "ua2f" and case.binary is None for case in cases):
        raise SystemExit("UA2F binary not found. Pass --ua2f /path/to/ua2f or build it first.")
    if any(case.tool == "ua3f" and case.binary is None for case in cases):
        raise SystemExit("UA3F binary not found. Pass --ua3f /path/to/ua3f or build it first.")

    stats = ServerStats()
    body = b"x" * args.body_bytes
    server: ReusableThreadingHTTPServer | None = None
    server_thread: threading.Thread | None = None

    results: list[dict[str, Any]] = []
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = Path(args.report).resolve() if args.report else output_dir / f"ua-benchmark-{timestamp}.md"
    json_path = Path(args.json_output).resolve() if args.json_output else output_dir / f"ua-benchmark-{timestamp}.json"

    with tempfile.TemporaryDirectory(prefix="ua-bench-") as tmp:
        client_script = Path(tmp) / "client.py"
        client_script.write_text(CLIENT_CODE)

        try:
            setup_netns(ns)
            server = ReusableThreadingHTTPServer((args.server_ip, args.server_port), make_handler(stats, body))
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            wait_for_port(args.server_ip, args.server_port, 5.0)

            for index, case in enumerate(cases):
                chain_suffix = f"{suffix}_{index}"
                results.append(run_case(case, args, ns, stats, client_script, output_dir, chain_suffix))
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            cleanup_netns(ns)

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "args": vars(args),
        "environment": {
            "host": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "results": results,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    report_path.write_text(markdown_report(results, args, ns))

    print(f"Wrote report: {report_path}")
    print(f"Wrote JSON:   {json_path}")

    return 1 if any(not item.get("ok") for item in results) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
