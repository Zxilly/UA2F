#!/usr/bin/env python3
"""Opt-in, isolated packet-path checks for the exact empty-ACK rule generators.

Run only inside a disposable outer netns. This does not alter host routes,
sysctls, or security settings. IPv4/IPv6 and nft/iptables share one HTTP probe.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import benchmark as bench


def nft_family_matches(rule: dict, family: int) -> bool:
    """Identify generated predicates by their explicit IP-family header read."""
    protocol = "ip" if family == 4 else "ip6"
    def includes_header(value):
        if isinstance(value, dict):
            if value.get("payload", {}).get("protocol") == protocol:
                return True
            return any(includes_header(child) for child in value.values())
        return isinstance(value, list) and any(includes_header(child) for child in value)
    return includes_header(rule.get("expr", []))


def nft_ruleset(interface: str, rules: str) -> str:
    # nft requires a newline/semicolon between chain declarations and closing
    # blocks. Keep declarations on separate lines, including the final braces.
    return ("table inet ua_empty_test {\n"
            "  chain prerouting {\n"
            "    type filter hook prerouting priority mangle; policy accept;\n"
            f'    iifname "{interface}" tcp dport 18080 ct direction original jump inspect;\n'
            "  }\n"
            "  chain inspect {\n" + rules.rstrip() + "\n"
            "    counter queue num 10010;\n"
            "  }\n"
            "}\n")


def probe(host: str, port: int) -> None:
    """Split a header, pipeline requests, preserve a POST body, then half-close."""
    body = b"User-Agent: preserve this body\r\n" * 2048
    cases = [("GET", f"/first?padding=65536", "split-user-agent", b"")]
    cases += [("GET", f"/pipeline-{i}?padding=1024", f"pipeline-{i}", b"") for i in range(16)]
    cases += [("POST", "/body", "post-user-agent", body),
              ("GET", "/after-post?padding=65536", "after-post", b""),
              ("GET", "/without-ua", None, b"")]
    encoded = []
    for method, path, agent, payload in cases:
        headers = f"{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\nContent-Length: {len(payload)}\r\n"
        if agent is not None:
            headers += f"User-Agent: {agent}\r\n"
        encoded.append(headers.encode() + b"\r\n" + payload)
    with socket.create_connection((host, port), timeout=10) as connection:
        split = encoded[0].index(b"split-user-agent") + 6
        connection.sendall(encoded[0][:split])
        time.sleep(.02)
        connection.sendall(encoded[0][split:])
        stream = connection.makefile("rb")
        for index, (method, path, agent, payload) in enumerate(cases):
            status = stream.readline()
            if not status.startswith(b"HTTP/1.1 200 "):
                raise AssertionError(f"unexpected response: {status!r}")
            headers = {}
            while True:
                line = stream.readline()
                if line == b"\r\n":
                    break
                if not line:
                    raise AssertionError("truncated response headers")
                key, value = line.split(b":", 1)
                headers[key.lower()] = value.strip()
            size = int(headers[b"content-length"])
            raw = stream.read(size)
            if len(raw) != size:
                raise AssertionError("truncated response body")
            response = json.loads(raw)
            expected = None if agent is None else "F" * len(agent)
            if response["user_agent"] != expected or response["body"] != payload.decode():
                raise AssertionError(f"request rewrite/body mismatch: {path}")
            if response["method"] != method or response["path"] != path:
                raise AssertionError("request framing changed")
            expected_padding = 65536 if "65536" in path else (1024 if "padding=1024" in path else 0)
            if response["padding"] != "x" * expected_padding:
                raise AssertionError("response content changed")
            if index == 0:
                # Let response ACKs and classification settle before any later
                # request exists; then pipeline sixteen requests and a POST.
                time.sleep(.1)
                connection.sendall(b"".join(encoded[1:18]))
            elif index == 17:
                # A truly subsequent keep-alive request after the complete POST
                # response, rather than one already queued in the first write.
                time.sleep(.1)
                connection.sendall(b"".join(encoded[18:]))
                connection.shutdown(socket.SHUT_WR)
        if stream.read(1):
            raise AssertionError("unexpected bytes after final response")
    print(json.dumps({"ok": True, "host": host, "requests": len(cases),
                      "split_header": True, "pipeline_requests": 16,
                      "post_bytes": len(body), "later_keep_alive": True, "half_close": True}))


def run(binary: Path, helper: Path, output: Path) -> None:
    bench.require_root()
    bench.require_commands(["ip", "iptables", "ip6tables", "nft"])
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Use a disposable outer network namespace")
    output.mkdir(parents=True, exist_ok=True)
    suffix = str(os.getpid())[-6:]
    ns = bench.Netns(f"uae-{suffix}", f"uae{suffix}h", f"uae{suffix}c", "10.250.0.1", "10.250.0.2", 24)
    endpoint = Path(__file__).with_name("http_test_endpoint.py")
    server = target = None
    results = []
    try:
        bench.setup_netns(ns)
        bench.run_cmd(["ip", "-6", "addr", "add", "fd42:250::1/64", "dev", ns.host_if, "nodad"])
        bench.run_cmd(["ip", "netns", "exec", ns.name, "ip", "-6", "addr", "add", "fd42:250::2/64", "dev", ns.ns_if, "nodad"])
        with (output / "origin.log").open("wb") as log:
            server = bench.ProcessHandle(subprocess.Popen(
                [sys.executable, str(endpoint), "serve", "--port", "18080", "--ipv6"],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True), output / "origin.log")
        bench.wait_for_port("127.0.0.1", 18080, 5)
        env = {key: value for key, value in os.environ.items() if not key.startswith("UA2F_")}
        env.update(UA2F_NFQUEUE_WORKERS="1", UA2F_PROXY_WORKERS="1")
        log_path = output / "ua2f.log"
        with log_path.open("wb") as log:
            target = bench.ProcessHandle(subprocess.Popen(
                [str(binary), "--mode", "NFQUEUE", "--listen-port", "10010"],
                cwd=binary.parent, env=env, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True), log_path)
        time.sleep(.5)
        if target.proc.poll() is not None:
            raise RuntimeError(f"UA2F exited early: {target.proc.returncode}")
        for backend in ("iptables", "nft"):
            if backend == "iptables":
                for family, executable in ((4, "iptables"), (6, "ip6tables")):
                    bench.run_cmd([executable, "-t", "mangle", "-N", "UA_EMPTY_TEST"])
                    bench.run_cmd([executable, "-t", "mangle", "-A", "PREROUTING", "-i", ns.host_if,
                                   "-p", "tcp", "--dport", "18080", "-m", "conntrack", "--ctdir", "ORIGINAL", "-j", "UA_EMPTY_TEST"])
                    rules = bench.run_cmd(["sh", "-c", '. "$1"; ua2f_empty_ack_queue_iptables "$2" 10010 10010',
                                           "sh", str(helper), str(family)]).stdout.splitlines()
                    if len(rules) != 13:
                        raise AssertionError("candidate did not emit its thirteen-rule tail")
                    for rule in rules:
                        bench.run_cmd([executable, "-t", "mangle", "-A", "UA_EMPTY_TEST", *rule.split("\t")])
            else:
                rules = bench.run_cmd(["sh", "-c", '. "$1"; ua2f_empty_ack_nft', "sh", str(helper)]).stdout
                ruleset = nft_ruleset(ns.host_if, rules)
                (output / "candidate.nft").write_text(ruleset)
                subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)
            for family, host in ((4, ns.server_ip), (6, "fd42:250::1")):
                result = bench.run_cmd(["ip", "netns", "exec", ns.name, sys.executable,
                                       str(Path(__file__).resolve()), "--probe", host])
                results.append(dict(json.loads(result.stdout), backend=backend, family=family))
                # Preserve successful probes even if a later backend fails.
                (output / "probes.json").write_text(json.dumps(results, indent=2))
                print(json.dumps(results[-1]), flush=True)
            if backend == "iptables":
                for executable in ("iptables", "ip6tables"):
                    snapshot = bench.run_cmd([executable, "-t", "mangle", "-L", "UA_EMPTY_TEST", "-nvx"])
                    (output / f"{executable}-counters.txt").write_text(snapshot.stdout)
                    matches = [int(line.split()[0]) for line in snapshot.stdout.splitlines()
                               if len(line.split()) > 2 and line.split()[2] == "RETURN"]
                    if sum(matches) == 0:
                        raise AssertionError(f"{executable}: candidate rules never matched an ACK")
                    bench.run_cmd([executable, "-t", "mangle", "-D", "PREROUTING", "-i", ns.host_if,
                                   "-p", "tcp", "--dport", "18080", "-m", "conntrack", "--ctdir", "ORIGINAL", "-j", "UA_EMPTY_TEST"])
                    bench.run_cmd([executable, "-t", "mangle", "-F", "UA_EMPTY_TEST"])
                    bench.run_cmd([executable, "-t", "mangle", "-X", "UA_EMPTY_TEST"])
            else:
                snapshot = bench.run_cmd(["nft", "-j", "list", "table", "inet", "ua_empty_test"])
                (output / "nft-counters.json").write_text(snapshot.stdout)
                rules = [item["rule"] for item in json.loads(snapshot.stdout)["nftables"] if "rule" in item]
                for family in (4, 6):
                    matches = [expr["counter"]["packets"] for rule in rules
                               if rule.get("comment") == "!ua2f: empty ACK" and nft_family_matches(rule, family)
                               for expr in rule["expr"] if "counter" in expr]
                    if sum(matches) == 0:
                        raise AssertionError(f"nft IPv{family}: candidate rules never matched an ACK")
                bench.run_cmd(["nft", "delete", "table", "inet", "ua_empty_test"])
        (output / "summary.json").write_text(json.dumps({"status": "passed", "results": results}, indent=2))
    finally:
        bench.stop_process(target)
        bench.stop_process(server)
        bench.cleanup_netns(ns)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--probe")
    arguments = parser.parse_args()
    if arguments.probe:
        probe(arguments.probe, 18080)
    elif arguments.binary and arguments.helper and arguments.output_dir:
        run(arguments.binary.resolve(), arguments.helper.resolve(), arguments.output_dir.resolve())
    else:
        parser.error("specify --binary/--helper/--output-dir or --probe")
