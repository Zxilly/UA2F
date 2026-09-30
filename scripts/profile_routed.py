#!/usr/bin/env python3
"""Bounded diagnostics for the real routed benchmark; never mix tracing with A/B timings.

Must run in a disposable network namespace. Untraced cases use the unchanged Go
client/origin and candidate binary. A separate strace pass preserves raw calls,
counts, error codes, read sizes and receive batching evidence. No host security
settings, perf permissions, CPU affinity or kernel settings are changed.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

import benchmark as bench
import benchmark_compare as compare

MODES = ("DIRECT", *bench.UA2F_MODES)
TRACE_SYSCALLS = ("read,write,readv,writev,recvfrom,recvmsg,recvmmsg,sendto,sendmsg,sendmmsg,"
                  "splice,epoll_wait,epoll_pwait,epoll_ctl,poll,ppoll,accept,accept4,connect,"
                  "socket,close,getsockopt,setsockopt,futex")
CTX_FIELDS = ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")


def proc_snapshot(pid: int) -> dict[str, Any]:
    """Process-wide CPU, plus explicitly per-thread context counters (not leader-only)."""
    root = Path(f"/proc/{pid}")
    raw = (root / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    ticks = float(os.sysconf("SC_CLK_TCK"))
    threads = {}
    for task in (root / "task").iterdir():
        try:
            status = dict(line.split(":", 1) for line in (task / "status").read_text().splitlines())
            threads[task.name] = {key: int(status[key]) for key in CTX_FIELDS}
        except FileNotFoundError:  # A runtime thread may exit during the snapshot.
            continue
    return {"pid": pid, "user_sec": int(fields[11]) / ticks,
            "system_sec": int(fields[12]) / ticks, "threads": threads,
            "raw_stat": raw, "raw_status": (root / "status").read_text()}


def process_delta(before: dict[str, Any], after: dict[str, Any], wall: float,
                  requests: int) -> dict[str, Any]:
    user = after["user_sec"] - before["user_sec"]
    system = after["system_sec"] - before["system_sec"]
    if min(user, system) < 0 or wall <= 0 or requests <= 0:
        raise ValueError("invalid CPU sampling window")
    ctx = {key: sum(max(0, values[key] - before["threads"].get(tid, {}).get(key, 0))
                    for tid, values in after["threads"].items()) for key in CTX_FIELDS}
    missing = sorted(set(before["threads"]) - set(after["threads"]))
    return {"user_sec": user, "system_sec": system, "total_sec": user + system,
            "user_us_per_request": user / requests * 1e6,
            "system_us_per_request": system / requests * 1e6,
            "total_us_per_request": (user + system) / requests * 1e6,
            "cpu_pct_one_core": (user + system) / wall * 100,
            "context_switches": ctx,
            "context_switches_per_request": {key: value / requests for key, value in ctx.items()},
            "context_scope": "sum of surviving/new thread counters; lower bound if threads exit",
            "threads_missing_at_end": missing}


def key_values(path: Path) -> dict[str, int]:
    return {key: int(value) for key, value in (line.split() for line in path.read_text().splitlines())}


def cgroup_snapshot() -> dict[str, Any]:
    """Read v2 CPU usage/quota at this process's cgroup and each visible ancestor."""
    membership = Path("/proc/self/cgroup").read_text()
    unified = next((line.split(":", 2)[2] for line in membership.splitlines()
                    if line.startswith("0::")), None)
    result: dict[str, Any] = {"membership": membership, "groups": {}, "scope":
                             "shared runner cgroup, includes observer and any colocated processes"}
    if unified is None:
        result["unavailable"] = "No cgroup v2 CPU accounting; process accounting remains available"
        return result
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    mount = next((line.split()[4] for line in mounts if " - cgroup2 " in line), None)
    if mount is None:
        result["unavailable"] = "No visible cgroup v2 mount"
        return result
    root = Path(mount)
    # The mount root may already be the service's cgroup in a cgroup namespace.
    path = root / unified.lstrip("/")
    if not path.is_dir():
        path = root
    while True:
        if (path / "cpu.stat").is_file():
            result["groups"][str(path)] = {
                "cpu_stat": key_values(path / "cpu.stat"),
                "cpu_max": (path / "cpu.max").read_text().strip() if (path / "cpu.max").exists() else None,
                "cpuset_effective": (path / "cpuset.cpus.effective").read_text().strip()
                if (path / "cpuset.cpus.effective").exists() else None}
        if path == root:
            break
        path = path.parent
    if not result["groups"]:
        result["unavailable"] = "No readable cpu.stat"
    return result


def cgroup_delta(before: dict[str, Any], after: dict[str, Any], wall: float) -> dict[str, Any]:
    result = {}
    for name, item in after["groups"].items():
        if name not in before["groups"]:
            continue
        old = before["groups"][name]["cpu_stat"]
        delta = {key: value - old[key] for key, value in item["cpu_stat"].items() if key in old}
        result[name] = {"cpu_stat_delta": delta, "cpu_max": item["cpu_max"],
                        "cpu_pct_one_core": delta.get("usage_usec", 0) / wall / 1e4}
    return result


def client_command(binary: Path, ns: bench.Netns, args: argparse.Namespace, requests: int) -> list[str]:
    return ["ip", "netns", "exec", ns.name, str(binary), "--kind", "direct",
            "--host", ns.server_ip, "--port", str(args.server_port), "--requests", str(requests),
            "--concurrency", str(args.concurrency), "--timeout", str(args.timeout)]


def measured_client(binary: Path, ns: bench.Netns, args: argparse.Namespace, directory: Path,
                    processes: dict[str, int]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Gate the child before exec, preserve its zombie /proc, then collect wait4.

    wait4 accounts for all exited client threads, including their context switches.
    Startup, final JSON encoding and exit are included, unlike the Go HTTP wall
    timer. A getrusage baseline immediately before exec excludes the gated shim.
    """
    gate_read, gate_write = os.pipe()
    ready_read, ready_write = os.pipe()
    command = [sys.executable, str(Path(__file__).resolve()), "--exec-gated", str(gate_read),
               str(ready_write), *client_command(binary, ns, args, args.requests)]
    proc = None
    try:
        with (directory / "client.json").open("wb") as stdout, (directory / "client.stderr.log").open("wb") as stderr:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True,
                                    pass_fds=(gate_read, ready_write))
        os.close(gate_read)
        os.close(ready_write)
        gate_read = ready_write = -1
        import select
        if not select.select([ready_read], [], [], 10)[0] or os.read(ready_read, 1) != b"R":
            raise bench.BenchmarkError("client gate did not become ready")
        pids = dict(processes, client=proc.pid)
        before = {name: proc_snapshot(pid) for name, pid in pids.items()}
        cg_before = cgroup_snapshot()
        started = time.monotonic()
        os.write(gate_write, b"G")
        while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() - started > args.case_timeout:
                raise bench.BenchmarkError("diagnostic client timed out")
            time.sleep(0.005)
        wall = time.monotonic() - started
        # WNOWAIT leaves /proc present; never poll()/wait() before this snapshot.
        after = {name: proc_snapshot(pid) for name, pid in pids.items()}
        cg_after = cgroup_snapshot()
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        metrics = {name: process_delta(before[name], after[name], wall, args.requests) for name in pids}
        baseline = json.loads(os.read(ready_read, 8192))
        client = metrics["client"]
        user = max(0, usage.ru_utime - baseline["user_sec"])
        system = max(0, usage.ru_stime - baseline["system_sec"])
        client.update(user_sec=user, system_sec=system, total_sec=user + system,
                      user_us_per_request=user / args.requests * 1e6,
                      system_us_per_request=system / args.requests * 1e6,
                      total_us_per_request=(user + system) / args.requests * 1e6,
                      cpu_pct_one_core=(user + system) / wall * 100)
        client["context_switches"] = {key: value - baseline[key]
                                      for key, value in zip(CTX_FIELDS, (usage.ru_nvcsw, usage.ru_nivcsw))}
        client["context_switches_per_request"] = {key: value / args.requests
                                                 for key, value in client["context_switches"].items()}
        client["context_scope"] = "wait4 entire process including exited threads, minus immediate pre-exec getrusage"
        client.pop("threads_missing_at_end")
        raw = {"before": before, "after": after, "cgroup_before": cg_before, "cgroup_after": cg_after,
               "client_pre_exec_rusage": baseline, "client_wait4": dict(zip(usage._fields, usage)) if hasattr(usage, "_fields") else {
                   name: getattr(usage, name) for name in dir(usage) if name.startswith("ru_")}}
        compare.write_json(directory / "process-snapshots.json", raw)
        if proc.returncode != 0:
            raise bench.BenchmarkError(f"diagnostic client exited {proc.returncode}")
        return json.loads((directory / "client.json").read_text()), {
            "wall_sec": wall, "processes": metrics, "cgroups": cgroup_delta(cg_before, cg_after, wall),
            "cgroup_unavailable": cg_before.get("unavailable")}
    finally:
        for fd in (gate_read, gate_write, ready_read, ready_write):
            if fd >= 0:
                os.close(fd)
        if proc is not None:
            bench.stop_process(bench.ProcessHandle(proc, directory / "client.stderr.log"))


def validate(client: dict[str, Any], origin: dict[str, Any], requests: int, mode: str) -> None:
    if mode != "DIRECT":
        compare.validate_client(client, origin, requests)
        return
    # Reuse all client/status/latency checks with a synthetic UA check only, then
    # separately verify the real DIRECT UA sample is unchanged. The origin helper
    # intentionally exposes top-10 UAs only; do not imply full DIRECT-UA coverage.
    compare.validate_client(client, {"requests": origin.get("requests"),
                                     "user_agents": {"F" * 12: requests}}, requests)
    agents = origin.get("user_agents", {})
    if not agents or any(not re.fullmatch(r"UA-BENCH/\d+", ua) for ua in agents):
        raise bench.BenchmarkError("DIRECT origin UA sample was unexpectedly modified")


def start_traced(binary: Path, mode: str, args: argparse.Namespace, directory: Path) -> bench.ProcessHandle:
    env = {key: value for key, value in os.environ.items() if not key.startswith("UA2F_")}
    env.update(UA2F_NFQUEUE_WORKERS=str(args.nfqueue_workers), UA2F_PROXY_WORKERS=str(args.proxy_workers))
    log_path = directory / "ua2f.log"
    command = ["strace", "-f", "-qq", "-C", "-s", "24", "-e", f"trace={TRACE_SYSCALLS}",
               "-o", str(directory / "ua2f.strace"), str(binary), "--mode", mode,
               "--listen-port", str(args.proxy_port)]
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, cwd=binary.parent, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
    handle = bench.ProcessHandle(proc, log_path)
    try:
        if mode == "NFQUEUE":
            time.sleep(0.5)
        else:
            bench.wait_for_port("127.0.0.1", args.proxy_port, 5)
        if proc.poll() is not None:
            raise bench.BenchmarkError("strace/UA2F exited during startup; see ua2f.log")
        return handle
    except BaseException:
        bench.stop_process(handle)
        raise


def parse_trace(raw: str) -> dict[str, Any]:
    counts, observations, pending = {}, {}, {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) in (5, 6) and re.fullmatch(r"\d+\.\d+", parts[0]) and parts[-1] != "total":
            try:
                counts[parts[-1]] = {"calls": int(parts[3]), "errors": int(parts[4]) if len(parts) == 6 else 0}
            except ValueError:
                pass
        match = re.match(r"(\d+)\s+(.*)", line)
        if not match:
            continue
        tid, call = match.groups()
        if "<unfinished ...>" in call:
            pending[tid] = call.replace("<unfinished ...>", "")
            continue
        if call.startswith("<... "):
            resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", call)
            if not resumed or tid not in pending:
                continue
            call = pending.pop(tid) + resumed[1]
        result = re.match(r"(\w+)\((.*)\)\s+=\s+(-?\d+)(?:\s+([A-Z][A-Z0-9_]+))?", call)
        if not result:
            continue
        syscall, arguments, returned, error = result.groups()
        returned = int(returned)
        item = observations.setdefault(syscall, {"parsed_calls": 0, "errors": {}, "positive_returns": 0,
                                                 "zero_returns": 0, "positive_return_sum": 0,
                                                 "short_reads": 0, "requested_read_bytes": 0})
        item["parsed_calls"] += 1
        if returned == -1 and error:
            item["errors"][error] = item["errors"].get(error, 0) + 1
        elif returned == 0:
            item["zero_returns"] += 1
        elif returned > 0:
            item["positive_returns"] += 1
            item["positive_return_sum"] += returned
        if syscall == "read":
            size = re.search(r", (\d+)$", arguments)
            if size:
                requested = int(size[1])
                item["requested_read_bytes"] += requested
                if 0 < returned < requested:
                    item["short_reads"] += 1
    return {"counts": counts, "observations": observations,
            "scope": "selected UA2F syscalls across startup, warmup, requests and shutdown; no timing claims",
            "receive_batching_note": "recvmsg/recvfrom returns are bytes, recvmmsg returns messages; raw trace shows netlink messages"}


def run_case(item: dict[str, Any], args: argparse.Namespace, client_bin: Path,
             server_bin: Path, output: Path, index: int) -> dict[str, Any]:
    directory = output / "runs" / f"{index:02d}-{item['body_bytes']}-{item['mode'].lower()}-{item['kind']}"
    directory.mkdir(parents=True)
    result = dict(item, ok=False, raw_directory=str(directory.relative_to(output)))
    suffix = str(os.getpid())[-6:]
    ns = bench.Netns(f"uap-{suffix}", f"uap{suffix}h", f"uap{suffix}c", "10.250.0.1", "10.250.0.2", 24)
    target = server = None
    args.body_bytes, args.server_ip = item["body_bytes"], ns.server_ip
    traced = item["kind"] == "strace"
    args.requests = args.trace_requests if traced else args.profile_requests
    warmup = args.trace_warmup if traced else args.warmup
    control = bench.server_control_addr(args)
    try:
        bench.setup_netns(ns)
        server = bench.start_bench_server(server_bin, args, directory)
        if item["mode"] != "DIRECT":
            starter = start_traced if traced else compare.start_target
            target = starter(Path(args.candidate).resolve(), item["mode"], args, directory)
            bench.setup_firewall(item["mode"], bench.UA2F_QUEUE, args.proxy_port, suffix, ns,
                                 args.server_port, queue_count=args.nfqueue_workers)
        bench.server_reset(control)
        client = compare.run_client(client_bin, ns, args, warmup, directory, "warmup")
        origin = bench.server_snapshot(control)
        compare.write_json(directory / "warmup-server.json", origin)
        validate(client, origin, warmup, item["mode"])
        bench.server_reset(control)
        if traced:
            client = compare.run_client(client_bin, ns, args, args.requests, directory, "client")
        else:
            pids = {"origin": server.proc.pid}
            if target:
                pids["ua2f"] = target.proc.pid
            client, result["accounting"] = measured_client(client_bin, ns, args, directory, pids)
            result["summary"] = bench.summarize_client(client)
        origin = bench.server_snapshot(control)
        compare.write_json(directory / "server.json", origin)
        validate(client, origin, args.requests, item["mode"])
        if target and target.proc.poll() is not None:
            raise bench.BenchmarkError("UA2F exited during profile load")
        result.update(ok=True, requests=args.requests, warmup=warmup, server=origin,
                      ua_validation="all rewritten" if item["mode"] != "DIRECT" else "top-10 unchanged sample")
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        bench.cleanup_firewall(suffix, ns, args.server_port)
        bench.stop_process(target)
        bench.stop_process(server)
        bench.cleanup_netns(ns)
        if traced and (directory / "ua2f.strace").exists():
            trace = parse_trace((directory / "ua2f.strace").read_text())
            result["trace"] = trace
            if not trace["counts"]:
                result.update(ok=False, error="strace summary was missing; inspect raw ua2f.strace/ua2f.log")
            compare.write_json(directory / "syscalls.json", trace)
        compare.write_json(directory / "result.json", result)
    return result


def markdown(payload: dict[str, Any]) -> str:
    lines = ["# Routed workload diagnostics", "", f"- Status: **{payload['status']}**",
             f"- Exact candidate: `{payload['parameters']['candidate_sha']}`",
             "- Diagnostic runs are not paired performance evidence. DIRECT retains the same Go workload; unique-UA origin bookkeeping differs from rewritten UAs.",
             "- CPU = one core at 100%; user/system µs per request includes client startup/JSON/exit. Origin/UA2F exclude warmup.",
             "- /proc CPU resolution is one clock tick; client uses wait4 minus immediate pre-exec getrusage. All processes share the same sampling wall window.",
             "- Context switches sum OS threads, not only the leader; exited origin/UA2F threads can make those values lower bounds.",
             "- Cgroup CPU includes observer/colocated work; inspect quota and throttling before attributing a limit.",
             "- Traces are separate instrumented runs. Their timings/throughput are deliberately omitted; counts include startup/warmup/shutdown.", "",
             "| Body | Mode | Diagnostic req/s | Process | CPU % | User µs/req | System µs/req | Vol ctx/req | Invol ctx/req |",
             "| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
    for item in payload["results"]:
        if not item["ok"]:
            lines.append(f"\nFailed {item['raw_directory']}: {item.get('error')}\n")
        if "accounting" not in item:
            continue
        for name, metrics in item["accounting"]["processes"].items():
            ctx = metrics["context_switches_per_request"]
            lines.append(f"| {item['body_bytes']} | {item['mode']} | {item['summary']['rps']:.0f} | {name} | "
                         f"{metrics['cpu_pct_one_core']:.1f} | {metrics['user_us_per_request']:.2f} | "
                         f"{metrics['system_us_per_request']:.2f} | {ctx[CTX_FIELDS[0]]:.3f} | {ctx[CTX_FIELDS[1]]:.3f} |")
    lines.extend(["", "## Cgroup CPU and throttling", ""])
    for item in payload["results"]:
        accounting = item.get("accounting")
        if not accounting:
            continue
        total = sum(metrics["cpu_pct_one_core"] for metrics in accounting["processes"].values())
        lines.append(f"- {item['body_bytes']} / {item['mode']}: client+origin+UA2F {total:.1f}% of one core")
        if accounting["cgroup_unavailable"]:
            lines.append(f"  - Unavailable: {accounting['cgroup_unavailable']}")
        for path, group in accounting["cgroups"].items():
            lines.append(f"  - {path}: CPU {group['cpu_pct_one_core']:.1f}%, quota {group['cpu_max']}; "
                         f"raw counter deltas {json.dumps(group['cpu_stat_delta'], sort_keys=True)}")
    lines.extend(["", "## Instrumented syscall counts", "",
                  "Positive return sums mean bytes for read/recv/splice/send, events for epoll_wait, and messages for recvmmsg/sendmmsg."])
    for item in payload["results"]:
        if "trace" not in item:
            continue
        lines.append(f"### {item['body_bytes']} bytes / {item['mode']}; {item.get('requests', '?')} requests + {item.get('warmup', '?')} warmup")
        counts = item["trace"]["counts"]
        observed = item["trace"]["observations"]
        for syscall, values in sorted(counts.items(), key=lambda pair: pair[1]["calls"], reverse=True)[:12]:
            extra = observed.get(syscall, {})
            lines.append(f"- {syscall}: {values['calls']} calls, {values['errors']} errors; "
                         f"parsed errno {extra.get('errors', {})}; short reads {extra.get('short_reads', 0)}; "
                         f"positive returns {extra.get('positive_returns', 0)}, sum {extra.get('positive_return_sum', 0)}")
    if payload.get("error"):
        lines.extend(["", f"Error: {payload['error']}"])
    lines.extend(["", "Raw /proc snapshots, cgroup counters, client/origin JSON and syscall traces are preserved in the artifact.", ""])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--profile-requests", type=int, default=50000)
    parser.add_argument("--warmup", type=int, default=5000)
    parser.add_argument("--trace-requests", type=int, default=2000)
    parser.add_argument("--trace-warmup", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument("--body-sizes", nargs="+", type=int, default=[1024, 65536])
    parser.add_argument("--nfqueue-workers", type=int, choices=range(1, 17), default=1)
    parser.add_argument("--proxy-workers", type=int, choices=range(1, 17), default=1)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--case-timeout", type=float, default=90)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if any(getattr(args, key) <= 0 for key in ("profile_requests", "warmup", "trace_requests", "trace_warmup", "concurrency")):
        parser.error("request counts, warmup and concurrency must be positive")
    if any(size <= 0 for size in args.body_sizes) or len(set(args.body_sizes)) != len(args.body_sizes):
        parser.error("body sizes must be positive and unique")
    if not re.fullmatch("[0-9a-f]{40}", args.candidate_sha):
        parser.error("candidate-sha must be a full lowercase Git SHA")
    if not (math.isfinite(args.timeout) and math.isfinite(args.case_timeout) and args.case_timeout >= args.timeout > 0):
        parser.error("invalid timeouts")
    args.server_port, args.server_control_port, args.proxy_port = 18080, 18081, 10010
    return args


def main() -> int:
    args = parse_args()
    plan = [{"body_bytes": size, "mode": mode, "kind": kind}
            for kind in ("accounting", "strace") for size in args.body_sizes
            for mode in (MODES if kind == "accounting" else bench.UA2F_MODES)]
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    bench.require_root()
    bench.require_commands(["ip", "iptables", "go", "strace"])
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Run inside a disposable network namespace")
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "summary.json").exists() or (output / "runs").exists():
        raise SystemExit("Use a fresh diagnostics output directory")
    payload: dict[str, Any] = {"schema_version": 1, "started_at": compare.utc_now(),
                               "parameters": vars(args).copy(), "plan": plan, "results": [], "status": "failed"}
    previous = signal.signal(signal.SIGTERM, compare.interrupted)
    try:
        binary = Path(args.candidate).resolve()
        version = compare.command_output([str(binary), "--version"])
        if f"Git commit: {args.candidate_sha}" not in version.splitlines():
            raise bench.BenchmarkError("candidate binary does not embed the exact expected SHA")
        root = Path(__file__).resolve().parent
        payload["environment"] = {"binary_sha256": compare.sha256(binary), "binary_version": version,
                                  "source_sha256": {name: compare.sha256(root / name) for name in
                                                    ("profile_routed.py", "benchmark_compare.py", "benchmark.py", "bench_client.go", "bench_server.go")},
                                  "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                                  "cpu_affinity": sorted(os.sched_getaffinity(0)),
                                  "network_namespace": os.readlink("/proc/self/ns/net"),
                                  "strace_version": compare.command_output(["strace", "--version"])}
        with tempfile.TemporaryDirectory(prefix="ua2f-profile-") as temporary:
            client, server = bench.build_bench_tools(Path(temporary))
            for index, item in enumerate(plan, 1):
                print(f"[profile {index}/{len(plan)}] {item['kind']} {item['body_bytes']} {item['mode']}", flush=True)
                result = run_case(item, args, client, server, output, index)
                payload["results"].append(result)
                if not result["ok"]:
                    raise bench.BenchmarkError(result["error"])
        payload["status"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        payload["error"] = f"{type(exc).__name__}: {exc}"
        print(payload["error"], file=sys.stderr, flush=True)
    finally:
        signal.signal(signal.SIGTERM, previous)
        payload["finished_at"] = compare.utc_now()
        compare.write_json(output / "summary.json", payload)
        (output / "summary.md").write_text(markdown(payload))
        print(f"Diagnostics: {output / 'summary.json'}", flush=True)
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exec-gated":
        gate, ready = map(int, sys.argv[2:4])
        import resource
        os.write(ready, b"R")
        if os.read(gate, 1) != b"G":
            raise SystemExit("client gate closed")
        os.close(gate)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        os.write(ready, json.dumps({"user_sec": usage.ru_utime, "system_sec": usage.ru_stime,
                                   "voluntary_ctxt_switches": usage.ru_nvcsw,
                                   "nonvoluntary_ctxt_switches": usage.ru_nivcsw}).encode())
        os.close(ready)
        os.execvp(sys.argv[4], sys.argv[4:])
    raise SystemExit(main())
