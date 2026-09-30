#!/usr/bin/env python3
"""Compare two UA2F builds on one Linux host with counterbalanced paired runs.

Run inside a disposable network namespace, as performance.yml does. The existing
benchmark helpers exercise real NFQUEUE, REDIRECT and TPROXY PREROUTING paths.
No UA3F historical measurements are rerun or incorporated in this comparison.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import benchmark as bench


METRICS = ("rps", "mbps", "avg_ms", "p95_ms", "p99_ms", "process_cpu_sec",
           "process_cpu_pct", "process_rss_kib", "process_hwm_kib")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def command_output(command: list[str]) -> str:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=30, check=False)
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cpu_seconds(pid: int) -> float:
    # /proc comm may contain spaces and parentheses. The tail starts at field 3.
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    return (int(fields[11]) + int(fields[12])) / float(os.sysconf("SC_CLK_TCK"))


def distribution(values: list[float]) -> dict[str, float | int]:
    if not values or not all(math.isfinite(value) for value in values):
        raise ValueError("statistics require finite, nonempty samples")
    mean = statistics.fmean(values)
    return {"n": len(values), "median": statistics.median(values), "mean": mean,
            "min": min(values), "max": max(values),
            "cv_pct": statistics.pstdev(values) / mean * 100 if mean else 0.0}


def make_plan(pairs: int, body_sizes: list[int]) -> list[dict[str, Any]]:
    plan = []
    modes = list(bench.UA2F_MODES)
    for pair in range(pairs):
        # Adjacent A/B pairs, with the first variant reversed each round. Six
        # rounds give equal A-first and B-first counts for every workload.
        variants = ("base", "candidate") if pair % 2 == 0 else ("candidate", "base")
        sizes = body_sizes if pair % 2 == 0 else list(reversed(body_sizes))
        ordered_modes = modes[pair % len(modes):] + modes[:pair % len(modes)]
        for size in sizes:
            for mode in ordered_modes:
                for variant in variants:
                    plan.append({"pair": pair + 1, "body_bytes": size,
                                 "mode": mode, "variant": variant})
    return plan


def validate_client(client: dict[str, Any], server: dict[str, Any], requests: int) -> None:
    if client.get("requests") != requests or client.get("completed") != requests:
        raise bench.BenchmarkError("client did not complete exactly the requested load")
    if client.get("errors") != 0 or client.get("status_counts") != {"200": requests}:
        raise bench.BenchmarkError("client errors or unexpected HTTP statuses")
    if len(client.get("latencies_sec", [])) != requests:
        raise bench.BenchmarkError("missing latency samples")
    if not math.isfinite(client.get("duration_sec", 0)) or client["duration_sec"] <= 0:
        raise bench.BenchmarkError("invalid client duration")
    if not all(math.isfinite(value) and value >= 0 for value in client["latencies_sec"]):
        raise bench.BenchmarkError("invalid latency samples")
    if server.get("requests") != requests:
        raise bench.BenchmarkError("origin did not receive exactly the requested load")
    valid, detail = bench.ua_check("ua2f", server)
    if not valid:
        raise bench.BenchmarkError(detail)
    # The server returns only its top 10 UA values. Requiring their counts to
    # cover EVERY request prevents an omitted, unmodified UA from passing.
    if sum(server.get("user_agents", {}).values()) != requests:
        raise bench.BenchmarkError("UA samples do not account for every request")


def run_client(client_bin: Path, ns: bench.Netns, args: argparse.Namespace,
               requests: int, directory: Path, name: str) -> dict[str, Any]:
    command = ["ip", "netns", "exec", ns.name, str(client_bin), "--kind", "direct",
               "--host", ns.server_ip, "--port", str(args.server_port),
               "--requests", str(requests), "--concurrency", str(args.concurrency),
               "--timeout", str(args.timeout)]
    # Raw stdout remains available even on a timeout or malformed JSON.
    with (directory / f"{name}.json").open("wb") as stdout, \
            (directory / f"{name}.stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        handle = bench.ProcessHandle(proc, directory / f"{name}.stderr.log")
        try:
            status = proc.wait(timeout=args.case_timeout)
            if status != 0:
                raise bench.BenchmarkError(f"{name} exited with status {status}")
        finally:
            bench.stop_process(handle)
    return json.loads((directory / f"{name}.json").read_text())


def start_target(binary: Path, mode: str, args: argparse.Namespace,
                 directory: Path) -> bench.ProcessHandle:
    env = {key: value for key, value in os.environ.items() if not key.startswith("UA2F_")}
    env.update(UA2F_NFQUEUE_WORKERS=str(args.nfqueue_workers),
               UA2F_PROXY_WORKERS=str(args.proxy_workers))
    log_path = directory / "ua2f.log"
    with log_path.open("wb") as log:
        proc = subprocess.Popen([str(binary), "--mode", mode, "--listen-port", str(args.proxy_port)],
                                cwd=binary.parent, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
    handle = bench.ProcessHandle(proc, log_path)
    try:
        if mode == "NFQUEUE":
            time.sleep(0.5)
        else:
            bench.wait_for_port("127.0.0.1", args.proxy_port, 5.0)
        if proc.poll() is not None:
            raise bench.BenchmarkError(f"UA2F exited early: {proc.returncode}")
        return handle
    except BaseException:
        bench.stop_process(handle)
        raise


def run_case(item: dict[str, Any], args: argparse.Namespace, client_bin: Path,
             server_bin: Path, output: Path, index: int) -> dict[str, Any]:
    directory = output / "runs" / f"{index:03d}-{item['body_bytes']}-{item['mode'].lower()}-{item['variant']}"
    directory.mkdir(parents=True)
    result = dict(item, started_at=utc_now(), ok=False, raw_directory=str(directory.relative_to(output)))
    suffix = f"{os.getpid()}"[-6:]
    ns = bench.Netns(f"uac-{suffix}", f"uac{suffix}h", f"uac{suffix}c",
                     "10.250.0.1", "10.250.0.2", 24)
    target = server = None
    binary = Path(getattr(args, item["variant"])).resolve()
    args.body_bytes = item["body_bytes"]
    args.server_ip = ns.server_ip
    control = bench.server_control_addr(args)
    try:
        bench.setup_netns(ns)
        server = bench.start_bench_server(server_bin, args, directory)
        target = start_target(binary, item["mode"], args, directory)
        bench.setup_firewall(item["mode"], bench.UA2F_QUEUE, args.proxy_port, suffix,
                             ns, args.server_port, queue_count=args.nfqueue_workers)
        # Preserve actual TPROXY routing state; request and UA checks below
        # reject a missing/bypassed transparent route rather than timing it.
        if item["mode"] == "TPROXY":
            result["policy_rules"] = command_output(["ip", "rule", "show"])
            result["policy_routes"] = command_output(["ip", "route", "show", "table", bench.TPROXY_TABLE])
        bench.server_reset(control)
        warmup = run_client(client_bin, ns, args, args.warmup, directory, "warmup")
        warmup_server = bench.server_snapshot(control)
        write_json(directory / "warmup-server.json", warmup_server)
        validate_client(warmup, warmup_server, args.warmup)
        bench.server_reset(control)

        # Exclude warmup and startup from process CPU. CPU % uses this same
        # wall-clock sampling window, with 100% meaning one fully used core.
        before = cpu_seconds(target.proc.pid)
        sample_start = time.monotonic()
        client = run_client(client_bin, ns, args, args.requests, directory, "client")
        after = cpu_seconds(target.proc.pid)
        sample_seconds = time.monotonic() - sample_start
        memory = bench.read_proc_memory(target.proc.pid)
        snapshot = bench.server_snapshot(control)
        write_json(directory / "server.json", snapshot)
        validate_client(client, snapshot, args.requests)
        if target.proc.poll() is not None:
            raise bench.BenchmarkError("UA2F exited during the measured load")
        if any(key not in memory for key in ("VmRSS", "VmHWM")):
            raise bench.BenchmarkError("could not sample process RSS/HWM")
        summary = bench.summarize_client(client)
        summary.update(process_cpu_sec=after - before,
                       process_cpu_pct=(after - before) / sample_seconds * 100,
                       process_rss_kib=memory["VmRSS"], process_hwm_kib=memory["VmHWM"])
        result.update(ok=True, summary=summary, cpu_sample_wall_sec=sample_seconds,
                      server=snapshot, ua_ok=True)
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        bench.cleanup_firewall(suffix, ns, args.server_port)
        bench.stop_process(target)
        bench.stop_process(server)
        bench.cleanup_netns(ns)
        result["finished_at"] = utc_now()
        write_json(directory / "result.json", result)
    return result


def aggregate(results: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    aggregates = []
    for size in args.body_sizes:
        for mode in bench.UA2F_MODES:
            selected = [item for item in results if item["body_bytes"] == size and item["mode"] == mode]
            variants = {name: [item for item in selected if item["variant"] == name and item["ok"]]
                        for name in ("base", "candidate")}
            complete = all(len(items) == args.pairs for items in variants.values())
            row: dict[str, Any] = {"body_bytes": size, "mode": mode, "complete": complete,
                                  "successful_runs": {name: len(items) for name, items in variants.items()}}
            # Never make a speed claim from a partial/failing workload.
            if complete:
                for name, items in variants.items():
                    row[name] = {metric: distribution([item["summary"][metric] for item in items])
                                 for metric in METRICS}
                ratios = []
                for pair in range(1, args.pairs + 1):
                    base = next(item for item in variants["base"] if item["pair"] == pair)
                    candidate = next(item for item in variants["candidate"] if item["pair"] == pair)
                    ratios.append(candidate["summary"]["rps"] / base["summary"]["rps"])
                row["paired_rps_ratio_candidate_over_base"] = distribution(ratios)
                row["rps_ratio_of_medians"] = row["candidate"]["rps"]["median"] / row["base"]["rps"]["median"]
            aggregates.append(row)
    return aggregates


def markdown(payload: dict[str, Any]) -> str:
    args = payload["parameters"]
    env = payload["environment"]
    lines = ["# Same-runner UA2F performance comparison", "",
             f"- Status: **{payload['status']}**",
             f"- UTC start: `{payload['started_at']}`; finish: `{payload['finished_at']}`",
             f"- Base: `{args['base_sha']}`; candidate: `{args['candidate_sha']}`",
             f"- Host: `{env['platform']}`; CPUs: `{env['cpu_count']}`; Go: `{env['go']}`",
             f"- {args['pairs']} adjacent pairs per workload; alternating base/candidate first",
             f"- {args['requests']} measured + {args['warmup']} warmup requests; concurrency {args['concurrency']}",
             f"- Workers: NFQUEUE={args['nfqueue_workers']}, proxy={args['proxy_workers']}",
             "- Every measured AND warmup run must have zero errors, all HTTP 200, and all origin UAs rewritten",
             "- Req/s and latency are end-to-end Go client measurements, including origin and kernel work",
             "- Mbps estimates HTTP request+response bytes, not Ethernet/IP/TCP wire bandwidth",
             "- CPU excludes warmup; 100% = one core. RSS is sampled at load end; HWM includes startup/warmup",
             "- CV is population standard deviation / mean. Shared-runner noise is not statistical significance",
             "- UA3F is not run; older README UA3F measurements remain historical data", "",
             "| Body | Mode | Build | Req/s median | Req/s min–max | CV | Mbps median | P95 ms median | CPU % median | RSS KiB median | HWM KiB median |",
             "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in payload["aggregates"]:
        if not row["complete"]:
            lines.append(f"| {row['body_bytes']} | {row['mode']} | incomplete | | | | | | | | |")
            continue
        for variant in ("base", "candidate"):
            metrics = row[variant]
            rps = metrics["rps"]
            lines.append(f"| {row['body_bytes']} | {row['mode']} | {variant} | {rps['median']:.0f} | "
                         f"{rps['min']:.0f}–{rps['max']:.0f} | {rps['cv_pct']:.2f}% | "
                         f"{metrics['mbps']['median']:.1f} | {metrics['p95_ms']['median']:.3f} | "
                         f"{metrics['process_cpu_pct']['median']:.1f} | "
                         f"{metrics['process_rss_kib']['median']:.0f} | {metrics['process_hwm_kib']['median']:.0f} |")
    lines.extend(["", "## Paired throughput ratios (candidate / base)", ""])
    for row in payload["aggregates"]:
        if row["complete"]:
            ratio = row["paired_rps_ratio_candidate_over_base"]
            lines.append(f"- {row['body_bytes']} bytes / {row['mode']}: median {ratio['median']:.4f}× "
                         f"({(ratio['median'] - 1) * 100:+.2f}%), range {ratio['min']:.4f}–{ratio['max']:.4f}×; "
                         f"CV {ratio['cv_pct']:.2f}%")
    if payload.get("error"):
        lines.extend(["", f"Error: {payload['error']}"])
    for result in payload["results"]:
        if not result["ok"]:
            lines.append(f"- Failed: {result['raw_directory']}: {result.get('error', 'validation failed')}")
    lines.extend(["", "Full metadata, all metric distributions, and per-run raw JSON/logs are in the artifact.", ""])
    return "\n".join(lines)


def environment(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(__file__).resolve().parent
    return {"platform": platform.platform(), "uname": list(platform.uname()),
            "os_release": Path("/etc/os-release").read_text(), "cpu_count": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "lscpu": command_output(["lscpu", "--json"]),
            "memory": Path("/proc/meminfo").read_text(), "python": sys.version,
            "go": command_output(["go", "version"]), "cc": command_output(["cc", "--version"]),
            "cmake": command_output(["cmake", "--version"]),
            "iptables": command_output(["iptables", "--version"]),
            "network_namespace": os.readlink("/proc/self/ns/net"),
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "source_sha256": {name: sha256(root / name) for name in
                              ("benchmark_compare.py", "benchmark.py", "bench_client.go", "bench_server.go")},
            "binaries": {name: {"path": str(Path(getattr(args, name)).resolve()),
                                "sha256": sha256(Path(getattr(args, name))),
                                "version": command_output([str(Path(getattr(args, name)).resolve()), "--version"]),
                                "ldd": command_output(["ldd", str(Path(getattr(args, name)).resolve())])}
                         for name in ("base", "candidate")}}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    for variant in ("base", "candidate"):
        parser.add_argument(f"--{variant}", required=True, help="Path to built UA2F")
        parser.add_argument(f"--{variant}-sha", required=True, help="Full commit SHA embedded in this binary")
    parser.add_argument("--output-dir", default="scripts/benchmark-results/comparison")
    parser.add_argument("--pairs", type=int, default=6)
    parser.add_argument("--requests", type=int, default=100000)
    parser.add_argument("--warmup", type=int, default=10000)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument("--body-sizes", type=int, nargs="+", default=[1024, 65536])
    parser.add_argument("--nfqueue-workers", type=int, choices=range(1, 17), default=1)
    parser.add_argument("--proxy-workers", type=int, choices=range(1, 17), default=1)
    parser.add_argument("--timeout", type=float, default=5, help="HTTP request timeout seconds")
    parser.add_argument("--case-timeout", type=float, default=90, help="Maximum seconds for each load-generator invocation")
    parser.add_argument("--build-metadata", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="Show plan without root or network changes")
    args = parser.parse_args()
    if args.pairs < 5 or args.requests < 1 or args.warmup < 1 or args.concurrency < 1:
        parser.error("at least five pairs and positive requests, warmup and concurrency are required")
    if len(set(args.body_sizes)) != len(args.body_sizes) or any(size < 1 for size in args.body_sizes):
        parser.error("body sizes must be positive and unique")
    if not (math.isfinite(args.timeout) and math.isfinite(args.case_timeout)
            and args.case_timeout >= args.timeout > 0):
        parser.error("timeouts must be finite and case-timeout >= timeout > 0")
    for name in ("base_sha", "candidate_sha"):
        value = getattr(args, name)
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            parser.error(f"{name.replace('_', '-')} must be a full lowercase Git SHA")
    args.server_port, args.server_control_port, args.proxy_port = 18080, 18081, 10010
    return args


def interrupted(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt("benchmark interrupted")


def main() -> int:
    args = parse_args()
    plan = make_plan(args.pairs, args.body_sizes)
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    bench.require_root()
    bench.require_commands(["ip", "iptables", "go", "cc", "cmake", "lscpu", "ldd"])
    # Do not manipulate routing/firewall state in the initial host namespace.
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Run inside a disposable network namespace (see .github/workflows/performance.yml)")
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "summary.json").exists() or (output / "runs").exists():
        raise SystemExit("Use a fresh output directory; prior measurements must not be overwritten")
    parameters = vars(args).copy()
    parameters["build_metadata"] = str(args.build_metadata) if args.build_metadata else None
    payload: dict[str, Any] = {"schema_version": 1, "started_at": utc_now(), "parameters": parameters,
                               "plan": plan, "results": [], "status": "failed", "environment": {}}
    previous_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        payload["environment"] = environment(args)
        for variant in ("base", "candidate"):
            expected = f"Git commit: {getattr(args, variant + '_sha')}"
            if expected not in payload["environment"]["binaries"][variant]["version"].splitlines():
                raise bench.BenchmarkError(f"{variant} binary does not embed the expected SHA")
        if args.build_metadata:
            payload["build"] = json.loads(args.build_metadata.read_text())
        with tempfile.TemporaryDirectory(prefix="ua2f-compare-") as temporary:
            client_bin, server_bin = bench.build_bench_tools(Path(temporary))
            for index, item in enumerate(plan, 1):
                print(f"[{index}/{len(plan)}] pair {item['pair']} {item['body_bytes']} bytes "
                      f"{item['mode']} {item['variant']}", flush=True)
                result = run_case(item, args, client_bin, server_bin, output, index)
                payload["results"].append(result)
                if not result["ok"]:
                    raise bench.BenchmarkError(result["error"])
        payload["status"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        payload["error"] = f"{type(exc).__name__}: {exc}"
        print(payload["error"], file=sys.stderr, flush=True)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        payload["finished_at"] = utc_now()
        payload["aggregates"] = aggregate(payload["results"], args)
        write_json(output / "summary.json", payload)
        if payload["environment"]:
            (output / "summary.md").write_text(markdown(payload))
        else:
            (output / "summary.md").write_text(f"# UA2F comparison failed\n\n{payload.get('error')}\n")
        print(f"Results: {output / 'summary.json'}", flush=True)
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
