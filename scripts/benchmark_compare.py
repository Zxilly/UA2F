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
import resource
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
           "process_cpu_pct", "process_rss_kib", "process_hwm_kib",
           "process_user_us_per_request", "process_system_us_per_request",
           "client_user_us_per_request", "client_system_us_per_request",
           "origin_user_us_per_request", "origin_system_us_per_request",
           "combined_process_us_per_request", "guest_busy_us_per_request",
           "guest_kernel_us_per_request", "guest_softirq_us_per_request",
           "guest_busy_cpu_pct", "guest_steal_cpu_pct")

HOST_CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


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
    user, system = cpu_breakdown(pid)
    return user + system


def cpu_breakdown(pid: int) -> tuple[float, float]:
    # /proc comm may contain spaces and parentheses. The tail starts at field 3.
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    ticks = float(os.sysconf("SC_CLK_TCK"))
    return int(fields[11]) / ticks, int(fields[12]) / ticks


def parse_host_cpu(raw: str) -> dict[str, int]:
    fields = raw.splitlines()[0].split() if raw.splitlines() else []
    if not fields or fields[0] != "cpu" or len(fields) < len(HOST_CPU_FIELDS) + 1:
        raise bench.BenchmarkError("missing aggregate /proc/stat CPU counters")
    try:
        result = dict(zip(HOST_CPU_FIELDS, map(int, fields[1:9])))
    except ValueError as exc:
        raise bench.BenchmarkError("non-numeric /proc/stat CPU counters") from exc
    if min(result.values()) < 0:
        raise bench.BenchmarkError("negative /proc/stat CPU counters")
    # guest and guest_nice are already included in user/nice, so never add them.
    return result


def host_cpu_snapshot() -> dict[str, int]:
    return parse_host_cpu(Path("/proc/stat").read_text())


def host_cpu_delta(before: dict[str, int], after: dict[str, int], wall: float,
                   requests: int, ticks: float | None = None) -> dict[str, Any]:
    ticks = float(os.sysconf("SC_CLK_TCK")) if ticks is None else ticks
    if wall <= 0 or requests <= 0 or ticks <= 0:
        raise bench.BenchmarkError("invalid guest CPU sampling interval")
    delta = {key: after[key] - before[key] for key in HOST_CPU_FIELDS}
    # Linux documents iowait as unreliable, including possible decreases. Keep
    # its raw delta, but exclude it from busy/kernel accounting either way.
    if any(value < 0 for key, value in delta.items() if key != "iowait"):
        raise bench.BenchmarkError("guest CPU counters reset during load")
    seconds = {key: value / ticks for key, value in delta.items()}
    busy = sum(seconds[key] for key in ("user", "nice", "system", "irq", "softirq"))
    kernel = sum(seconds[key] for key in ("system", "irq", "softirq"))
    return {"before": before, "after": after, "seconds": seconds,
            "busy_us_per_request": busy / requests * 1e6,
            "kernel_us_per_request": kernel / requests * 1e6,
            "softirq_us_per_request": seconds["softirq"] / requests * 1e6,
            "busy_cpu_pct_one_core": busy / wall * 100,
            "steal_cpu_pct_one_core": seconds["steal"] / wall * 100,
            "scope": "entire CI guest, includes observer/colocated work; kernel=system+irq+softirq; not physical host CPU"}


def waited_child_cpu(before: Any, after: Any) -> dict[str, Any]:
    user, system = after.ru_utime - before.ru_utime, after.ru_stime - before.ru_stime
    if min(user, system) < 0:
        raise bench.BenchmarkError("child CPU counters reset")
    return {"user_sec": user, "system_sec": system,
            "scope": "RUSAGE_CHILDREN delta around the only waited child; includes ip exec, Go startup, JSON output and exit"}


def parse_queue_counters(raw: str, first_queue: int, workers: int) -> dict[int, dict[str, int]]:
    """Parse the documented nfnetlink_queue /proc fields, not receive calls.

    The kernel assigns id_sequence before delivery to the userspace socket.
    A delta counts successful queued packet messages only when drop counters
    are unchanged. The snapshot also preserves in-flight queue_total.
    """
    names = ("queue_num", "peer_portid", "queue_total", "copy_mode", "copy_range",
             "queue_dropped", "queue_user_dropped", "id_sequence")
    wanted = set(range(first_queue, first_queue + workers))
    queues = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < len(names):
            raise bench.BenchmarkError("truncated nfnetlink_queue counter line")
        try:
            values = dict(zip(names, map(int, fields[:len(names)])))
        except ValueError as exc:
            raise bench.BenchmarkError("non-numeric nfnetlink_queue counters") from exc
        number = values["queue_num"]
        if number in wanted:
            if number in queues:
                raise bench.BenchmarkError("duplicate NFQUEUE counter entry")
            if not 0 <= values["id_sequence"] <= 0xffffffff:
                raise bench.BenchmarkError("invalid NFQUEUE packet sequence")
            queues[number] = values
    if set(queues) != wanted:
        raise bench.BenchmarkError("missing expected NFQUEUE counter entry")
    return queues


def queue_snapshot(workers: int) -> dict[int, dict[str, int]]:
    return parse_queue_counters(Path("/proc/net/netfilter/nfnetlink_queue").read_text(),
                                bench.UA2F_QUEUE, workers)


def queue_delta(before: dict[int, dict[str, int]], after: dict[int, dict[str, int]]) -> dict[str, Any]:
    if set(before) != set(after):
        raise bench.BenchmarkError("NFQUEUE identities changed during load")
    packets = 0
    for queue, old in before.items():
        new = after[queue]
        if any(new[key] != old[key] for key in ("peer_portid", "copy_mode", "copy_range")):
            raise bench.BenchmarkError("NFQUEUE was replaced or reconfigured during load")
        if any(new[key] != old[key] for key in ("queue_dropped", "queue_user_dropped")):
            raise bench.BenchmarkError("NFQUEUE reported kernel/userspace drops during load")
        # One uint32 wrap is unambiguous for these bounded (<2^32 packet) runs.
        delta = (new["id_sequence"] - old["id_sequence"]) & 0xffffffff
        if delta > 0x7fffffff:
            raise bench.BenchmarkError("NFQUEUE sequence reset or ambiguous counter interval")
        packets += delta
    return {"packets": packets, "before": before, "after": after,
            "scope": "NFQUEUE packet IDs allocated in the measured window, with unchanged drop counters"}


def distribution(values: list[float]) -> dict[str, float | int]:
    if not values or not all(math.isfinite(value) for value in values):
        raise ValueError("statistics require finite, nonempty samples")
    mean = statistics.fmean(values)
    return {"n": len(values), "median": statistics.median(values), "mean": mean,
            "min": min(values), "max": max(values),
            "cv_pct": statistics.pstdev(values) / mean * 100 if mean else 0.0}


def make_plan(pairs: int, body_sizes: list[int], modes: list[str] | None = None,
              include_direct: bool = False) -> list[dict[str, Any]]:
    plan = []
    modes = list(bench.UA2F_MODES) if modes is None else modes
    for pair in range(pairs):
        # Adjacent A/B pairs, with the first variant reversed each round. Six
        # rounds give equal A-first and B-first counts for every workload.
        variants = ("base", "candidate") if pair % 2 == 0 else ("candidate", "base")
        sizes = body_sizes if pair % 2 == 0 else list(reversed(body_sizes))
        ordered_modes = modes[pair % len(modes):] + modes[:pair % len(modes)]
        for size in sizes:
            if include_direct and pair % 2 == 0:
                plan.append({"pair": pair + 1, "body_bytes": size, "mode": "DIRECT", "variant": "direct"})
            for mode in ordered_modes:
                for variant in variants:
                    plan.append({"pair": pair + 1, "body_bytes": size,
                                 "mode": mode, "variant": variant})
            if include_direct and pair % 2 != 0:
                plan.append({"pair": pair + 1, "body_bytes": size, "mode": "DIRECT", "variant": "direct"})
    return plan


def validate_client(client: dict[str, Any], server: dict[str, Any], requests: int,
                    direct: bool = False) -> None:
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
    if direct:
        # DIRECT is a workload-ceiling reference, not paired optimization evidence.
        # Its original unique UAs have different origin map bookkeeping. Preserve
        # this caveat rather than silently changing the shared Go workload.
        agents = server.get("user_agents", {})
        if not agents or not all(ua.startswith("UA-BENCH/") and count == 1 for ua, count in agents.items()):
            raise bench.BenchmarkError("DIRECT origin UA sample was modified")
        return
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
    # Origin/UA2F stay running and are not waited in this interval; only this
    # client contributes to the RUSAGE_CHILDREN delta (including its threads).
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
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
    cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = json.loads((directory / f"{name}.json").read_text())
    result["process_cpu_accounting"] = waited_child_cpu(cpu_before, cpu_after)
    return result


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


def install_empty_ack_candidate(helper: Path, chain: str, workers: int = 1) -> list[list[str]]:
    """Install the production-generated tail in this isolated benchmark chain."""
    generated = bench.run_cmd(["sh", "-c", '. "$1"; ua2f_empty_ack_queue_iptables 4 "$2" "$3"',
                               "sh", str(helper), str(bench.UA2F_QUEUE), str(bench.UA2F_QUEUE + workers - 1)])
    rules = [line.split("\t") for line in generated.stdout.splitlines()]
    if len(rules) != 13 or any(not rule or any(not arg for arg in rule) for rule in rules):
        raise bench.BenchmarkError("empty-ACK helper did not emit its complete thirteen-rule tail")
    # This fresh chain contains only setup_firewall's plain queue target. It is
    # private to the disposable namespace and no client load has started yet.
    bench.run_cmd(["iptables", "-t", "mangle", "-F", chain])
    for rule in rules:
        bench.run_cmd(["iptables", "-t", "mangle", "-A", chain, *rule])
    return rules


def run_case(item: dict[str, Any], args: argparse.Namespace, client_bin: Path,
             server_bin: Path, output: Path, index: int) -> dict[str, Any]:
    directory = output / "runs" / f"{index:03d}-{item['body_bytes']}-{item['mode'].lower()}-{item['variant']}"
    directory.mkdir(parents=True)
    result = dict(item, started_at=utc_now(), ok=False, raw_directory=str(directory.relative_to(output)))
    suffix = f"{os.getpid()}"[-6:]
    ns = bench.Netns(f"uac-{suffix}", f"uac{suffix}h", f"uac{suffix}c",
                     "10.250.0.1", "10.250.0.2", 24)
    target = server = None
    direct = item["mode"] == "DIRECT"
    binary = None if direct else Path(getattr(args, item["variant"])).resolve()
    args.body_bytes = item["body_bytes"]
    args.server_ip = ns.server_ip
    control = bench.server_control_addr(args)
    try:
        bench.setup_netns(ns)
        server = bench.start_bench_server(server_bin, args, directory)
        if not direct:
            target = start_target(binary, item["mode"], args, directory)
            bench.setup_firewall(item["mode"], bench.UA2F_QUEUE, args.proxy_port, suffix,
                                 ns, args.server_port, queue_count=args.nfqueue_workers)
            if (item["mode"] == "NFQUEUE" and item["variant"] == "candidate"
                    and args.candidate_firewall_helper):
                result["candidate_empty_ack_iptables"] = install_empty_ack_candidate(
                    args.candidate_firewall_helper, f"UA_BENCH_M_{suffix}", args.nfqueue_workers)
        # Preserve actual TPROXY routing state; request and UA checks below
        # reject a missing/bypassed transparent route rather than timing it.
        if item["mode"] == "TPROXY":
            result["policy_rules"] = command_output(["ip", "rule", "show"])
            result["policy_routes"] = command_output(["ip", "route", "show", "table", bench.TPROXY_TABLE])
        bench.server_reset(control)
        warmup = run_client(client_bin, ns, args, args.warmup, directory, "warmup")
        warmup_server = bench.server_snapshot(control)
        write_json(directory / "warmup-server.json", warmup_server)
        validate_client(warmup, warmup_server, args.warmup, direct=direct)
        bench.server_reset(control)

        # Exclude warmup and startup from process CPU. CPU % uses this same
        # wall-clock sampling window, with 100% meaning one fully used core.
        before = (0.0, 0.0) if direct else cpu_breakdown(target.proc.pid)
        origin_before = cpu_breakdown(server.proc.pid)
        queues_before = queue_snapshot(args.nfqueue_workers) if item["mode"] == "NFQUEUE" else None
        guest_before = host_cpu_snapshot()
        sample_start = time.monotonic()
        client = run_client(client_bin, ns, args, args.requests, directory, "client")
        after = (0.0, 0.0) if direct else cpu_breakdown(target.proc.pid)
        origin_after = cpu_breakdown(server.proc.pid)
        guest_after = host_cpu_snapshot()
        sample_seconds = time.monotonic() - sample_start
        queues_after = queue_snapshot(args.nfqueue_workers) if queues_before is not None else None
        memory = {"VmRSS": 0, "VmHWM": 0} if direct else bench.read_proc_memory(target.proc.pid)
        snapshot = bench.server_snapshot(control)
        write_json(directory / "server.json", snapshot)
        validate_client(client, snapshot, args.requests, direct=direct)
        if not direct and target.proc.poll() is not None:
            raise bench.BenchmarkError("UA2F exited during the measured load")
        if any(key not in memory for key in ("VmRSS", "VmHWM")):
            raise bench.BenchmarkError("could not sample process RSS/HWM")
        summary = bench.summarize_client(client)
        user, system = after[0] - before[0], after[1] - before[1]
        origin_user, origin_system = origin_after[0] - origin_before[0], origin_after[1] - origin_before[1]
        if min(user, system, origin_user, origin_system) < 0:
            raise bench.BenchmarkError("process CPU counters reset during load")
        client_cpu = client["process_cpu_accounting"]
        guest_cpu = host_cpu_delta(guest_before, guest_after, sample_seconds, args.requests)
        combined = user + system + origin_user + origin_system + client_cpu["user_sec"] + client_cpu["system_sec"]
        summary.update(process_cpu_sec=user + system,
                       process_cpu_pct=(user + system) / sample_seconds * 100,
                       process_user_us_per_request=user / args.requests * 1e6,
                       process_system_us_per_request=system / args.requests * 1e6,
                       origin_user_us_per_request=origin_user / args.requests * 1e6,
                       origin_system_us_per_request=origin_system / args.requests * 1e6,
                       client_user_us_per_request=client_cpu["user_sec"] / args.requests * 1e6,
                       client_system_us_per_request=client_cpu["system_sec"] / args.requests * 1e6,
                       combined_process_us_per_request=combined / args.requests * 1e6,
                       guest_busy_us_per_request=guest_cpu["busy_us_per_request"],
                       guest_kernel_us_per_request=guest_cpu["kernel_us_per_request"],
                       guest_softirq_us_per_request=guest_cpu["softirq_us_per_request"],
                       guest_busy_cpu_pct=guest_cpu["busy_cpu_pct_one_core"],
                       guest_steal_cpu_pct=guest_cpu["steal_cpu_pct_one_core"],
                       process_rss_kib=memory["VmRSS"], process_hwm_kib=memory["VmHWM"])
        result["guest_cpu_accounting"] = guest_cpu
        result["process_cpu_accounting"] = {"client": client_cpu,
            "origin": {"user_sec": origin_user, "system_sec": origin_system},
            "ua2f": {"user_sec": user, "system_sec": system}}
        if queues_before is not None:
            result["queue_accounting"] = queue_delta(queues_before, queues_after)
            summary["queued_packets_per_request"] = result["queue_accounting"]["packets"] / args.requests
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
        for mode in args.modes:
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
                    if mode == "NFQUEUE":
                        row[name]["queued_packets_per_request"] = distribution(
                            [item["summary"]["queued_packets_per_request"] for item in items])
                ratios = []
                for pair in range(1, args.pairs + 1):
                    base = next(item for item in variants["base"] if item["pair"] == pair)
                    candidate = next(item for item in variants["candidate"] if item["pair"] == pair)
                    ratios.append(candidate["summary"]["rps"] / base["summary"]["rps"])
                row["paired_rps_ratio_candidate_over_base"] = distribution(ratios)
                row["rps_ratio_of_medians"] = row["candidate"]["rps"]["median"] / row["base"]["rps"]["median"]
            aggregates.append(row)
    return aggregates


def direct_aggregates(results: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = []
    if not args.include_direct:
        return rows
    for size in args.body_sizes:
        selected = [r for r in results if r["mode"] == "DIRECT" and r["body_bytes"] == size and r["ok"]]
        row = {"body_bytes": size, "complete": len(selected) == args.pairs}
        if row["complete"]:
            row["rps"] = distribution([r["summary"]["rps"] for r in selected])
        rows.append(row)
    return rows


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
             "- Every measured AND warmup run must have zero errors and all HTTP 200; routed cases account for every rewritten UA",
             "- Req/s and latency are end-to-end Go client measurements, including origin and kernel work",
             "- Mbps estimates HTTP request+response bytes, not Ethernet/IP/TCP wire bandwidth",
             "- Origin/UA2F CPU excludes warmup; client CPU includes startup/JSON/exit. 100% = one core",
             "- Guest CPU is read-only /proc/stat and includes observer/colocated work; it is not physical-host CPU",
             "- RSS is sampled at load end; HWM includes startup/warmup",
             "- CV is population standard deviation / mean. Shared-runner noise is not statistical significance",
             "- UA3F is not run; older README UA3F measurements remain historical data", "",
             "- NFQUEUE original-direction conntrack matching is identical in both variants; candidate per-rule matching is preserved", "",
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
    lines.extend(["", "## Whole-workload CPU accounting", "",
                  "CPU work per request; guest and process totals are distinct views and must not be added together.",
                  "| Body | Mode | Build | Client user/sys µs | Origin user/sys µs | All 3 processes µs | Guest busy µs | Guest system+irq+softirq µs | Guest busy CPU % |",
                  "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for row in payload["aggregates"]:
        if not row["complete"]:
            continue
        for variant in ("base", "candidate"):
            m = row[variant]
            lines.append(f"| {row['body_bytes']} | {row['mode']} | {variant} | "
                         f"{m['client_user_us_per_request']['median']:.2f}/{m['client_system_us_per_request']['median']:.2f} | "
                         f"{m['origin_user_us_per_request']['median']:.2f}/{m['origin_system_us_per_request']['median']:.2f} | "
                         f"{m['combined_process_us_per_request']['median']:.2f} | {m['guest_busy_us_per_request']['median']:.2f} | "
                         f"{m['guest_kernel_us_per_request']['median']:.2f} | {m['guest_busy_cpu_pct']['median']:.1f} |")
    if payload.get("direct_aggregates"):
        lines.extend(["", "## DIRECT diagnostic references", "",
                      "Same Go workload; unique-UA origin map bookkeeping differs. These are not paired speedups."])
        for row in payload["direct_aggregates"]:
            if row["complete"]:
                lines.append(f"- {row['body_bytes']} bytes: {row['rps']['median']:.0f} req/s median")
    if any(row["mode"] == "NFQUEUE" and row["complete"] for row in payload["aggregates"]):
        lines.extend(["", "## NFQUEUE accounting", "",
                      "Counts use /proc NFQUEUE packet-ID deltas with unchanged drop counters, not recv syscall counts."])
        for row in payload["aggregates"]:
            if row["mode"] == "NFQUEUE" and row["complete"]:
                for variant in ("base", "candidate"):
                    stats = row[variant]
                    lines.append(f"- {row['body_bytes']} bytes / {variant}: "
                                 f"{stats['queued_packets_per_request']['median']:.3f} queued packets/request; "
                                 f"UA2F user/system {stats['process_user_us_per_request']['median']:.2f}/"
                                 f"{stats['process_system_us_per_request']['median']:.2f} µs/request")
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
    parser.add_argument("--modes", nargs="+", choices=bench.UA2F_MODES, default=list(bench.UA2F_MODES))
    parser.add_argument("--include-direct", action="store_true", help="Add same-runner diagnostic references")
    parser.add_argument("--candidate-firewall-helper", type=Path,
                        help="Explicitly enable candidate empty-ACK returns in NFQUEUE cases, using this source helper")
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
    if len(set(args.modes)) != len(args.modes):
        parser.error("modes must be unique")
    if not (math.isfinite(args.timeout) and math.isfinite(args.case_timeout)
            and args.case_timeout >= args.timeout > 0):
        parser.error("timeouts must be finite and case-timeout >= timeout > 0")
    for name in ("base_sha", "candidate_sha"):
        value = getattr(args, name)
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            parser.error(f"{name.replace('_', '-')} must be a full lowercase Git SHA")
    args.server_port, args.server_control_port, args.proxy_port = 18080, 18081, 10010
    if args.candidate_firewall_helper:
        args.candidate_firewall_helper = args.candidate_firewall_helper.resolve()
        if not args.candidate_firewall_helper.is_file():
            parser.error("candidate firewall helper must be an existing file")
    return args


def interrupted(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt("benchmark interrupted")


def main() -> int:
    args = parse_args()
    plan = make_plan(args.pairs, args.body_sizes, args.modes, args.include_direct)
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
    parameters["candidate_firewall_helper"] = str(args.candidate_firewall_helper) if args.candidate_firewall_helper else None
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
        payload["direct_aggregates"] = direct_aggregates(payload["results"], args)
        write_json(output / "summary.json", payload)
        if payload["environment"]:
            (output / "summary.md").write_text(markdown(payload))
        else:
            (output / "summary.md").write_text(f"# UA2F comparison failed\n\n{payload.get('error')}\n")
        print(f"Results: {output / 'summary.json'}", flush=True)
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
