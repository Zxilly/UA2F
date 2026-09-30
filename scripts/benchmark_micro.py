#!/usr/bin/env python3
"""Pinned, alternating UA2F in-process benchmark comparison (standard library only).

Build both source revisions with the SAME CMake flags and this SAME harness:
  cmake -S BASE -B BASE/build-benchmark -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DUA2F_BUILD_BENCHMARKS=ON -DUA2F_ENABLE_UCI=OFF -DUA2F_ENABLE_BACKTRACE=OFF
  cmake --build BASE/build-benchmark --target ua2f_benchmark -j
  # Repeat for CANDIDATE, preserving all compiler/linker/configuration flags.
  python3 scripts/benchmark_micro.py --baseline BASE/build-benchmark/ua2f_benchmark \
    --candidate CANDIDATE/build-benchmark/ua2f_benchmark --cpu 2 --seconds .2 \
    --repetitions 9 --output comparison.json

One operation is one workload cycle. For segmented requests, also report
ns/packet; for pipeline workloads, one cycle includes all 16 requests.
No networking, NFQUEUE kernel delivery, sockets, conntrack or concurrency is
measured. Handler input malloc+copy and a replacement-payload verdict memcpy
ARE timed. Only successful persistent HTTP sessions are steady-state; malformed
HTTP incurs create/delete and parser error cases include parser initialization.
Full payload/checksum and parser-entry validation precedes every timed sample.
Warmup and validation are excluded. Time-based runs check time every 64 cycles.
Raw samples, iteration counts, exact commands, binary hashes, CPU affinity,
compiler flags and AB/BA order are retained. A CV is descriptive, not a CI.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


COMPARE_FIELDS = (
    "compiler", "build_type", "c_flags", "cxx_flags", "link_flags", "build_options",
    "benchmark_sha256", "packet_builder_sha256", "common_compile_options",
    "conntrack", "handler_input_allocation_timed", "verdict_payload_copy_timed", "syslog_mask",
)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_optional(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def cpu_metadata(cpu):
    info = read_optional("/proc/cpuinfo") or ""
    selected = {}
    for section in info.split("\n\n"):
        fields = dict(line.split(":", 1) for line in section.splitlines() if ":" in line)
        fields = {k.strip(): v.strip() for k, v in fields.items()}
        if fields.get("processor") == str(cpu):
            selected = {k: fields.get(k) for k in ("processor", "model name", "cpu MHz", "vendor_id", "microcode")}
            break
    prefix = "/sys/devices/system/cpu/cpu%d/cpufreq/" % cpu
    selected["governor"] = read_optional(prefix + "scaling_governor")
    selected["scaling_driver"] = read_optional(prefix + "scaling_driver")
    return selected


def describe_source(path):
    if not path:
        return None
    path = Path(path).resolve()
    def git(*args):
        result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None
    # A source digest distinguishes dirty candidates sharing a commit ID.
    digest = hashlib.sha256()
    for filename in sorted((path / "src").rglob("*")):
        if filename.is_file():
            digest.update(str(filename.relative_to(path)).encode() + b"\0")
            digest.update(filename.read_bytes())
    return {"path": str(path), "commit": git("rev-parse", "HEAD"),
            "status": git("status", "--short"), "production_source_sha256": digest.hexdigest(),
            "production_diff": git("diff", "--", "src")}


def summary(values):
    mean = statistics.mean(values)
    return {"n": len(values), "mean": mean, "median": statistics.median(values),
            "cv": statistics.pstdev(values) / mean if mean else 0,
            "min": min(values), "max": max(values)}


def write_report(path, report):
    # Keep all successful samples even when a later process fails/interruption
    # occurs. Replace atomically so an interrupted write leaves valid JSON.
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", type=Path, help="omit for a baseline-only profile")
    parser.add_argument("--baseline-source", type=Path)
    parser.add_argument("--candidate-source", type=Path)
    parser.add_argument("--cpu", type=int, help="single logical CPU; default first allowed CPU")
    length = parser.add_mutually_exclusive_group()
    length.add_argument("--seconds", type=float, default=None, help="seconds per sample (default .2)")
    length.add_argument("--iterations", type=int, help="fixed workload cycles per sample")
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--warmup", type=int, default=500)
    parser.add_argument("--modes", nargs="+", default=["parser", "handler4", "handler6"],
                        choices=["parser", "handler4", "handler6"])
    parser.add_argument("--workloads", nargs="+", help="default every workload printed by --list")
    parser.add_argument("--output", type=Path, default=Path("benchmark-comparison.json"))
    args = parser.parse_args()
    if args.seconds is None and args.iterations is None:
        args.seconds = .2
    if args.repetitions < 1 or args.warmup < 0 or (args.iterations is not None and args.iterations < 1) or \
       (args.seconds is not None and (not math.isfinite(args.seconds) or args.seconds <= 0)):
        parser.error("repetitions/run length must be positive; warmup must be nonnegative")
    if not hasattr(os, "sched_setaffinity"):
        parser.error("Linux sched_setaffinity is required for pinned comparisons")
    allowed = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed[0]
    if cpu not in allowed:
        parser.error("CPU %d is outside allowed affinity %s" % (cpu, allowed))
    os.sched_setaffinity(0, {cpu})
    binaries = {"baseline": args.baseline.resolve()}
    if args.candidate:
        binaries["candidate"] = args.candidate.resolve()
    for binary in binaries.values():
        if not binary.is_file():
            parser.error("missing binary: %s" % binary)
    available = subprocess.check_output([str(binaries["baseline"]), "--list"], text=True).splitlines()
    workloads = args.workloads or available
    if any(name not in available for name in workloads):
        parser.error("unknown workload; choose from %s" % ", ".join(available))
    report = {
        "schema_version": 1, "kind": "in_process_microbenchmark_comparison", "complete": False,
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "metadata": {"platform": platform.platform(), "python": platform.python_version(),
                     "cpu": cpu, "allowed_affinity_before": allowed, "affinity_during": sorted(os.sched_getaffinity(0)),
                     "cpu_info_before": cpu_metadata(cpu), "order": "AB on even repetitions, BA on odd repetitions, per workload/mode",
                     "repetitions": args.repetitions, "seconds_per_sample": args.seconds,
                     "iterations_per_sample": args.iterations, "warmup_cycles": args.warmup},
        "binaries": {role: {"path": str(binary), "sha256": sha256(binary)} for role, binary in binaries.items()},
        "sources": {"baseline": describe_source(args.baseline_source), "candidate": describe_source(args.candidate_source)},
        "raw_runs": [], "summaries": [],
        "limitations": ["Synthetic in-process single-thread measurements; not NFQUEUE or end-to-end throughput",
                        "No real kernel/socket/netlink transmission, conntrack lookup, NIC, routing or network latency",
                        "Handler includes input malloc/copy and preallocated mock-verdict payload copy when supplied",
                        "Packets are synthetically sized; larger cases may represent offload/segmentation workloads",
                        "CV describes sample dispersion; speedup is baseline median divided by candidate median",
                        "CPU pinning does not isolate the host; frequency scaling and unrelated load may remain"],
    }
    baseline_metadata = None
    write_report(args.output, report)
    try:
        for mode in args.modes:
            for workload in workloads:
                recorded = {role: [] for role in binaries}
                pair_values = []
                packets_per_op = None
                for repetition in range(args.repetitions):
                    order = list(binaries)
                    if repetition % 2:
                        order.reverse()
                    pair = {}
                    for role in order:
                        command = [str(binaries[role]), "--mode", mode, "--workload", workload,
                                   "--repetitions", "1", "--warmup", str(args.warmup)]
                        command += ["--iterations", str(args.iterations)] if args.iterations is not None else ["--seconds", str(args.seconds)]
                        start = time.time()
                        process = subprocess.run(command, capture_output=True, text=True, check=True)
                        result = json.loads(process.stdout)
                        metadata = result["metadata"]
                        if baseline_metadata is None:
                            baseline_metadata = metadata
                        differences = {key: [baseline_metadata.get(key), metadata.get(key)] for key in COMPARE_FIELDS
                                       if baseline_metadata.get(key) != metadata.get(key)}
                        if differences:
                            raise RuntimeError("build/harness mismatch: " + json.dumps(differences))
                        report["binaries"][role]["build_metadata"] = metadata
                        rows = result["results"]
                        if len(rows) != 1 or rows[0]["mode"] != mode or rows[0]["workload"] != workload:
                            raise RuntimeError("unexpected benchmark result selection")
                        row = rows[0]
                        packets_per_op = row["packets_per_op"]
                        sample = row["samples"][0]
                        if sample["iterations"] <= 0 or not math.isfinite(sample["ns_per_op"]) or sample["ns_per_op"] <= 0:
                            raise RuntimeError("invalid sample")
                        recorded[role].append(sample["ns_per_op"])
                        pair[role] = sample["ns_per_op"]
                        report["raw_runs"].append({"role": role, "repetition": repetition, "order": order,
                            "started_unix": start, "command": command, "result": result, "stderr": process.stderr})
                        write_report(args.output, report)
                    if "candidate" in pair:
                        pair_values.append(pair["baseline"] / pair["candidate"])
                row = {"mode": mode, "workload": workload, "packets_per_op": packets_per_op,
                       "ns_per_op": {role: summary(values) for role, values in recorded.items()}}
                row["median_ns_per_packet"] = {role: values["median"] / packets_per_op for role, values in row["ns_per_op"].items()}
                if "candidate" in recorded:
                    base = row["ns_per_op"]["baseline"]["median"]
                    candidate = row["ns_per_op"]["candidate"]["median"]
                    row["speedup_ratio"] = base / candidate
                    row["time_reduction_percent"] = (1 - candidate / base) * 100
                    row["paired_speedup_ratios"] = pair_values
                    row["paired_speedup_summary"] = summary(pair_values)
                    print("%-8s %-28s %10.1f -> %10.1f ns/op %7.3fx  CV %.2f%% / %.2f%%" % (
                        mode, workload, base, candidate, base / candidate,
                        row["ns_per_op"]["baseline"]["cv"] * 100, row["ns_per_op"]["candidate"]["cv"] * 100), flush=True)
                else:
                    print("%-8s %-28s %10.1f ns/op CV %.2f%%" % (
                        mode, workload, row["ns_per_op"]["baseline"]["median"], row["ns_per_op"]["baseline"]["cv"] * 100), flush=True)
                report["summaries"].append(row)
                write_report(args.output, report)
        # Fail if a binary was replaced while collecting samples.
        for role, binary in binaries.items():
            if sha256(binary) != report["binaries"][role]["sha256"]:
                raise RuntimeError(role + " binary changed during measurement")
        report["complete"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["metadata"]["cpu_info_after"] = cpu_metadata(cpu)
        write_report(args.output, report)
    print("Raw samples and summary: %s" % args.output)


if __name__ == "__main__":
    main()
