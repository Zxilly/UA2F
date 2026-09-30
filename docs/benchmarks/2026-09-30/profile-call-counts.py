#!/usr/bin/env python3
r"""Count actual dynamically linked calls; discard all instrumented timing.

Example, from the repository root (both binaries must use this same harness):
  python3 docs/benchmarks/2026-09-30/profile-call-counts.py \
    --binary baseline=/path/to/base/build-benchmark/ua2f_benchmark \
    --binary candidate=/path/to/candidate/build-benchmark/ua2f_benchmark \
    --cpu 2 --output call-counts.json

By default, compile the adjacent profile-call-counts.c with the installed C
compiler into a temporary directory. Use --library /path/to/counter.so to reuse
an existing counter library. If dependencies are outside the system search
path, export LD_LIBRARY_PATH before running; the child processes inherit it.
A --workloads/--modes subset is useful for a short smoke check.

For each selection, run 1,000 and 2,000 cycles with zero warmup and subtract the
counts. This cancels startup and the three mandatory validation cycles. Divide
by the 1,000-cycle difference to obtain calls per complete workload operation.
LD_PRELOAD changes execution costs: none of these timings are speed evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


COUNTERS = {"tcp4", "tcp6", "ip4", "mangle4", "mangle6", "sysconf", "pagesize"}
DEFAULT_WORKLOADS = ["get_single_ua", "get_no_ua", "get_16_duplicate_ua",
                     "get_128_duplicate_ua", "get_16_pipelined", "post_segmented_body"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def collect(args, binaries, library, report):
    environment = dict(os.environ, LD_PRELOAD=str(library))
    for role, binary in binaries.items():
        for mode in args.modes:
            for workload in args.workloads:
                runs = []
                for iterations in (1000, 2000):
                    command = [str(binary), "--mode", mode, "--workload", workload,
                               "--iterations", str(iterations), "--repetitions", "1", "--warmup", "0"]
                    result = subprocess.run(command, env=environment, capture_output=True,
                                            text=True, timeout=60)
                    if result.returncode:
                        raise RuntimeError("command failed (%d): %s\n%s" % (
                            result.returncode, shlex.join(command), result.stderr))
                    output = json.loads(result.stdout)
                    lines = [line[len("UA2F_CALL_PROFILE "):] for line in result.stderr.splitlines()
                             if line.startswith("UA2F_CALL_PROFILE ")]
                    if len(lines) != 1:
                        raise RuntimeError("expected exactly one counter record: " + result.stderr)
                    counts = json.loads(lines[0])
                    if set(counts) != COUNTERS or any(type(n) is not int or n < 0 for n in counts.values()):
                        raise RuntimeError("unexpected counter schema")
                    rows = output["results"]
                    if (len(rows) != 1 or rows[0]["mode"] != mode or
                            rows[0]["workload"] != workload or len(rows[0]["samples"]) != 1 or
                            rows[0]["samples"][0]["iterations"] != iterations):
                        raise RuntimeError("unexpected benchmark selection or iteration count")
                    runs.append(counts)
                    report["raw"].append({
                        "role": role, "mode": mode, "workload": workload, "iterations": iterations,
                        "command": command, "binary_sha256": report["binaries"][role]["sha256"],
                        "build_metadata": output["metadata"], "counts": counts,
                        "validation": "benchmark exited successfully", "sink": output["sink"],
                    })
                    write_report(args.output, report)
                difference = {key: (runs[1][key] - runs[0][key]) / 1000 for key in sorted(COUNTERS)}
                if any(value < 0 for value in difference.values()):
                    raise RuntimeError("negative call-count difference; inspect raw runs")
                report["per_operation"].append({"role": role, "mode": mode,
                                                "workload": workload, "calls": difference})
                print(role, mode, workload, json.dumps(difference, sort_keys=True), flush=True)
                write_report(args.output, report)
    for role, binary in binaries.items():
        if sha256(binary) != report["binaries"][role]["sha256"]:
            raise RuntimeError(role + " binary changed during profiling")
    report["complete"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", action="append", required=True, metavar="ROLE=/PATH",
                        help="benchmark binary, repeat once per distinct role")
    parser.add_argument("--library", type=Path, help="existing LD_PRELOAD counter; otherwise compile adjacent C source")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"), help="compiler command for the temporary counter")
    parser.add_argument("--cpu", type=int, help="allowed logical CPU; default first allowed CPU")
    parser.add_argument("--output", type=Path, default=Path("profile-call-counts.json"))
    parser.add_argument("--modes", nargs="+", choices=["handler4", "handler6"], default=["handler4", "handler6"])
    parser.add_argument("--workloads", nargs="+", default=DEFAULT_WORKLOADS)
    args = parser.parse_args()
    if not hasattr(os, "sched_getaffinity"):
        parser.error("Linux CPU affinity and LD_PRELOAD are required")
    allowed = sorted(os.sched_getaffinity(0))
    cpu = allowed[0] if args.cpu is None else args.cpu
    if cpu not in allowed:
        parser.error("CPU %d is outside allowed affinity %s" % (cpu, allowed))
    binaries = {}
    for value in args.binary:
        role, separator, filename = value.partition("=")
        if not separator or not role or not filename or role in binaries:
            parser.error("use distinct nonempty ROLE=/PATH values for --binary")
        path = Path(filename).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error("not an executable file: " + str(path))
        binaries[role] = path
    if args.library is not None and not args.library.expanduser().is_file():
        parser.error("counter library not found: " + str(args.library))
    os.sched_setaffinity(0, {cpu})
    report = {
        "schema_version": 1, "kind": "dynamic_call_count_profile", "complete": False,
        "cpu": cpu, "allowed_affinity_before": allowed,
        "note": "LD_PRELOAD wrappers perturb execution. No instrumented timing is used. Calls per op are differences between 2000- and 1000-cycle processes, cancelling common initialization, 3 validation cycles, and zero warmup.",
        "ld_library_path": os.environ.get("LD_LIBRARY_PATH"),
        "binaries": {role: {"path": str(binary), "sha256": sha256(binary)} for role, binary in binaries.items()},
        "raw": [], "per_operation": [],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="ua2f-call-counter-") as temporary:
            if args.library is None:
                source = Path(__file__).resolve().with_suffix(".c")
                if not source.is_file():
                    raise RuntimeError("counter source not found beside this driver: " + str(source))
                library = Path(temporary) / "counter.so"
                command = shlex.split(args.cc) + ["-O2", "-fPIC", "-shared", "-o", str(library), str(source), "-ldl"]
                subprocess.run(command, check=True, timeout=60)
                report["build_command"] = command
                report["counter_source_sha256"] = sha256(source)
                report["library_source"] = "compiled adjacent source in temporary directory"
            else:
                library = args.library.expanduser().resolve()
                report["library_source"] = str(library)
            report["library_sha256"] = sha256(library)
            collect(args, binaries, library, report)
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        write_report(args.output, report)


if __name__ == "__main__":
    main()
