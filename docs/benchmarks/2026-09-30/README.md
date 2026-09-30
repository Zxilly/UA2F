# UA2F performance measurements, 2026-09-30

## Scope and source revisions

- Baseline production sources: fresh master `4ff67c3770cb2dabc6f1427ef19277df093aafc1`, including the dynamic utarray/inline-eight, pipelining, sticky OOM, and active-upload TTL fixes from #221.
- First optimized production sources: `f12729b07c615e33f7d607df6cf03c96e7f30a06`; the following `f056be2` commit changes CI configuration only.
- No compiler optimization flags, parser grammar, inline storage capacity, conntrack semantics, or idle TTL were relaxed to obtain the results.
- In-process microbenchmarks and routed end-to-end benchmarks are different experiments. Never interpret a dense-header microbenchmark speedup as network throughput or compare results across these machines.

## In-process experiment

Environment: Debian 13 (trixie), Linux 6.18.44 x86_64, GCC 14.2.0, reported AMD EPYC 9V74 80-Core Processor. This is a shared virtualized environment with nine allowed logical CPUs; benchmark processes were pinned to logical CPU 2. Host governor/turbo/isolation were not controlled.

Both builds used `RelWithDebInfo` (`-O2 -g -DNDEBUG`), `-fno-omit-frame-pointer -fno-strict-aliasing`, UCI/backtrace/coverage/sanitizers disabled, default replacement UA, and the same extracted libnetfilter-queue dependencies. Full flags, dependency paths, executable/harness hashes, source status and diffs, and CPU metadata are recorded in [micro-summary.json](micro-summary.json).

The benchmark runs the production parser or production IPv4/IPv6 handler. Before every timed sample it verifies three full cycles. The 13 parser cases verify parse results and UA spans (offset, length, replacement offset); the 26 IPv4/IPv6 handler cases verify exact replacement bytes, unchanged packet lengths, and independently computed IP/TCP checksums. Packet construction and expected results are outside timing. The handler timing includes the input malloc/copy required by its ownership API, session lookup and locks, parser, statistics, packet-buffer allocation, rewriting/checksums, and a preallocated verdict-payload copy when one is returned. Conntrack is disabled and syslog is masked. No netlink socket, kernel queue, firewall, real TCP, origin server, or load generator is involved.

Each sample warms 500 cycles, then runs for at least 200 ms (batches of 64 cycles). There are nine adjacent A/B repetitions per workload, reversing order each repetition, across 13 workloads and three modes: 702 raw samples. An operation is one complete workload cycle, so split requests include multiple packets and a 16-request pipeline is one operation, not one request. Tables report median nanoseconds per operation, baseline/candidate median ratio, and population coefficient of variation (CV). The report also retains every paired ratio and min/max/mean.

The baseline was built with the exact same benchmark harness and CMake target copied into its worktree; only those benchmark/build additions made it dirty. Its `src/` files remain the pinned baseline. The candidate confirmation came from a clean detached checkout. The runner rejects mismatched compiler flags, build options, or harness hashes.

### Controls and interpretation

The unchanged parser controls differ by roughly 3–12% between binary layouts in this environment. Per-run CV alone therefore does not capture all layout/systematic effects. Effects of a few percent, including no-UA packets, the full 16 KiB POST, many irrelevant headers, TLS, and ACKs, are inconclusive. Large dense-UA and pipelining improvements are repeatable, but these workloads must be identified explicitly. The 128-duplicate-UA case is a stress case, not a typical request.

- [All 39-case summaries](micro-summary.json)
- [All 702 raw samples, gzip JSON](micro-raw.json.gz)

### Incremental attribution

Each step was built separately with identical harness/flags and measured using five alternating 50 ms samples per workload. The patches are cumulative against the baseline and are supplied for reproducibility; the final production diff is in the commits above.

1. [Omit unchanged verdict payloads](iteration01-no-verdict-payload.patch): avoids sending body-only/no-UA bytes back to the kernel. The segmented-body IPv4 microbenchmark improved about 1.26×; the no-UA small-packet effect remains inconclusive.
2. [Cache replacement capacity](iteration02-cache-capacity.patch): avoids repeatedly evaluating libmnl's page-size expression. Single-UA IPv4 improved about 1.10× in the incremental comparison.
3. Batch same-length UA writes/checksums and fill only the replacement suffix: large duplicate/pipeline batches avoid repeated full-packet checksum scans.

Raw incremental reports: [base → 1](benchmark-increment-base-01.json.gz), [1 → 2](benchmark-increment-01-02.json.gz), [2 → final](benchmark-increment-02-final.json.gz). They support attribution; the longer confirmation above is the main published microbenchmark.

### Actual call-count profiling

A disposable LD_PRELOAD counter intercepted the dynamically linked mangle/checksum/sysconf APIs. Subtracting otherwise identical 1,000-cycle and 2,000-cycle runs removes startup/validation/warmup counts. Original code calls the libc function `sysconf(_SC_PAGESIZE)` four times per UA (these are not four kernel syscalls); the cache removes those calls. Original code checksums the full TCP packet once per UA (16/128 for the corresponding duplicate workloads); optimized code computes it once per rewritten UA-bearing packet (zero for no-UA packets), for IPv4 and IPv6. Instrumented timings were discarded.

[Counter source](profile-call-counts.c), [driver](profile-call-counts.py), [96 raw profiles and 48 deltas](profile-call-counts.json.gz), [raw file hashes](raw-manifest.json).

## Reproduction

Install the normal development dependencies listed by the CI workflow. From a checkout containing both commits, use fresh directories (do not reuse build caches):

```sh
git worktree add --detach ../ua2f-bench-base 4ff67c3770cb2dabc6f1427ef19277df093aafc1
git worktree add --detach ../ua2f-bench-candidate f12729b07c615e33f7d607df6cf03c96e7f30a06
# Use exactly the same benchmark/build definitions with unchanged base src/.
cp ../ua2f-bench-candidate/CMakeLists.txt ../ua2f-bench-base/CMakeLists.txt
cp ../ua2f-bench-candidate/test/benchmark.cc ../ua2f-bench-base/test/benchmark.cc
git -C ../ua2f-bench-base diff --exit-code -- src/
for source in ../ua2f-bench-base ../ua2f-bench-candidate; do
  env -u UA2F_ENABLE_ASAN cmake -S "$source" -B "$source/build-benchmark" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DUA2F_BUILD_BENCHMARKS=ON \
    -DUA2F_BUILD_TESTS=OFF -DUA2F_ENABLE_UCI=OFF -DUA2F_ENABLE_ASAN=OFF \
    -DUA2F_ENABLE_BACKTRACE=OFF -DUA2F_ENABLE_COVERAGE=OFF
  cmake --build "$source/build-benchmark" --target ua2f_benchmark
done
python3 scripts/benchmark_micro.py \
  --baseline ../ua2f-bench-base/build-benchmark/ua2f_benchmark \
  --candidate ../ua2f-bench-candidate/build-benchmark/ua2f_benchmark \
  --baseline-source ../ua2f-bench-base --candidate-source ../ua2f-bench-candidate \
  --cpu 2 --seconds .2 --repetitions 9 --output comparison.json
```

Choose an allowed logical CPU on the target machine. Do not run builds or other benchmark jobs concurrently on it. Keep raw results, including negative/inconclusive cases.

## Correctness verification

- Fresh baseline: 144 native tests passed.
- Optimized code: 151 ASan+UBSan tests passed, including independent checksums, IPv4/TCP options, IPv6 extension headers, >8/pipelined UAs, replacement-capacity crossing, no-UA connmarks, active uploads, and sticky allocation failures.
- LeakSanitizer could not run under this ptraced local runtime (`detect_leaks=0`); this is not a leak-check claim.
- All 39 microbenchmark cases validate before timing: 13 parser cases check parse results/spans, and 26 handler cases check packet bytes/length/checksums.
- The five additional checksum/long-UA regressions also pass the original master handler, confirming they exercise preserved behavior.

## Routed benchmark methodology

The dedicated [performance workflow](../../../.github/workflows/performance.yml) uses a normal GitHub-hosted Ubuntu runner, `contents: read`, a 35-minute job timeout, an 18-minute benchmark timeout, and a separate eight-minute diagnostics timeout. Both exact commits are built on that runner with the same compiler and `RelWithDebInfo`, UCI/backtrace/coverage/ASan off. Worker counts are explicitly fixed at one for both NFQUEUE and proxy modes.

The comparison runs in an additional disposable network namespace. A separate client namespace reaches the origin through PREROUTING, exercising real NFQUEUE/REDIRECT/TPROXY and keep-alive TCP. For each mode and 1 KiB/64 KiB response workload, it runs six adjacent A/B pairs, equally balanced AB/BA, rotating modes and reversing body-size order. Each case uses 10,000 warmup requests and 100,000 measured requests at concurrency 128. Response size is not upload size.

Every sample must have exactly the expected completed/client/origin requests, no errors, all HTTP 200, and fully accounted-for rewritten UAs. CPU is sampled after warmup; 100% means one occupied core. RSS and high-water memory are process measurements. Full latency arrays, origin UA counts, build logs/cache, binary hashes, kernel/CPU/toolchain metadata, errors, paired ratios, and min/max/CV are preserved. Incomplete/failed workloads never produce a speed claim. Shared-runner results are observational, not a controlled hardware throughput guarantee.

### First routed result

The [completed run](https://github.com/Zxilly/UA2F/actions/runs/36661195647) compared baseline `4ff67c3` with `f056be2` on AMD EPYC 7763 (4 vCPU), Ubuntu / Linux `6.17.0-1022-azure`, Go 1.22.2. All 72 measured cases and their warmups passed. Paired ordinary-GET throughput medians ranged from −0.64% to +0.75%; **no clear end-to-end throughput improvement was measured**. This is consistent with the optimized parsing/rewriting being only one component of the routed path, not proof of a particular remaining bottleneck.

See [full readable table](e2e-summary.md), [all metrics and metadata](e2e-summary.json), [per-run request/UA/validation outputs](e2e-per-run.json.gz), and [build metadata](e2e-build-metadata.json). Median UA2F process CPU per request was approximately 12.45→12.30 µs (1 KiB NFQUEUE), 29.10→29.25 µs (REDIRECT), and 26.60→26.30 µs (TPROXY); small deltas remain inconclusive. Full per-request latency arrays and complete logs are in the [GitHub artifact](https://github.com/Zxilly/UA2F/actions/runs/36661195647/artifacts/11074866229), retained until 2026-10-14. Its ZIP SHA-256 is `3cadfbbddb9718e3ba3afa3243ffa66d22e9c6fceef3246d3c98d5c720811c37`. The permanently stored per-run file omits large latency arrays but retains their original file hashes and sample counts; aggregate latency statistics and every run's metrics are retained.

### Rejected lock-held-write experiment

A separate experimental worktree removed the handler's result-entry copy/allocation by validating and writing UA spans while holding the session state lock. It passed 47 handler/PCAP tests, ASan (leak checks unavailable), and 100 repetitions of an added concurrent cleaner/four-worker regression. No incorrect bytes or deadlock were observed.

The ordinary handler gain was only about 2% median across 26 cases. Instrumented lock hold grew roughly 4–6% in duplicate/long-UA cases. Contention results were mixed, with worse same-session latency under deliberately aggressive cleaning. That harness used two workers on CPUs 2/3, an optional cleaner on CPU 6 every **100 µs** (production: **60 seconds**), 100 warmups, 5,000 packets per worker, and seven AB/BA repetitions; it is risk evidence, **not a production p99 prediction**. The small benefit did not justify a longer critical section, so none of this experimental code is included in the PR.


## Next routed diagnostic pass

The workflow also prepares untraced DIRECT/NFQUEUE/REDIRECT/TPROXY process accounting for 1 KiB and 64 KiB responses, followed by separate short syscall traces. It records client/origin/UA2F user/system CPU, CPU per request, thread-aware context switches, thread exits, cgroup CPU/throttling, and syscall/EAGAIN counts. Traced timings are excluded from speed comparisons. No security setting is changed to enable tracing; this local environment rejects ptrace, so actual tracing must be verified on the normal CI runner. Results are pending, and no bottleneck attribution is asserted from this pass yet.
