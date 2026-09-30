# Optional empty-ACK NFQUEUE path, 2026-09-30

## Result and scope

The final IPv4/iptables experiment measured **+11.97% paired median throughput for 64 KiB responses**, with all six pairs between +9.86% and +14.26%. The 1 KiB workload was effectively unchanged (+0.10%, range −1.65% to +2.80%). This is an optional, default-off firewall path; it is not a claim that every workload or router becomes faster.

The first successful layout had a small-response trade-off (+12.53% at 64 KiB, −2.29% at 1 KiB). Its negative result is retained. A logically equivalent early-queue layout avoids scanning all eleven precise empty-ACK predicates for obviously larger packets. The later run did not reproduce the small-response loss. These were separate shared runners; differences between their absolute request rates cannot isolate a layout speedup.

| Experiment | Candidate | 1 KiB paired req/s ratio | 64 KiB paired req/s ratio | Evidence |
| --- | --- | ---: | ---: | --- |
| Initial precise rules | `b42b291fb8cbb8ae362c2b12286c39ca9d2cba73` | 0.9771× | 1.1253× | [readable results](empty-ack-initial-summary.md), [complete metrics, gzip JSON](empty-ack-initial-summary.json.gz), [CI](https://github.com/Zxilly/UA2F/actions/runs/36683065831) |
| Equivalent early-queue layout | `be6cd4333a181cad18d2f8e1f4736678f861d44b` | 1.0010× | 1.1197× | [readable results](empty-ack-layout-summary.md), [complete metrics, gzip JSON](empty-ack-layout-summary.json.gz), [CI](https://github.com/Zxilly/UA2F/actions/runs/36685191916) |

Both compare against `f7965c1b5d4b0f31b8a97bc332b93db55e6c63ab`, which contains the earlier #222 userspace optimization and master `462e5bffb38a9682095b6c9fc7eb8367460a302e`'s half-close fix. **Production C sources are identical between this baseline and both candidates.** The new work changes rule selection/layout, tests and measurement only. The earlier ordinary-GET/parser experiments remain separate evidence.

## What is bypassed

Only a packet proven to contain no TCP data, with ACK set and SYN/FIN/RST clear, can return before NFQUEUE:

- IPv4: ordinary 20-byte IP header, no fragmentation, exact IP/TCP header lengths
- IPv6: base next-header TCP, exact IPv6 payload/TCP header lengths
- TCP doff 5–15 is covered, including TCP options
- IP options, IPv4 fragments, IPv6 extension/fragment headers, payload-bearing ACKs and SYN/FIN/RST retain the original queue path
- The feature never marks an entire connection as exempt; later keep-alive, pipelined and upload requests still pass through rewriting

Existing local-address/port/non-HTTP bypasses and connmark 44/43 operations retain their order. The final iptables layout places a coarse **NFQUEUE**, not an acceptance rule, before the eleven exact predicates. Every old IPv4 RETURN implies total length `20 + 4*d`, hence 40–80; every old IPv6 RETURN implies payload length `4*d`, hence 20–60. The coarse guard uses the same initial u32 read and transformation. Outside that interval, all old RETURN rules already fail at the first comparison. Both early and fallback NFQUEUE actions use identical queue number/range and bypass flags. Inside the interval, the old predicates are unchanged. Rule counters are partitioned between the two queue targets; packet disposition and marking are preserved.

The native nft helper remains unchanged from the first layout. **The throughput benchmark uses iptables 1.8.10 with its nf_tables backend, not direct native-nft rules.** Native nft throughput was not measured.

## Method and correctness

Each successful CI used an AMD EPYC 7763 guest reporting four logical CPUs (two cores, two SMT threads/core), Ubuntu/Linux `6.17.0-1022-azure`, GCC 13.3.0 and Go 1.22.2. Both binaries were independently built with identical RelWithDebInfo flags, UCI/backtrace/coverage/ASan off, cache on. Each body size has six adjacent A/B pairs, equally balanced AB/BA, 10,000 warmup and 100,000 measured requests, concurrency 128 and one NFQUEUE worker. DIRECT references appear before/after pairs in alternating rounds. DIRECT retains unique-UA origin-map bookkeeping and is diagnostic, not an exact optimization baseline.

All 36 timed samples and their warmups passed completed-request, HTTP 200, error and UA accounting. Four preceding real packet-path probes covered IPv4/IPv6 with both iptables and native nft: a split UA header, sixteen pipelined requests, a byte-preserved 65,536-byte POST, genuinely later requests after ACK-only intervals, an absent UA, complete large responses and half-close. Each backend/family required positive empty-ACK counters. These probes exercise ordinary TCP timestamps (doff=8); runtime behavior for every header-length/malformed-input combination was not exhaustively tested.

The final 19 offline firewall tests cover every declared 16-bit length, IPv4 fragment fields, flags/header combinations, maximal-header byte mutations, 20,000 random malformed strings, 96 init configurations, the necessary-condition proof and partial-install fallback. These are byte-model/equivalence checks, not a substitute for every kernel-path case. Eighteen accounting/construction/integration tests also pass. Production C behavior is unchanged by this firewall iteration.

The first attempted CI stopped at an nft test-wrapper syntax error before timing. The wrapper was fixed and regression-tested; it contributes no speed result. [Failed run](https://github.com/Zxilly/UA2F/actions/runs/36682198604), [retained failure artifact](https://github.com/Zxilly/UA2F/actions/runs/36682198604/artifacts/11081768895).

## Packet and whole-workload CPU accounting

Untraced NFQUEUE counts come from `/proc/net/netfilter/nfnetlink_queue` packet-ID deltas, requiring stable queue identity/configuration and unchanged kernel/userspace drop counters. Both queue backlogs and the wrap-aware deltas are retained. They count actual packet messages in the measured interval; **receive syscall counts are not used as packet counts**.

| Final run | Baseline | Candidate |
| --- | ---: | ---: |
| 1 KiB queued packets/request | 1.007 | 1.003 |
| 64 KiB queued packets/request | 3.035 | 1.003 |
| 64 KiB UA2F user/system µs/request | 7.75 / 27.55 | 4.30 / 10.85 |
| 64 KiB all-three-process CPU µs/request | 230.55 | 205.88 |
| 64 KiB guest busy CPU µs/request | 228.10 | 204.75 |
| 64 KiB guest system+irq+softirq µs/request | 131.80 | 110.45 |

Across paired samples, 64 KiB guest busy CPU/request fell 10.3%, guest kernel CPU/request fell 16.4%, and combined client/origin/UA2F CPU/request fell 10.7%. All six pairs point in the same direction. Guest busy utilization stayed around 3.75 logical CPUs; more requests were completed with less CPU work per request. Small-response CPU differences remain inconclusive.

UA2F and origin CPU use process `/proc` deltas after warmup. Client CPU uses a RUSAGE_CHILDREN delta around the only waited child, including its threads, ip-exec/startup, JSON output and exit. Guest `/proc/stat` busy work is user+nice+system+irq+softirq; guest fields are not counted twice, and idle/iowait/steal are excluded. Raw steal and other deltas are retained. The guest view includes observation and colocated work and is not physical-host CPU. Process/guest counters have distinct scopes and clock resolution, so their totals are not added together or required to match exactly. Sampling was read-only, without perf/ptrace/sysctl/host-network changes. These observational paired results do not establish a universal hardware guarantee.

## Configuration and compatibility

`ua2f.firewall.bypass_empty_ack` defaults to `0`; deployment compatibility and the measured coverage remain explicit. Enable it only for the desired NFQUEUE deployment:

```sh
uci set ua2f.firewall.bypass_empty_ack='1'
uci commit ua2f
service ua2f restart
```

iptables requires `iptables-mod-u32` and its `kmod-ipt-u32` dependency. The legacy-firewall package dependency is declared; if u32 rule installation fails, the init script warns and appends the normal NFQUEUE fallback. If the module is absent, the first guarded rule fails before any RETURN is installed. For a later partial-install error, any already installed RETURN rules remain limited to the same exact empty-ACK set; all other packets retain the unconditional queue fallback. nft uses its existing queue dependency and basic expressions. REDIRECT/TPROXY are unaffected. No router configuration was deployed by these experiments.

## Raw evidence and reproduction

The gzip summaries retain every result metric, per-run CPU/queue counters, paired ratios, correctness results, build/source hashes and a hash manifest of every original artifact file. Unrelated absolute paths, host/namespace identifiers, PIDs, memory addresses and environment dumps are omitted. Full latency arrays and logs remain in the GitHub artifacts until **2026-10-14**:

- [Initial artifact](https://github.com/Zxilly/UA2F/actions/runs/36683065831/artifacts/11083025682), ZIP SHA-256 `0d5bf9b2646d47426b3f94ff76e9d06631272740b7abb895e0c4e628a769a26c`
- [Final artifact](https://github.com/Zxilly/UA2F/actions/runs/36685191916/artifacts/11083028381), ZIP SHA-256 `9df96c228da33762879e304fff44f927b86d1bb77ba284edb086ab2143583a5d`

Build the exact baseline/candidate with the same flags in the existing performance workflow, then run `scripts/test_empty_ack_netns.py` before `scripts/benchmark_compare.py --modes NFQUEUE --include-direct --candidate-firewall-helper openwrt/files/ua2f.firewall`, using the recorded request counts and revisions. Both scripts require a disposable outer network namespace. The reproducible command/flags and complete outputs are in each run's logs and artifact.

The final workflow remains **workflow_dispatch only**, with diagnostics off by default. These runs used explicitly approved, exact-branch/exact-message temporary push triggers because the workflow was not yet registered on master; those triggers were removed after execution. No permanent PR/merge performance gate was added, and master was not changed.
