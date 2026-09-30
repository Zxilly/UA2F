# Same-runner UA2F performance comparison

- Status: **passed**
- UTC start: `2026-09-30T07:42:35.102487+00:00`; finish: `2026-09-30T07:46:01.239850+00:00`
- Base: `f7965c1b5d4b0f31b8a97bc332b93db55e6c63ab`; candidate: `be6cd4333a181cad18d2f8e1f4736678f861d44b`
- Host: `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`; CPUs: `4`; Go: `go version go1.22.2 linux/amd64`
- 6 adjacent pairs per workload; alternating base/candidate first
- 100000 measured + 10000 warmup requests; concurrency 128
- Workers: NFQUEUE=1, proxy=1
- Every measured AND warmup run must have zero errors and all HTTP 200; routed cases account for every rewritten UA
- Req/s and latency are end-to-end Go client measurements, including origin and kernel work
- Mbps estimates HTTP request+response bytes, not Ethernet/IP/TCP wire bandwidth
- Origin/UA2F CPU excludes warmup; client CPU includes startup/JSON/exit. 100% = one core
- Guest CPU is read-only /proc/stat and includes observer/colocated work; it is not physical-host CPU
- RSS is sampled at load end; HWM includes startup/warmup
- CV is population standard deviation / mean. Shared-runner noise is not statistical significance
- UA3F is not run; older README UA3F measurements remain historical data

- NFQUEUE original-direction conntrack matching is identical in both variants; candidate per-rule matching is preserved

| Body | Mode | Build | Req/s median | Req/s min–max | CV | Mbps median | P95 ms median | CPU % median | RSS KiB median | HWM KiB median |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1024 | NFQUEUE | base | 27793 | 26977–29700 | 3.45% | 291.4 | 9.760 | 40.4 | 2390 | 2390 |
| 1024 | NFQUEUE | candidate | 27746 | 27580–29694 | 2.64% | 291.0 | 9.750 | 40.0 | 2388 | 2388 |
| 65536 | NFQUEUE | base | 16596 | 16216–16872 | 1.43% | 8739.2 | 15.776 | 57.8 | 2392 | 2392 |
| 65536 | NFQUEUE | candidate | 18546 | 18442–18795 | 0.68% | 9766.3 | 15.019 | 27.6 | 2388 | 2388 |

## Paired throughput ratios (candidate / base)

- 1024 bytes / NFQUEUE: median 1.0010× (+0.10%), range 0.9835–1.0280×; CV 1.58%
- 65536 bytes / NFQUEUE: median 1.1197× (+11.97%), range 1.0986–1.1426×; CV 1.26%

## Whole-workload CPU accounting

CPU work per request; guest and process totals are distinct views and must not be added together.
| Body | Mode | Build | Client user/sys µs | Origin user/sys µs | All 3 processes µs | Guest busy µs | Guest system+irq+softirq µs | Guest busy CPU % |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1024 | NFQUEUE | base | 46.12/23.91 | 27.65/20.05 | 132.71 | 131.80 | 53.15 | 361.2 |
| 1024 | NFQUEUE | candidate | 46.18/24.42 | 27.80/19.75 | 132.67 | 131.70 | 53.50 | 359.1 |
| 65536 | NFQUEUE | base | 56.08/51.85 | 34.25/53.80 | 230.55 | 228.10 | 131.80 | 374.8 |
| 65536 | NFQUEUE | candidate | 56.04/51.62 | 33.65/49.55 | 205.88 | 204.75 | 110.45 | 374.9 |

## DIRECT diagnostic references

Same Go workload; unique-UA origin map bookkeeping differs. These are not paired speedups.
- 1024 bytes: 35701 req/s median
- 65536 bytes: 23058 req/s median

## NFQUEUE accounting

Counts use /proc NFQUEUE packet-ID deltas with unchanged drop counters, not recv syscall counts.
- 1024 bytes / base: 1.007 queued packets/request; UA2F user/system 4.15/10.50 µs/request
- 1024 bytes / candidate: 1.003 queued packets/request; UA2F user/system 4.05/10.45 µs/request
- 65536 bytes / base: 3.035 queued packets/request; UA2F user/system 7.75/27.55 µs/request
- 65536 bytes / candidate: 1.003 queued packets/request; UA2F user/system 4.30/10.85 µs/request

Full metadata, all metric distributions, and per-run raw JSON/logs are in the artifact.
