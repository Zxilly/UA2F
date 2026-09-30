# Same-runner UA2F performance comparison

- Status: **passed**
- UTC start: `2026-09-30T07:20:22.484284+00:00`; finish: `2026-09-30T07:23:56.689780+00:00`
- Base: `f7965c1b5d4b0f31b8a97bc332b93db55e6c63ab`; candidate: `b42b291fb8cbb8ae362c2b12286c39ca9d2cba73`
- Host: `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`; CPUs: `4`; Go: `go version go1.22.2 linux/amd64`
- 6 adjacent pairs per workload; alternating base/candidate first
- 100000 measured + 10000 warmup requests; concurrency 128
- Workers: NFQUEUE=1, proxy=1
- Every measured AND warmup run must have zero errors and all HTTP 200; routed cases account for every rewritten UA
- Req/s and latency are end-to-end Go client measurements, including origin and kernel work
- Mbps estimates HTTP request+response bytes, not Ethernet/IP/TCP wire bandwidth
- CPU excludes warmup; 100% = one core. RSS is sampled at load end; HWM includes startup/warmup
- CV is population standard deviation / mean. Shared-runner noise is not statistical significance
- UA3F is not run; older README UA3F measurements remain historical data

- NFQUEUE original-direction conntrack matching is identical in both variants; candidate per-rule matching is preserved

| Body | Mode | Build | Req/s median | Req/s min–max | CV | Mbps median | P95 ms median | CPU % median | RSS KiB median | HWM KiB median |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1024 | NFQUEUE | base | 27519 | 27024–28025 | 1.13% | 288.6 | 9.851 | 38.9 | 2388 | 2388 |
| 1024 | NFQUEUE | candidate | 27124 | 26173–28106 | 2.38% | 284.4 | 9.992 | 37.9 | 2390 | 2390 |
| 65536 | NFQUEUE | base | 15853 | 15167–16383 | 2.44% | 8348.0 | 16.652 | 55.5 | 2390 | 2390 |
| 65536 | NFQUEUE | candidate | 17723 | 17063–18358 | 2.83% | 9332.9 | 16.150 | 27.0 | 2388 | 2388 |

## Paired throughput ratios (candidate / base)

- 1024 bytes / NFQUEUE: median 0.9771× (-2.29%), range 0.9685–1.0173×; CV 2.07%
- 65536 bytes / NFQUEUE: median 1.1253× (+12.53%), range 1.0751–1.1535×; CV 2.15%

## DIRECT diagnostic references

Same Go workload; unique-UA origin map bookkeeping differs. These are not paired speedups.
- 1024 bytes: 35046 req/s median
- 65536 bytes: 21958 req/s median

## NFQUEUE accounting

Counts use /proc NFQUEUE packet-ID deltas with unchanged drop counters, not recv syscall counts.
- 1024 bytes / base: 1.007 queued packets/request; UA2F user/system 4.10/10.25 µs/request
- 1024 bytes / candidate: 1.003 queued packets/request; UA2F user/system 4.00/10.10 µs/request
- 65536 bytes / base: 3.038 queued packets/request; UA2F user/system 7.95/27.40 µs/request
- 65536 bytes / candidate: 1.003 queued packets/request; UA2F user/system 4.60/10.80 µs/request

Full metadata, all metric distributions, and per-run raw JSON/logs are in the artifact.
