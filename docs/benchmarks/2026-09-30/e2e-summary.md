# Same-runner UA2F performance comparison

- Status: **passed**
- UTC start: `2026-09-30T02:45:32.086299+00:00`; finish: `2026-09-30T02:52:20.122433+00:00`
- Base: `4ff67c3770cb2dabc6f1427ef19277df093aafc1`; candidate: `f056be200811cf811fb86bce784a40d810b0cfb3`
- Host: `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`; CPUs: `4`; Go: `go version go1.22.2 linux/amd64`
- 6 adjacent pairs per workload; alternating base/candidate first
- 100000 measured + 10000 warmup requests; concurrency 128
- Workers: NFQUEUE=1, proxy=1
- Every measured AND warmup run must have zero errors, all HTTP 200, and all origin UAs rewritten
- Req/s and latency are end-to-end Go client measurements, including origin and kernel work
- Mbps estimates HTTP request+response bytes, not Ethernet/IP/TCP wire bandwidth
- CPU excludes warmup; 100% = one core. RSS is sampled at load end; HWM includes startup/warmup
- CV is population standard deviation / mean. Shared-runner noise is not statistical significance
- UA3F is not run; older README UA3F measurements remain historical data

| Body | Mode | Build | Req/s median | Req/s min–max | CV | Mbps median | P95 ms median | CPU % median | RSS KiB median | HWM KiB median |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1024 | NFQUEUE | base | 33092 | 31939–33958 | 2.14% | 347.0 | 8.041 | 40.3 | 2384 | 2384 |
| 1024 | NFQUEUE | candidate | 33225 | 32002–34347 | 2.16% | 348.4 | 8.119 | 40.3 | 2388 | 2388 |
| 1024 | REDIRECT | base | 27195 | 25577–27801 | 2.71% | 285.2 | 8.608 | 78.1 | 2136 | 3072 |
| 1024 | REDIRECT | candidate | 27177 | 24424–28179 | 4.90% | 285.0 | 8.731 | 78.0 | 2136 | 3126 |
| 1024 | TPROXY | base | 28416 | 26836–28884 | 2.79% | 298.0 | 8.594 | 74.5 | 2264 | 3130 |
| 1024 | TPROXY | candidate | 28681 | 26926–29194 | 2.64% | 300.8 | 8.403 | 74.2 | 2264 | 3208 |
| 65536 | NFQUEUE | base | 18846 | 18433–20161 | 3.57% | 9924.3 | 14.102 | 58.1 | 2388 | 2388 |
| 65536 | NFQUEUE | candidate | 18925 | 17976–20078 | 3.99% | 9965.8 | 14.068 | 57.5 | 2384 | 2384 |
| 65536 | REDIRECT | base | 16976 | 16163–18131 | 4.27% | 8939.2 | 12.818 | 81.7 | 2136 | 3006 |
| 65536 | REDIRECT | candidate | 17181 | 15599–17996 | 5.36% | 9047.2 | 12.865 | 81.8 | 2136 | 2956 |
| 65536 | TPROXY | base | 17978 | 17079–18667 | 3.55% | 9467.0 | 13.000 | 76.7 | 2264 | 3192 |
| 65536 | TPROXY | candidate | 17745 | 16991–18818 | 3.49% | 9344.3 | 13.228 | 76.8 | 2264 | 3206 |

## Paired throughput ratios (candidate / base)

- 1024 bytes / NFQUEUE: median 1.0017× (+0.17%), range 0.9783–1.0518×; CV 2.23%
- 1024 bytes / REDIRECT: median 1.0050× (+0.50%), range 0.8985–1.0136×; CV 4.11%
- 1024 bytes / TPROXY: median 1.0075× (+0.75%), range 0.9994–1.0398×; CV 1.31%
- 65536 bytes / NFQUEUE: median 1.0015× (+0.15%), range 0.9689–1.0094×; CV 1.34%
- 65536 bytes / REDIRECT: median 0.9988× (-0.12%), range 0.9651–1.0183×; CV 1.86%
- 65536 bytes / TPROXY: median 0.9936× (-0.64%), range 0.9831–1.0222×; CV 1.29%

Full metadata, all metric distributions, and per-run raw JSON/logs are in the artifact.
