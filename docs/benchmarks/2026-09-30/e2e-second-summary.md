# Same-runner UA2F performance comparison

- Status: **passed**
- UTC start: `2026-09-30T03:16:15.134191+00:00`; finish: `2026-09-30T03:21:09.460403+00:00`
- Base: `4ff67c3770cb2dabc6f1427ef19277df093aafc1`; candidate: `c192712beeff892344ef8be57619c3c380617cf8`
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
| 1024 | NFQUEUE | base | 48827 | 46017–49681 | 2.46% | 512.0 | 5.745 | 42.5 | 2514 | 2514 |
| 1024 | NFQUEUE | candidate | 48315 | 47306–49812 | 1.73% | 506.6 | 5.707 | 41.6 | 2516 | 2516 |
| 1024 | REDIRECT | base | 39607 | 36543–40126 | 3.09% | 415.3 | 6.033 | 79.2 | 2264 | 3136 |
| 1024 | REDIRECT | candidate | 39298 | 37108–40074 | 2.53% | 412.1 | 5.951 | 79.9 | 2264 | 3146 |
| 1024 | TPROXY | base | 39820 | 38239–41682 | 3.25% | 417.6 | 6.254 | 76.8 | 2392 | 3334 |
| 1024 | TPROXY | candidate | 40318 | 37665–41159 | 3.03% | 422.8 | 6.349 | 76.4 | 2392 | 3336 |
| 65536 | NFQUEUE | base | 27542 | 27307–27913 | 0.67% | 14503.2 | 9.648 | 58.7 | 2514 | 2514 |
| 65536 | NFQUEUE | candidate | 27086 | 26972–27676 | 1.11% | 14263.2 | 9.846 | 57.5 | 2512 | 2512 |
| 65536 | REDIRECT | base | 25110 | 24503–25245 | 1.07% | 13222.9 | 9.467 | 82.5 | 2264 | 3200 |
| 65536 | REDIRECT | candidate | 24900 | 24016–25246 | 1.55% | 13111.8 | 9.391 | 81.8 | 2264 | 3122 |
| 65536 | TPROXY | base | 26059 | 25614–26573 | 1.34% | 13722.2 | 9.258 | 77.4 | 2392 | 3236 |
| 65536 | TPROXY | candidate | 26174 | 25640–26418 | 0.93% | 13783.0 | 9.280 | 77.2 | 2392 | 3272 |

## Paired throughput ratios (candidate / base)

- 1024 bytes / NFQUEUE: median 0.9915× (-0.85%), range 0.9769–1.0326×; CV 1.85%
- 1024 bytes / REDIRECT: median 0.9983× (-0.17%), range 0.9691–1.0155×; CV 1.62%
- 1024 bytes / TPROXY: median 1.0034× (+0.34%), range 0.9363–1.0344×; CV 3.34%
- 65536 bytes / NFQUEUE: median 0.9872× (-1.28%), range 0.9671–1.0073×; CV 1.48%
- 65536 bytes / REDIRECT: median 0.9883× (-1.17%), range 0.9795–1.0091×; CV 1.21%
- 65536 bytes / TPROXY: median 1.0014× (+0.14%), range 0.9877–1.0178×; CV 1.19%

Full metadata, all metric distributions, and per-run raw JSON/logs are in the artifact.
