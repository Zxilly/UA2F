# Routed workload diagnostics

- Status: **passed**
- Exact candidate: `c192712beeff892344ef8be57619c3c380617cf8`
- Diagnostic runs are not paired performance evidence. DIRECT retains the same Go workload; unique-UA origin bookkeeping differs from rewritten UAs.
- CPU = one core at 100%; user/system µs per request includes client startup/JSON/exit. Origin/UA2F exclude warmup.
- /proc CPU resolution is one clock tick; client uses wait4 minus immediate pre-exec getrusage. All processes share the same sampling wall window.
- Context switches sum OS threads, not only the leader; exited origin/UA2F threads can make those values lower bounds.
- Cgroup CPU includes observer/colocated work; inspect quota and throttling before attributing a limit.
- Traces are separate instrumented runs. Their timings/throughput are deliberately omitted; counts include startup/warmup/shutdown.

| Body | Mode | Diagnostic req/s | Process | CPU % | User µs/req | System µs/req | Vol ctx/req | Invol ctx/req |
| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1024 | DIRECT | 59208 | origin | 150.2 | 14.40 | 11.40 | 0.193 | 0.056 |
| 1024 | DIRECT | 59208 | client | 204.4 | 23.76 | 11.37 | 0.098 | 0.079 |
| 1024 | NFQUEUE | 49831 | origin | 128.2 | 14.80 | 11.20 | 0.243 | 0.073 |
| 1024 | NFQUEUE | 49831 | ua2f | 42.4 | 1.60 | 7.00 | 0.057 | 0.033 |
| 1024 | NFQUEUE | 49831 | client | 180.8 | 24.34 | 12.33 | 0.189 | 0.099 |
| 1024 | REDIRECT | 39814 | origin | 110.1 | 15.00 | 13.00 | 0.362 | 0.086 |
| 1024 | REDIRECT | 39814 | ua2f | 81.0 | 1.80 | 18.80 | 0.008 | 0.062 |
| 1024 | REDIRECT | 39814 | client | 154.7 | 25.15 | 14.20 | 0.278 | 0.109 |
| 1024 | TPROXY | 40791 | origin | 109.7 | 15.20 | 12.00 | 0.347 | 0.082 |
| 1024 | TPROXY | 40791 | ua2f | 77.4 | 1.60 | 17.60 | 0.017 | 0.084 |
| 1024 | TPROXY | 40791 | client | 162.0 | 26.13 | 14.04 | 0.275 | 0.111 |
| 65536 | DIRECT | 34969 | origin | 162.2 | 16.80 | 30.00 | 0.220 | 0.088 |
| 65536 | DIRECT | 34969 | client | 210.9 | 31.08 | 29.76 | 0.153 | 0.131 |
| 65536 | NFQUEUE | 24911 | origin | 123.6 | 18.80 | 31.20 | 0.302 | 0.104 |
| 65536 | NFQUEUE | 24911 | ua2f | 54.9 | 3.00 | 19.20 | 0.073 | 0.067 |
| 65536 | NFQUEUE | 24911 | client | 162.8 | 33.91 | 31.96 | 0.281 | 0.136 |
| 65536 | REDIRECT | 24833 | origin | 110.6 | 17.60 | 27.20 | 0.380 | 0.103 |
| 65536 | REDIRECT | 24833 | ua2f | 82.0 | 1.80 | 31.40 | 0.009 | 0.076 |
| 65536 | REDIRECT | 24833 | client | 168.9 | 33.02 | 35.40 | 0.345 | 0.159 |
| 65536 | TPROXY | 25538 | origin | 111.9 | 19.00 | 25.20 | 0.347 | 0.089 |
| 65536 | TPROXY | 25538 | ua2f | 78.0 | 1.80 | 29.00 | 0.016 | 0.083 |
| 65536 | TPROXY | 25538 | client | 175.1 | 32.69 | 36.47 | 0.297 | 0.155 |

## Cgroup CPU and throttling

- 1024 / DIRECT: client+origin+UA2F 354.6% of one core
  - Unavailable: No visible cgroup v2 mount
- 1024 / NFQUEUE: client+origin+UA2F 351.4% of one core
  - Unavailable: No visible cgroup v2 mount
- 1024 / REDIRECT: client+origin+UA2F 345.8% of one core
  - Unavailable: No visible cgroup v2 mount
- 1024 / TPROXY: client+origin+UA2F 349.1% of one core
  - Unavailable: No visible cgroup v2 mount
- 65536 / DIRECT: client+origin+UA2F 373.1% of one core
  - Unavailable: No visible cgroup v2 mount
- 65536 / NFQUEUE: client+origin+UA2F 341.2% of one core
  - Unavailable: No visible cgroup v2 mount
- 65536 / REDIRECT: client+origin+UA2F 361.5% of one core
  - Unavailable: No visible cgroup v2 mount
- 65536 / TPROXY: client+origin+UA2F 365.1% of one core
  - Unavailable: No visible cgroup v2 mount

## Instrumented syscall counts

Positive return sums mean bytes for read/recv/splice/send, events for epoll_wait, and messages for recvmmsg/sendmmsg.
### 1024 bytes / NFQUEUE; 2000 requests + 200 warmup
- sendto: 3437 calls, 0 errors; parsed errno {}; short reads 0; positive returns 3437, sum 549654
- recvmsg: 3421 calls, 1 errors; parsed errno {'EINTR': 1}; short reads 0; positive returns 3420, sum 765248
- close: 8 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334
- futex: 5 calls, 0 errors; parsed errno {}; short reads 0; positive returns 1, sum 1
- socket: 3 calls, 0 errors; parsed errno {}; short reads 0; positive returns 3, sum 12
- setsockopt: 3 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- write: 1 calls, 0 errors; parsed errno {}; short reads 0; positive returns 1, sum 30
- connect: 1 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
### 1024 bytes / REDIRECT; 2000 requests + 200 warmup
- splice: 6849 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 4400, sum 5130400
- recvfrom: 4912 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 2200, sum 311760
- sendto: 2215 calls, 0 errors; parsed errno {}; short reads 0; positive returns 2215, sum 312771
- epoll_ctl: 1538 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- close: 1035 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- setsockopt: 774 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- getsockopt: 513 calls, 1 errors; parsed errno {'ENOENT': 1}; short reads 0; positive returns 0, sum 0
- accept: 260 calls, 3 errors; parsed errno {'EAGAIN': 3}; short reads 0; positive returns 257, sum 71443
- socket: 259 calls, 0 errors; parsed errno {}; short reads 0; positive returns 259, sum 71706
- connect: 257 calls, 256 errors; parsed errno {'EINPROGRESS': 256}; short reads 0; positive returns 0, sum 0
- epoll_wait: 51 calls, 0 errors; parsed errno {}; short reads 0; positive returns 51, sum 5498
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334
### 1024 bytes / TPROXY; 2000 requests + 200 warmup
- splice: 6850 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 4400, sum 5130400
- recvfrom: 4912 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 2200, sum 311760
- sendto: 2215 calls, 0 errors; parsed errno {}; short reads 0; positive returns 2215, sum 312757
- epoll_ctl: 1538 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- close: 1035 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- setsockopt: 776 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- accept: 260 calls, 3 errors; parsed errno {'EAGAIN': 3}; short reads 0; positive returns 257, sum 66823
- socket: 259 calls, 0 errors; parsed errno {}; short reads 0; positive returns 259, sum 67086
- connect: 257 calls, 256 errors; parsed errno {'EINPROGRESS': 256}; short reads 0; positive returns 0, sum 0
- getsockopt: 256 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- epoll_wait: 52 calls, 0 errors; parsed errno {}; short reads 0; positive returns 52, sum 5490
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334
### 65536 bytes / NFQUEUE; 2000 requests + 200 warmup
- sendto: 24592 calls, 0 errors; parsed errno {}; short reads 0; positive returns 24592, sum 1226614
- recvmsg: 24576 calls, 1 errors; parsed errno {'EINTR': 1}; short reads 0; positive returns 24575, sum 3558032
- close: 8 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334
- futex: 5 calls, 0 errors; parsed errno {}; short reads 0; positive returns 1, sum 1
- socket: 3 calls, 0 errors; parsed errno {}; short reads 0; positive returns 3, sum 12
- setsockopt: 3 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- write: 1 calls, 0 errors; parsed errno {}; short reads 0; positive returns 1, sum 30
- connect: 1 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
### 65536 bytes / REDIRECT; 2000 requests + 200 warmup
- splice: 6856 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 4400, sum 288987600
- recvfrom: 4912 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 2200, sum 311760
- sendto: 2215 calls, 0 errors; parsed errno {}; short reads 0; positive returns 2215, sum 312771
- epoll_ctl: 1538 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- close: 1035 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- setsockopt: 774 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- getsockopt: 513 calls, 1 errors; parsed errno {'ENOENT': 1}; short reads 0; positive returns 0, sum 0
- accept: 260 calls, 3 errors; parsed errno {'EAGAIN': 3}; short reads 0; positive returns 257, sum 66823
- socket: 259 calls, 0 errors; parsed errno {}; short reads 0; positive returns 259, sum 67086
- connect: 257 calls, 256 errors; parsed errno {'EINPROGRESS': 256}; short reads 0; positive returns 0, sum 0
- epoll_wait: 54 calls, 1 errors; parsed errno {'EINTR': 1}; short reads 0; positive returns 53, sum 5485
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334
### 65536 bytes / TPROXY; 2000 requests + 200 warmup
- splice: 6856 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 4400, sum 288987600
- recvfrom: 4912 calls, 2200 errors; parsed errno {'EAGAIN': 2200}; short reads 0; positive returns 2200, sum 311760
- sendto: 2215 calls, 0 errors; parsed errno {}; short reads 0; positive returns 2215, sum 312757
- epoll_ctl: 1538 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- close: 1035 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- setsockopt: 776 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- accept: 260 calls, 3 errors; parsed errno {'EAGAIN': 3}; short reads 0; positive returns 257, sum 101447
- socket: 259 calls, 0 errors; parsed errno {}; short reads 0; positive returns 259, sum 101710
- connect: 257 calls, 256 errors; parsed errno {'EINPROGRESS': 256}; short reads 0; positive returns 0, sum 0
- getsockopt: 256 calls, 0 errors; parsed errno {}; short reads 0; positive returns 0, sum 0
- epoll_wait: 53 calls, 1 errors; parsed errno {'EINTR': 1}; short reads 0; positive returns 52, sum 5475
- read: 7 calls, 0 errors; parsed errno {}; short reads 2; positive returns 7, sum 4334

Raw /proc snapshots, cgroup counters, client/origin JSON and syscall traces are preserved in the artifact.
