# UA2F

[![CodeQL](https://github.com/Zxilly/UA2F/actions/workflows/codeql.yml/badge.svg)](https://github.com/Zxilly/UA2F/actions/workflows/codeql.yml)
[![Build OpenWRT Package](https://github.com/Zxilly/UA2F/actions/workflows/ci.yml/badge.svg)](https://github.com/Zxilly/UA2F/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Zxilly/UA2F/graph/badge.svg?token=6PBFSZCDWP)](https://codecov.io/gh/Zxilly/UA2F)

参照 [博客文章](https://learningman.top/archives/304) 完成操作

如果遇到了任何问题，欢迎提出 Issues，但是更欢迎直接提交 Pull Request

> 由于新加入的 CONNMARK 影响，编译内核时需要添加 `NETFILTER_NETLINK_GLUE_CT` flag
 
> 可以在网页 [http://ua-check.stagoh.com](http://ua-check.stagoh.com) 上测试 UA2F 是否正常工作

## 快速开始

```bash
# 启用 UA2F
uci set ua2f.enabled.enabled=1

# 可选的防火墙配置选项
# 是否自动添加防火墙规则
uci set ua2f.firewall.handle_fw=1

# 是否尝试处理 443 端口的流量， 通常来说，流经 443 端口的流量是加密的，因此无需处理
uci set ua2f.firewall.handle_tls=1

# 是否处理微信的流量，微信的流量通常是加密的，因此无需处理。这一规则在启用 nftables 时无效
uci set ua2f.firewall.handle_mmtls=1

# 是否处理内网流量，如果你的路由器是在内网中，且你想要处理内网中的流量，那么请启用这一选项
uci set ua2f.firewall.handle_intranet=1

# 使用自定义 User-Agent
uci set ua2f.main.custom_ua="Test UA/1.0"

# 运行模式，默认 NFQUEUE；也可使用 REDIRECT 或 TPROXY
uci set ua2f.main.mode="TPROXY"

# REDIRECT/TPROXY 透明代理监听端口，默认 10010
uci set ua2f.main.listen_port="10010"

# NFQUEUE 模式 worker 数，默认 1；自动防火墙规则会同步使用 queue-balance
uci set ua2f.main.nfqueue_workers="1"

# REDIRECT/TPROXY 模式代理 worker 数，默认 0 表示自动
uci set ua2f.main.proxy_workers="0"

# 禁用 Conntrack 标记，这会降低性能，但是有助于和其他修改 Connmark 的软件共存
uci set ua2f.main.disable_connmark=1

# 应用配置
uci commit ua2f

# 开机自启
service ua2f enable

# 启动 UA2F
service ua2f start

# 读取日志
logread | grep UA2F
```

## 配置

UA2F 的 OpenWRT 配置位于 `/etc/config/ua2f`。修改后需要执行 `uci commit ua2f`，并通过 `service ua2f restart` 重新启动服务。启用自动防火墙规则时，init 脚本会按 `main.mode` 生成对应规则。

### enabled

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `0` | 是否启用 UA2F 服务。 |

```bash
uci set ua2f.enabled.enabled=1
```

### main

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | `NFQUEUE` | 运行模式，可选 `NFQUEUE`、`REDIRECT`、`TPROXY`。UCI 可以直接设置该值；命令行 `--mode` 会覆盖 UCI 配置。 |
| `listen_port` | `10010` | `REDIRECT`/`TPROXY` 模式的本地透明代理监听端口。`NFQUEUE` 模式不使用该端口。 |
| `nfqueue_workers` | `1` | `NFQUEUE` 模式的工作线程和队列数量，范围 `1`-`16`。启用自动防火墙规则时会生成对应的 queue-balance 规则。 |
| `proxy_workers` | `0` | `REDIRECT`/`TPROXY` 模式的代理 worker 数，范围 `0`-`16`。`0` 表示自动，当前最多使用 4 个 CPU。 |
| `custom_ua` | 空 | 自定义 User-Agent 替换内容。UA2F 不改变包长度，长度不足会补空格，过长会截断。 |
| `disable_connmark` | `0` | 禁用 Conntrack 标记和缓存。会降低性能，但可避免和其他修改 Connmark 的程序冲突。 |
| `max_http_sessions` | `0` | HTTP parser session 上限，`0` 表示不限制。 |
| `session_ttl` | `300` | HTTP session 空闲过期时间，单位秒。 |

```bash
uci set ua2f.main.mode='TPROXY'
uci set ua2f.main.listen_port='10010'
uci set ua2f.main.nfqueue_workers='1'
uci set ua2f.main.proxy_workers='0'
uci set ua2f.main.custom_ua='Test UA/1.0'
uci set ua2f.main.disable_connmark='0'
uci set ua2f.main.max_http_sessions='0'
uci set ua2f.main.session_ttl='300'
uci commit ua2f
service ua2f restart
```

模式选择：

- `NFQUEUE`：默认模式，保持原有行为，通过 netfilter queue 改写 TCP 包。
- `REDIRECT`：透明代理模式，防火墙将流量 REDIRECT 到本地监听端口，再由 UA2F 连接原始目标。
- `TPROXY`：透明代理模式，适合接管转发流量；需要策略路由把 `fwmark 0x1c9` 指向 `lo`。固定监听端口的 TPROXY 不处理本机 OUTPUT 流量，本机流量请使用 `REDIRECT` 或 `NFQUEUE`。

### firewall

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `handle_fw` | `1` | 是否由 init 脚本自动安装防火墙规则。关闭后需要手动配置 netfilter。 |
| `handle_tls` | `0` | 是否处理 443 端口流量。通常 HTTPS 已加密，不需要处理。 |
| `handle_intranet` | `1` | 是否处理内网/保留地址流量。设为 `0` 时会绕过内网/保留地址。 |
| `handle_mmtls` | `0` | 是否处理微信 mmtls 流量。该规则仅在 iptables NFQUEUE 分支中生效，nftables 分支无效。 |
| `bypass_empty_ack` | `0` | NFQUEUE 可选优化：严格确认无 TCP 数据、ACK 置位且无 SYN/FIN/RST 的普通包不入队；IP options、分片、IPv6 扩展头继续原路径。 |

```bash
uci set ua2f.firewall.handle_fw='1'
uci set ua2f.firewall.handle_tls='0'
uci set ua2f.firewall.handle_intranet='1'
uci set ua2f.firewall.handle_mmtls='0'
uci commit ua2f
service ua2f restart
```

空 ACK 优化默认保持关闭，便于按设备的防火墙后端和覆盖范围选择启用；不会改变 REDIRECT/TPROXY。iptables 后端需要 `iptables-mod-u32`（依赖 `kmod-ipt-u32`），对应的 OpenWrt 包依赖已声明；缺少该匹配模块时会提示并保留普通 NFQUEUE fallback。nftables 使用原有 `kmod-nft-queue` 及基础表达式。本轮实际验证了 IPv4/IPv6 × iptables/nft 的正确性，吞吐数据仅覆盖 IPv4/iptables 路径，详见下方报告。

```bash
uci set ua2f.firewall.bypass_empty_ack='1'
uci commit ua2f
service ua2f restart
```

## 自定义 User-Agent

### 集成到二进制

`make menuconfig` 后，使用 option 设置

![image](https://github.com/Zxilly/UA2F/assets/31370133/09469f69-4481-4bd8-9ce3-7029df33838d)

`UA2F_CUSTOM_UA` 的值必须是一个字符串，且长度不超过 `(65535 + (MNL_SOCKET_BUFFER_SIZE / 2))` 字节。 `MNL_SOCKET_BUFFER_SIZE` 的值通常为 8192。

### 使用 uci 设置

```bash
uci set ua2f.main.custom_ua="Test UA/1.0"
uci commit ua2f
```

> UA2F 不会修改包的大小，因此即使自定义了 User-Agent， 运行时实际的 User-Agent 会是一个从 custom ua 中截取的长度与原始 User-Agent 相同的子串，长度不足时会在末尾补空格。

## 在非 OpenWRT 系统上运行

自 `v4.5.0` 起，UA2F 支持在非 OpenWRT 系统上运行，但是需要手动配置防火墙规则，将需要处理的流量转发到 `netfilter-queue` 的 10010 队列中。

编译时，需要添加 `-DUA2F_ENABLE_UCI=OFF` flag 至 CMake。

默认模式仍为 NFQUEUE。非 OpenWRT 环境也可以使用透明代理模式：

```bash
sudo ./build/ua2f --mode REDIRECT --listen-port 10010
sudo ./build/ua2f --mode TPROXY --listen-port 10010
```

REDIRECT/TPROXY 需要自行配置对应的 netfilter 规则。TPROXY 还需要 `fwmark 0x1c9` 指向本机 `lo` 的策略路由；UA2F 的出站连接会设置 `SO_MARK 0xc9`，防火墙规则应绕过该 mark 以避免回环。固定监听端口的 TPROXY 模式只适合接管 PREROUTING/转发流量，本机 OUTPUT 流量请使用 REDIRECT 或 NFQUEUE。

## Benchmark

### 本轮优化：同机 A/B（2026-09-30）

从 master `4ff67c3` 与本分支 `f056be2` 分别构建，在同一台 GitHub Actions Ubuntu runner 上交替测试：AMD EPYC 7763（4 vCPU）、Linux `6.17.0-1022-azure`、Go `1.22.2`；`RelWithDebInfo`，UCI/backtrace/ASan/coverage 关闭，NFQUEUE 和代理均固定 1 worker。客户端通过独立 network namespace 的 PREROUTING 访问 origin，使用 HTTP keep-alive，并发 128；每次预热 10000、测量 100000 请求，每组 6 对 AB/BA。

72 次正式运行及对应预热均无请求错误，HTTP 状态和服务端 UA 改写数量全部通过校验。普通 GET 的端到端吞吐变化处于本次共享 runner 的波动范围内，**没有测得明确的整体吞吐提升**；不能将下面的热路径微基准倍数当作网络吞吐提升。

| 响应体 | 模式 | master Req/s | 本分支 Req/s | 配对吞吐比中位数 | Req/s CV（基线 / 本分支） |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 KiB | NFQUEUE | 33092 | 33225 | 1.0017× | 2.14% / 2.16% |
| 1 KiB | REDIRECT | 27195 | 27177 | 1.0050× | 2.71% / 4.90% |
| 1 KiB | TPROXY | 28416 | 28681 | 1.0075× | 2.79% / 2.64% |
| 64 KiB | NFQUEUE | 18846 | 18925 | 1.0015× | 3.57% / 3.99% |
| 64 KiB | REDIRECT | 16976 | 17181 | 0.9988× | 4.27% / 5.36% |
| 64 KiB | TPROXY | 17978 | 17745 | 0.9936× | 3.55% / 3.49% |

Req/s 为各 6 次运行的中位数；配对吞吐比为每对「本分支 / 基线」的中位数，两者计算方式不同。完整延迟、CPU、RSS、min/max、每次运行数据及复现方法见 [测量报告](docs/benchmarks/2026-09-30/README.md) 和 [CI 运行](https://github.com/Zxilly/UA2F/actions/runs/36661195647)。

在另一台 4 vCPU AMD EPYC 9V74 runner 上，对 `c192712` 的第二轮 72 次 A/B 复测也未测得明确收益（配对中位吞吐比 0.9872–1.0034×）。独立的未插桩诊断中，1 KiB 请求的 UA2F user / system CPU 为 NFQUEUE `1.6 / 7.0 µs`、REDIRECT `1.8 / 18.8 µs`、TPROXY `1.6 / 17.6 µs`；client、origin、UA2F 合计使用约 3.4–3.7 个逻辑 CPU。后续应优先验证内核 / I/O 成本，不能仅凭 parser 微基准推断整体改善。单独的 syscall trace 只用于找线索，不作为吞吐证据；详情见 [routed profiling](docs/benchmarks/2026-09-30/routed-profile-summary.md)。不同 runner 的绝对吞吐不作横向比较。

### 可选空 ACK 路径：内核 / I/O 实测（2026-09-30）

基线 `f7965c1` 和候选 `be6cd43` 均包含上述用户态优化以及最新 master 的半关闭修复；两者生产 C 源码相同。本轮只比较是否启用空 ACK 规则，使用同一台 4 vCPU AMD EPYC 7763 runner、IPv4 / iptables 1.8.10（nf_tables）、单 NFQUEUE worker、并发 128；每种响应体 6 对相邻 AB/BA，每次 10000 warmup + 100000 请求，并穿插 DIRECT 参考。

| 响应体 | 基线 Req/s | 开启后 Req/s | 配对吞吐比中位数 | 实际入队包/请求（基线 → 开启） | CI guest 忙碌 CPU µs/请求（基线 → 开启） |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 27793 | 27746 | 1.0010×（持平） | 1.007 → 1.003 | 131.80 → 131.70 |
| 64 KiB | 16596 | 18546 | 1.1197×（+11.97%） | 3.035 → 1.003 | 228.10 → 204.75 |

Req/s 两列与配对比各自取中位数，不能直接用两列相除替代配对比。64 KiB 的 6 对吞吐均提高 9.86–14.26%；CI guest 忙碌 CPU/请求的配对中位减少 10.3%，system+irq+softirq/请求减少 16.4%，client+origin+UA2F 合计 CPU/请求减少 10.7%。这些是同机合成工作负载结果，guest 计数包含观察进程及同机工作，不能当作物理宿主或实际路由器的固定收益。1 KiB 原本几乎没有多余 ACK 入队，未测得明确收益。

初版逐条检查的规则曾测得 64 KiB +12.53%、1 KiB -2.29%；最终布局让不可能为空 ACK 的长度直接进入相同 NFQUEUE action，保留完全相同的旁路包集合和 connmark 顺序，本轮小响应负向现象未重现。两轮绝对吞吐不横向比较；负向结果也完整保留。全部四条实际正确性路径和 36 个计时样本通过；nft 仅验证正确性，没有 nft 吞吐提升声明。

[空 ACK 完整报告与可复核数据](docs/benchmarks/2026-09-30/empty-ack.md) · [本轮 CI](https://github.com/Zxilly/UA2F/actions/runs/36685191916)

### 热路径微基准（不含内核 / 网络）

另一台本地云环境：AMD EPYC 9V74、Debian 13 / Linux 6.18.44、GCC 14.2.0，固定 CPU 2；同样使用 `RelWithDebInfo`。基线 `4ff67c3` 与优化代码 `f12729b` 使用相同 harness，先验证改写字节和 IP/TCP checksum，再进行 9 对交替测量，每次至少 200 ms。下表为 IPv4 handler 的 ns/op 中位数；一个 op 是完整 workload，16 请求流水线不是单请求。

| Workload | 基线 ns/op | 优化后 ns/op | 基线 / 优化后 |
| --- | ---: | ---: | ---: |
| 普通单 UA GET | 388 | 327 | 1.18× |
| 16 个有效请求流水线 | 7296 | 2461 | 2.96× |
| 分段上传 body | 1708 | 1377 | 1.24× |
| 16 个重复 UA（压力测试） | 3760 | 1154 | 3.26× |
| 128 个重复 UA（压力测试） | 145022 | 7461 | 19.44× |

改进来自缓存 UA 替换容量、每个带 UA 的改写包只计算一次 TCP checksum，以及不再回传未改写 payload。utarray 溢出存储、inline 8 无额外 entry 分配、UA 条目分配失败后持续拒绝该流的数据包、分段 UA 和活跃上传 TTL 行为保持。未改动 parser 的对照仍出现约 3–12% 的二进制布局 / 环境差异，几个百分点的小变化不作优化结论；全部 39 个 case、702 个原始样本和增量实验均保留在报告中。

性能 workflow 仅手动触发，额外 syscall diagnostics 默认关闭；不会成为每次 PR 更新都自动执行的耗时 gate。

### 历史 UA2F / UA3F 对比（旧环境，非本轮重测）

以下数据保留自 2026-06-13 的 README（`1e7a3fc`），不可与上述不同机器、工具链和 worker 配置的数据直接比较；本轮未重新测试 UA3F。

测试对象为 UA2F 和 [UA3F](https://github.com/SunBK201/UA3F)。测试环境：WSL2 x86_64 / `Linux 6.18.33.1-microsoft-standard-WSL2` / `16` 核 / `go1.26.3 linux/amd64`；客户端在独立 network namespace 中以并发 `128`、HTTP keep-alive 通过 PREROUTING 透明代理访问 `10.250.0.1:18080` origin server。UA2F 使用 `RelWithDebInfo` 构建，UA3F 使用 `GLOBAL` rewrite mode 和 `FFF` User-Agent；两者均完成 User-Agent 改写。

> 表中 Req/s、Mbps 越高越好；延迟、CPU、内存越低越好。`UA2F / UA3F` 行为两者的比值。

#### 1 KiB 响应（50000 请求）

| 模式 | 工具 | Req/s | Mbps | 平均延迟 | P95 延迟 | CPU | RSS | 峰值内存 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DIRECT | 原始流量 | 92155 | 966 | 1.30 ms | 3.80 ms | — | — | — |
| REDIRECT | UA2F | 73515 | 771 | 1.69 ms | 4.11 ms | 224% | 2.5 MB | 3.0 MB |
| REDIRECT | UA3F | 60474 | 634 | 2.02 ms | 4.68 ms | 489% | 45.6 MB | 48.0 MB |
| REDIRECT | UA2F / UA3F | 1.22× | 1.22× | 0.84× | 0.88× | 0.46× | 0.054× | 0.063× |
| TPROXY | UA2F | 69188 | 725 | 1.79 ms | 4.39 ms | 224% | 2.5 MB | 3.1 MB |
| TPROXY | UA3F | 60260 | 632 | 2.06 ms | 4.76 ms | 471% | 46.3 MB | 46.9 MB |
| TPROXY | UA2F / UA3F | 1.15× | 1.15× | 0.87× | 0.92× | 0.48× | 0.055× | 0.067× |

#### 64 KiB 响应（100000 请求）

| 模式 | 工具 | Req/s | Mbps | 平均延迟 | P95 延迟 | CPU | RSS | 峰值内存 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DIRECT | 原始流量 | 74548 | 39256 | 1.67 ms | 4.89 ms | — | — | — |
| REDIRECT | UA2F | 55697 | 29330 | 2.24 ms | 5.56 ms | 245% | 2.5 MB | 3.0 MB |
| REDIRECT | UA3F | 54491 | 28694 | 2.29 ms | 5.55 ms | 440% | 46.3 MB | 50.1 MB |
| REDIRECT | UA2F / UA3F | 1.02× | 1.02× | 0.98× | 1.00× | 0.56× | 0.054× | 0.060× |
| TPROXY | UA2F | 61178 | 32216 | 2.04 ms | 5.10 ms | 242% | 2.5 MB | 3.0 MB |
| TPROXY | UA3F | 43040 | 22665 | 2.90 ms | 6.86 ms | 401% | 44.5 MB | 47.3 MB |
| TPROXY | UA2F / UA3F | 1.42× | 1.42× | 0.70× | 0.74× | 0.60× | 0.057× | 0.063× |

#### 历史对比的复现实验

仓库内置 benchmark 脚本会自动构建 Go client/server，并生成 Markdown/JSON 报告。将 `--body-bytes` 改为 `1024` 可复现小响应测试。

```bash
sudo python3 scripts/benchmark.py \
  --ua2f ./build/ua2f \
  --ua3f ./ref/UA3F/ua3f \
  --ua2f-modes REDIRECT,TPROXY \
  --ua3f-modes REDIRECT,TPROXY \
  --requests 100000 \
  --warmup 10000 \
  --concurrency 128 \
  --body-bytes 65536
```

## TODO

- [ ] pthread 支持，由不同线程完成入队出队
- [ ] 重写正则匹配为 parser
- [ ] 以连接为单位维护 parser 状态

## License

[GPL-3.0](./LICENSE)
