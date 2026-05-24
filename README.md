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
| `custom_ua` | 空 | 自定义 User-Agent 替换内容。UA2F 不改变包长度，长度不足会补空格，过长会截断。 |
| `disable_connmark` | `0` | 禁用 Conntrack 标记和缓存。会降低性能，但可避免和其他修改 Connmark 的程序冲突。 |
| `max_http_sessions` | `0` | HTTP parser session 上限，`0` 表示不限制。 |
| `session_ttl` | `300` | HTTP session 空闲过期时间，单位秒。 |

```bash
uci set ua2f.main.mode='TPROXY'
uci set ua2f.main.listen_port='10010'
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

```bash
uci set ua2f.firewall.handle_fw='1'
uci set ua2f.firewall.handle_tls='0'
uci set ua2f.firewall.handle_intranet='1'
uci set ua2f.firewall.handle_mmtls='0'
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

## TODO

- [ ] pthread 支持，由不同线程完成入队出队
- [ ] 重写正则匹配为 parser
- [ ] 以连接为单位维护 parser 状态

## License

[GPL-3.0](./LICENSE)
