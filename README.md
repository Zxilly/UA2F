![UA2F](https://socialify.git.ci/Zxilly/UA2F/image?description=1&descriptionEditable=Change%20User-agent%20to%20F-words%20on%20OpenWRT%20router.&font=Inter&language=1&pattern=Plus&stargazers=1&theme=Light)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZxilly%2FUA2F.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FZxilly%2FUA2F?ref=badge_shield)

~~**当前 git HEAD 是一个高度实验性版本，请查找 commit 以获得可用版本**~~

**我相信当前版本已经足够可用，但是仍然有很多改进等待完成**

暂时来说，懒得写 README，请先参照 [博客文章](https://learningman.top/archives/304) 完成操作

如果遇到了任何问题，欢迎提出 Issues，但是更欢迎直接提交 Pull Request

> 由于新加入的 CONNMARK 影响，编译内核时需要添加 `NETFILTER_NETLINK_GLUE_CT` flag，否则会出现 `mnl_cb_run:Not supported` 错误

> 由于新加入的 ipset 影响，需要确保你的内核支持 `hash:ip,port` 的 ipset 类型

# uci command

```bash
# Enable the daemon
uci set ua2f.enabled.enabled=1
# At your option set fw rules
uci set ua2f.firewall.handle_fw=1
uci set ua2f.firewall.handle_tls=1
uci set ua2f.firewall.handle_mmtls=1
uci set ua2f.firewall.handle_intranet=1

# Apply your modifications
uci commit ua2f

service ua2f enable
# Start the daemon
service ua2f start
```

# Manual configure
## ipset command

请确保添加此语句至开机自启
```bash
ipset create nohttp hash:ip,port hashsize 16384 timeout 300
```
`UA2F` 运行时依赖名称为 `nohttp`，类型为 `hash:ip,port` 的 ipset

## iptables rules
```shell
iptables -t mangle -N ua2f
iptables -t mangle -A ua2f -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A ua2f -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A ua2f -d 192.168.0.0/16 -j RETURN # 不处理流向保留地址的包
iptables -t mangle -A ua2f -p tcp --dport 443 -j RETURN
iptables -t mangle -A ua2f -p tcp --dport 22 -j RETURN # 不处理 SSH 和 https
iptables -t mangle -A ua2f -p tcp --dport 80 -j CONNMARK --set-mark 44
iptables -t mangle -A ua2f -m connmark --mark 43 -j RETURN # 不处理标记为非 http 的流 (实验性)
iptables -t mangle -A ua2f -m set --set nohttp dst,dst -j RETURN
iptables -t mangle -A ua2f -p tcp --dport 80 -m string --string "/mmtls/" --algo bm -j RETURN # 不处理微信的 mmtls
iptables -t mangle -A ua2f -j NFQUEUE --queue-num 10010

iptables -t mangle -A FORWARD -p tcp -m conntrack --ctdir ORIGINAL -j ua2f
```

## TODO

- [x] 灾难恢复
- [ ] pthread 支持，由不同线程完成入队出队
- [x] 修复偶现的非法内存访问，定位错误是一个麻烦的问题 (疑似修复，继续观察)
- [x] 配合 CONNMARK 与 ipset，不再修改已被判定为非 http 的 tcp 连接，期望减少 80% 以上的负载 (高度实验性实现)
- [ ] 清除 TCP Header 中的 timestamp，有论文认为这可以被用来识别 NAT 后的多设备，劫持 NTP 服务器并不一定有效


## Helpful Log
http 头包占比观察
```log
Sat Dec  5 23:57:23 2020 user.notice : UA2F try to start daemon parent at [10331], parent process will suicide.
Sat Dec  5 23:57:23 2020 user.notice : UA2F parent daemon start at [10331].
Sat Dec  5 23:57:23 2020 user.notice : UA2F parent daemon set sid at [10331].
Sat Dec  5 23:57:23 2020 user.notice : UA2F true daemon will start at [10332], daemon parent suicide.
Sat Dec  5 23:57:23 2020 user.notice : UA2F true daemon start at [10332].
Sat Dec  5 23:57:23 2020 syslog.notice UA2F[10332]: UA2F has inited successful.
Sat Dec  5 23:57:47 2020 syslog.info UA2F[10332]: UA2F has handled 8 http packet and 243 tcp packet in 24s
Sat Dec  5 23:57:47 2020 syslog.info UA2F[10332]: UA2F has handled 16 http packet and 356 tcp packet in 24s
Sat Dec  5 23:57:47 2020 syslog.info UA2F[10332]: UA2F has handled 32 http packet and 440 tcp packet in 24s
Sat Dec  5 23:57:48 2020 syslog.info UA2F[10332]: UA2F has handled 64 http packet and 609 tcp packet in 25s
Sat Dec  5 23:57:49 2020 syslog.info UA2F[10332]: UA2F has handled 128 http packet and 1287 tcp packet in 26s
Sat Dec  5 23:58:58 2020 syslog.info UA2F[10332]: UA2F has handled 256 http packet and 6052 tcp packet in 95s
Sat Dec  5 23:59:01 2020 syslog.info UA2F[10332]: UA2F has handled 512 http packet and 9003 tcp packet in 98s
Sat Dec  5 23:59:39 2020 syslog.info UA2F[10332]: UA2F has handled 1024 http packet and 13764 tcp packet in 136s
Sun Dec  6 00:08:21 2020 syslog.info UA2F[10332]: UA2F has handled 2048 http packet and 48231 tcp packet in 658s
Sun Dec  6 00:31:57 2020 syslog.info UA2F[10332]: UA2F has handled 4096 http packet and 163337 tcp packet in 2074s
Sun Dec  6 11:31:39 2020 syslog.info UA2F[10332]: UA2F has handled 8192 http packet and 588216 tcp packet in 41656s
```

当前运行时间
```log
Fri Jan  1 15:10:09 2021 syslog.notice UA2F[5219]: UA2F has inited successful.
Fri Jan  1 15:11:18 2021 syslog.info UA2F[5219]: UA2F has handled 8 http packet, 0 http packet without ua and 107 tcp packet in 1 minutes and 9 seconds
Fri Jan  1 15:12:23 2021 syslog.info UA2F[5219]: UA2F has handled 16 http packet, 4 http packet without ua and 370 tcp packet in 2 minutes and 14 seconds
Fri Jan  1 15:13:52 2021 syslog.info UA2F[5219]: UA2F has handled 32 http packet, 4 http packet without ua and 722 tcp packet in 3 minutes and 43 seconds
Fri Jan  1 15:13:57 2021 syslog.info UA2F[5219]: UA2F has handled 64 http packet, 4 http packet without ua and 850 tcp packet in 3 minutes and 48 seconds
Fri Jan  1 15:14:17 2021 syslog.info UA2F[5219]: UA2F has handled 128 http packet, 4 http packet without ua and 1243 tcp packet in 4 minutes and 8 seconds
Fri Jan  1 15:22:35 2021 syslog.info UA2F[5219]: UA2F has handled 256 http packet, 12 http packet without ua and 2565 tcp packet in 12 minutes and 26 seconds
Fri Jan  1 15:42:24 2021 syslog.info UA2F[5219]: UA2F has handled 512 http packet, 30 http packet without ua and 6491 tcp packet in 32 minutes and 15 seconds
Fri Jan  1 16:29:59 2021 syslog.info UA2F[5219]: UA2F has handled 1024 http packet, 68 http packet without ua and 19188 tcp packet in 1 hours, 19 minutes and 50 seconds
Fri Jan  1 18:06:01 2021 syslog.info UA2F[5219]: UA2F has handled 2048 http packet, 173 http packet without ua and 36951 tcp packet in 2 hours, 55 minutes and 52 seconds
Fri Jan  1 21:09:36 2021 syslog.info UA2F[5219]: UA2F has handled 4096 http packet, 849 http packet without ua and 137599 tcp packet in 5 hours, 59 minutes and 27 seconds
Sat Jan  2 01:39:39 2021 syslog.info UA2F[5219]: UA2F has handled 8192 http packet, 1747 http packet without ua and 249561 tcp packet in 10 hours, 29 minutes and 30 seconds
Sat Jan  2 15:06:43 2021 syslog.info UA2F[5219]: UA2F has handled 16384 http packet, 2844 http packet without ua and 551953 tcp packet in 23 hours, 56 minutes and 34 seconds
Sun Jan  3 10:22:28 2021 syslog.info UA2F[5219]: UA2F has handled 32768 http packet, 5047 http packet without ua and 1919845 tcp packet in 1 days, 19 hours, 12 minutes and 19 seconds
Mon Jan  4 13:25:04 2021 syslog.info UA2F[5219]: UA2F has handled 65536 http packet, 8435 http packet without ua and 3973193 tcp packet in 2 days, 22 hours, 14 minutes and 55 seconds
```

```
Sat Mar 13 14:26:48 2021 user.notice : Try to start UA2F processor at [24049].
Sat Mar 13 14:26:48 2021 user.notice : UA2F processor start at [24049].
Sat Mar 13 14:26:48 2021 syslog.notice UA2F[24049]: Pipset inited.
Sat Mar 13 14:26:48 2021 syslog.notice UA2F[24049]: UA2F has inited successful.
Sat Mar 13 14:26:51 2021 syslog.info UA2F[24049]: UA2F has handled 8 http, 0 http 1.0, 0 noua http, 58 tcp. Set 0 mark and 0 nohttp mark in 3 seconds
Sat Mar 13 14:26:57 2021 syslog.info UA2F[24049]: UA2F has handled 16 http, 0 http 1.0, 1 noua http, 140 tcp. Set 0 mark and 1 nohttp mark in 9 seconds
Sat Mar 13 14:27:23 2021 syslog.info UA2F[24049]: UA2F has handled 32 http, 0 http 1.0, 3 noua http, 1286 tcp. Set 2 mark and 3 nohttp mark in 35 seconds
Sat Mar 13 14:27:35 2021 syslog.info UA2F[24049]: UA2F has handled 64 http, 0 http 1.0, 3 noua http, 2042 tcp. Set 4 mark and 3 nohttp mark in 47 seconds
Sat Mar 13 14:28:55 2021 syslog.info UA2F[24049]: UA2F has handled 128 http, 0 http 1.0, 5 noua http, 7052 tcp. Set 13 mark and 8 nohttp mark in 2 minutes and 7 seconds
Sat Mar 13 14:33:45 2021 syslog.info UA2F[24049]: UA2F has handled 256 http, 2 http 1.0, 39 noua http, 12965 tcp. Set 19 mark and 25 nohttp mark in 6 minutes and 57 seconds
Sat Mar 13 14:50:22 2021 syslog.info UA2F[24049]: UA2F has handled 512 http, 4 http 1.0, 82 noua http, 25230 tcp. Set 58 mark and 45 nohttp mark in 23 minutes and 34 seconds
Sat Mar 13 15:05:10 2021 syslog.info UA2F[24049]: UA2F has handled 1024 http, 9 http 1.0, 154 noua http, 76718 tcp. Set 72 mark and 69 nohttp mark in 38 minutes and 22 seconds
Sat Mar 13 15:40:06 2021 syslog.info UA2F[24049]: UA2F has handled 2048 http, 218 http 1.0, 630 noua http, 118648 tcp. Set 151 mark and 162 nohttp mark in 1 hours, 13 minutes and 18 seconds
Sat Mar 13 16:56:16 2021 syslog.info UA2F[24049]: UA2F has handled 4096 http, 481 http 1.0, 1012 noua http, 222476 tcp. Set 368 mark and 291 nohttp mark in 2 hours, 29 minutes and 28 seconds
Sat Mar 13 21:49:04 2021 syslog.info UA2F[24049]: UA2F has handled 8192 http, 610 http 1.0, 1659 noua http, 355347 tcp. Set 673 mark and 789 nohttp mark in 7 hours, 22 minutes and 16 seconds
Sun Mar 14 00:46:13 2021 syslog.info UA2F[24049]: UA2F has handled 16384 http, 2260 http 1.0, 3479 noua http, 888912 tcp. Set 863 mark and 1052 nohttp mark in 10 hours, 19 minutes and 25 seconds
Sun Mar 14 02:39:43 2021 syslog.info UA2F[24049]: UA2F has handled 24576 http, 4570 http 1.0, 5854 noua http, 1288440 tcp. Set 1121 mark and 1121 nohttp mark in 12 hours, 12 minutes and 55 seconds
Sun Mar 14 09:38:22 2021 syslog.info UA2F[24049]: UA2F has handled 32768 http, 5663 http 1.0, 7167 noua http, 1550242 tcp. Set 1231 mark and 1306 nohttp mark in 19 hours, 11 minutes and 34 seconds
Sun Mar 14 09:45:30 2021 syslog.info UA2F[24049]: UA2F has handled 40960 http, 5665 http 1.0, 7170 noua http, 1623063 tcp. Set 1236 mark and 1317 nohttp mark in 19 hours, 18 minutes and 42 seconds
Sun Mar 14 11:23:40 2021 syslog.info UA2F[24049]: UA2F has handled 49152 http, 8001 http 1.0, 10014 noua http, 2138665 tcp. Set 1424 mark and 1585 nohttp mark in 20 hours, 56 minutes and 52 seconds
Sun Mar 14 18:50:18 2021 syslog.info UA2F[24049]: UA2F has handled 57344 http, 8632 http 1.0, 11863 noua http, 2705798 tcp. Set 1668 mark and 2281 nohttp mark in 1 days, 4 hours, 23 minutes and 30 seconds
Mon Mar 15 00:41:03 2021 syslog.info UA2F[24049]: UA2F has handled 65536 http, 8686 http 1.0, 12738 noua http, 3194659 tcp. Set 1830 mark and 2941 nohttp mark in 1 days, 10 hours, 14 minutes and 15 seconds
Mon Mar 15 11:39:34 2021 syslog.info UA2F[24049]: UA2F has handled 73728 http, 8691 http 1.0, 13282 noua http, 3360247 tcp. Set 1867 mark and 4219 nohttp mark in 1 days, 21 hours, 12 minutes and 46 seconds
```


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZxilly%2FUA2F.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FZxilly%2FUA2F?ref=badge_large)
