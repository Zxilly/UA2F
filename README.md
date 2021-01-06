# UA2F

~~**当前 git HEAD 是一个高度实验性版本，请查找 commit 以获得可用版本**~~

**我相信当前版本已经足够可用，但是仍然有很多改进等待完成**

暂时来说，懒得写 README，请先参照 [博客文章](https://learningman.top/archives/304) 完成操作

如果遇到了任何问题，欢迎提出 Issues，但是更欢迎直接提交 Pull Request

> 由于新加入的 CONNMARK 影响，编译内核时需要添加 `NETFILTER_NETLINK_GLUE_CT` flag，否则会出现 `mnl_cb_run:Not supported` 错误

# iptables rules
```shell
iptables -t mangle -N ua2f
iptables -t mangle -A ua2f -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A ua2f -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A ua2f -d 192.168.0.0/16 -j RETURN # 不处理流向保留地址的包
iptables -t mangle -A ua2f -p tcp --dport 443 -j RETURN
iptables -t mangle -A ua2f -p tcp --dport 22 -j RETURN # 不处理 SSH 和 https
iptables -t mangle -A ua2f -p tcp --dport 80 -j CONNMARK --set-mark 24
iptables -t mangle -A ua2f -m connmark --mark 23 -j RETURN # 不处理标记为非 http 的流 (实验性)
iptables -t mangle -A ua2f -j NFQUEUE --queue-num 10010

iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctdir ORIGINAL -j ua2f # 只处理出向流量
```

## TODO

- [x] 灾难恢复
- [ ] pthread 支持，由不同线程完成入队出队
- [x] 修复偶现的非法内存访问，定位错误是一个麻烦的问题 (疑似修复，继续观察)
- [ ] 期望对于 mips 硬件优化，减少内存读写
- [x] 配合 CONNMARK，不再修改已被判定为非 http 的 tcp 连接，期望减少 80% 以上的负载 (高度实验性实现)


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

debug断点
> 在断点 9 和 16 会出现内存非法访问，暂时做重启处理