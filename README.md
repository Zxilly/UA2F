# UA2F

**当前 git HEAD 是一个高度实验性版本，请查找 commit 以获得可用版本**

暂时来说，懒得写 README，请先参照 [博客文章](https://learningman.top/archives/304) 完成操作

如果遇到了任何问题，欢迎提出 Issues，但是更欢迎直接提交 Pull Request

## TODO

- [ ] pthread 支持，由不同线程完成入队出队
- [ ] 修复偶现的非法内存访问，定位错误是一个麻烦的问题
- [ ] 配合 CONNMARK，不再修改已被判定为非 http 的 tcp 连接，期望减少 80% 以上的负载
- [ ] 期望对于 mips 硬件优化，减少内存读写

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

偶发内存非法读取
```log
[102874.363012] do_page_fault(): sending SIGSEGV to ua2f for invalid read access from 46464647
[102874.371609] epc = 004013b7 in ua2f[400000+2000]
[102874.376383] ra  = 004013b3 in ua2f[400000+2000]
```
