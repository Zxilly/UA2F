![UA2F](https://socialify.git.ci/Zxilly/UA2F/image?description=1&descriptionEditable=Change%20User-agent%20to%20F-words%20on%20OpenWRT%20router.&font=Inter&language=1&pattern=Plus&stargazers=1&theme=Light)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZxilly%2FUA2F.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FZxilly%2FUA2F?ref=badge_shield)

暂时来说，懒得写 README，请先参照 [博客文章](https://learningman.top/archives/304) 完成操作

如果遇到了任何问题，欢迎提出 Issues，但是更欢迎直接提交 Pull Request

> 由于新加入的 CONNMARK 影响，编译内核时需要添加 `NETFILTER_NETLINK_GLUE_CT` flag

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

## TODO

- [ ] pthread 支持，由不同线程完成入队出队
- [ ] 清除 TCP Header 中的 timestamp，有论文认为这可以被用来识别 NAT 后的多设备，劫持 NTP 服务器并不一定有效


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZxilly%2FUA2F.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FZxilly%2FUA2F?ref=badge_large)
