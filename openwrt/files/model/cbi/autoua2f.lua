m = Map("autoua2f", translate("UA2F"))
m.description = translate([[
        <span style="font-family: '微软雅黑'; color: red">该插件并非适合所有类型的检测！！！有网络的情况时下方会显示你的UA，如果两个UA不一样就说明成功了</span>
    ]])
    
m:section(SimpleSection).template = "ua2f/ua2f"
m:section(SimpleSection).template = "ua2f/ua2f_A"

e = m:section(TypedSection, "autoua2f", translate(""))
e.addremove = false
e.anonymous = true

o1 = e:option(Flag, "enabled", translate("启用/开机自启"))
o1.rmempty = false

o2 = e:option(Flag, "handle_fw", translate("自动配置防火墙"), translate("是否自动添加防火墙规则"))
o2.rmempty = false


o3 = e:option(Flag, "handle_intranet", translate("处理内网流量"), translate("是否处理内网流量，如果你的路由器是在内网中，且你想要处理内网中的流量，那么请启用这一选项"))
o3.rmempty = false

o4 = e:option(Flag, "handle_tls", translate("处理443端口流量"), translate("通常来说，流经 443 端口的流量是加密的，因此无需处理"))
o4.rmempty = false

o5 = e:option(Flag, "handle_mmtls", translate("处理微信流量"), translate("微信的流量通常是加密的，因此无需处理，这一规则在启用 nftables 时无效"))
o5.rmempty = false

o6 = e:option(Value, "Custom_UA", translate("处理微信流量"), translate("自定义用户代理字符串，长度不足则填充空格，过长则截取与原来长度相同的子串"))
o6.default = "Mozilla/5.0 (Window NT 10.0;Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/555.66"

local apply = luci.http.formvalue("cbi.apply")
if apply then
	io.popen("/etc/init.d/autoua2f start")
end

return m
