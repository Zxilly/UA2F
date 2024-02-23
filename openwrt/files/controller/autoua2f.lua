module("luci.controller.autoua2f", package.seeall)

function index()
    entry({"admin", "services", "autoua2f"}, cbi("autoua2f"), _("UA2F配置"), 94)
    entry({"admin", "services", "autoua2f", "status"}, call("act_status")).leaf = true

end

function act_status()
	local e = {}
	e.running = luci.sys.call("pgrep ua2f >/dev/null") == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end


