-- hello-header: an example node extension (docs/reference/extensions.md).
-- Adds a greeting response header, a rule field ext.hello-header.greeted,
-- a log field, a counter, an endpoint and (optionally) a script in HTML.
local util = require("util")

local M = {}

function M.init(ew)
  ew.shared("state"):set("started", ew.now())
end

function M.access(ew)
  if ew.site_config.fail then
    error("hello-header: failing on purpose")
  end
  local greeted = ew.req.header("x-no-greeting") == nil
  ew.field("greeted", greeted)
  ew.ctx.greeted = greeted
  if ew.site_config.deny_path ~= "" and ew.req.path() == ew.site_config.deny_path then
    return ew.deny(403)
  end
end

function M.header_filter(ew)
  if not ew.ctx.greeted then
    return
  end
  ew.resp.set_header(ew.site_config.header, util.greeting(ew.global_config.greeting))
  if ew.site_config.inject then
    ew.html.script({ src = "/.edgeweir/ext/hello-header/assets/hello.js", defer = true })
  end
end

function M.log(ew)
  if ew.ctx.greeted then
    ew.log_field("greeting", ew.global_config.greeting)
    ew.count("greeted")
  end
end

function M.endpoint(ew, path)
  return ew.respond(200, "pong\n", { ["Content-Type"] = "text/plain" })
end

return M
