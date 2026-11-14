local M = {}

local function send(ew)
  local ok, reason = ew.early_hints({
    "</static/example.css>; rel=preload; as=style",
    "<https://static.example.org>; rel=preconnect",
  })
  ew.ctx.result = ok and "true" or reason
end

function M.access(ew)
  if ew.site_config.phase == "access" or ew.site_config.phase == "both" then send(ew) end
end

function M.access_late(ew)
  if ew.site_config.phase ~= "access" then send(ew) end
  if ew.site_config.deny then return ew.deny(403) end
end

function M.header_filter(ew)
  ew.resp.set_header("X-Info-" .. ew.id, ew.ctx.result or "none")
end

return M
