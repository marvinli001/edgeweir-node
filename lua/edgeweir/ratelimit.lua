-- Each site's dictionary is reserved by the rendered nginx configuration.
-- Ordinary rule updates share counters across workers without a reload.
local M = {}

function M.dict_name(site_id)
  return "edgeweir_rate_" .. (site_id:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

function M.check(dict, namespace, rule_id, action, value)
  if not dict then return { status = 503 } end
  local window = action.window_seconds
  local key = "rate:" .. namespace .. ":" .. rule_id .. ":"
    .. tostring(math.floor(ngx.now() / window)) .. ":" .. ngx.md5(tostring(value or ""))
  local ok, err = dict:safe_add(key, 0, window + 1)
  if not ok and err ~= "exists" then return { status = 503 } end
  local count = dict:incr(key, 1)
  if not count then return { status = 503 } end
  if count > action.limit then return { status = action.status_code or 429, retry_after = window } end
end

return M
