-- Each site's dictionary is reserved by the rendered nginx configuration.
-- Ordinary rule updates share counters across workers without a reload.
local M = {}

function M.dict_name(site_id)
  return "edgeweir_rate_" .. (site_id:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

-- passed lets a request through uncounted: a full partition never evicts
-- counters and must not turn new visitors away. Logged once a minute per
-- site with the total since nginx started.
local function passed(site_id)
  local logs = ngx.shared.edgeweir_policy_logs
  if not logs then return end
  local total = logs:incr("rate-full-n:" .. site_id, 1, 0)
  if logs:safe_add("rate-full:" .. site_id, true, 60) then
    ngx.log(ngx.WARN, "edgeweir: rate limit partition full, requests passed uncounted site=",
      site_id, " total=", total or "?", "; raise --rate-limit-dict-kb")
  end
end

function M.check(dict, site_id, namespace, rule_id, action, value)
  if not dict then
    -- The rendered configuration has no partition for the site.
    return { status = 503, code = "rate-limit-unavailable", message = "rate limit unavailable" }
  end
  local window = action.window_seconds
  -- A 16-byte digest and the window number (ids never contain ":") keep an
  -- entry in nginx's 128-byte slab class.
  local key = ngx.md5_bin(namespace .. ":" .. rule_id .. ":" .. tostring(value or ""))
    .. tostring(math.floor(ngx.now() / window))
  local ok, err = dict:safe_add(key, 0, window + 1)
  if not ok and err ~= "exists" then return passed(site_id) end
  local count = dict:incr(key, 1)
  if not count then return passed(site_id) end
  if count > action.limit then return { status = action.status_code or 429, retry_after = window, count = count } end
end

return M
