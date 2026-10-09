-- Sampled request diagnostics. Never collect query strings, headers or bodies.
-- The site's log_sample_rate (basis points) applies unless a config rule set
-- one for the request. Log rules with access_log (proto v0.29.0, feature
-- waf-v2) ask for a line whatever the rate: the line names them (rule_ids,
-- at most 8), and a line written only because of them says sample_rate
-- 10000; at most MAX_FORCED such lines per site and second on this node
-- (counted in edgeweir_logs), the others only as sampled.
local json = require("cjson.safe")
local M = {}
local MAX_PENDING = 2000
M.MAX_FORCED = 100
local function clean(value, limit)
  return string.sub(tostring(value or ""):gsub("[%z\1-\31\127]", ""), 1, limit)
end
-- log(waf_ids, waf_blocked): the CRS rules that matched (at most 16) and
-- whether CRS blocked the request, for requests of CRS sites.
function M.log(waf_ids, waf_blocked)
  if ngx.is_subrequest then return end
  local ctx = ngx.ctx
  local site = ctx.edgeweir_site
  if not site then return end
  -- Config rules may set the rate for a request (basis points).
  local policy = ctx.edgeweir_policy
  local rate = policy and policy.log_sample_rate or tonumber(site.log_sample_rate) or 0
  local rules = policy and policy.log_rules
  if rules and #rules == 0 then rules = nil end
  local dict = ngx.shared.edgeweir_logs
  local sampled = false
  if rate and rate > 0 then
    local id = ngx.var.request_id or tostring(ngx.now()) .. tostring(ngx.worker.pid())
    sampled = ngx.crc32_short(id) % 10000 < rate
  end
  if not sampled then
    if not rules then return end
    local forced = dict:incr("forced|" .. site.id .. "|" .. math.floor(ngx.now()), 1, 0, 2)
    if not forced or forced > M.MAX_FORCED then return end
    rate = 10000
  end
  local n = dict:llen("pending") or 0
  if n >= MAX_PENDING then dict:incr("dropped", 1, 0); return end
  local var = ngx.var
  local raw = json.encode({
    time = ngx.now(), site_id = site.id, client_ip = clean(var.remote_addr, 64),
    method = clean(var.request_method, 32), host = clean(var.host, 253),
    path = clean((ngx.ctx.edgeweir_original_path or var.uri or ""):match("^[^?#]*"), 2048),
    status = ngx.status, bytes_sent = tonumber(var.bytes_sent) or 0,
    duration_ms = math.min(86400000, math.floor((tonumber(var.request_time) or 0) * 1000)),
    cache_status = clean(var.upstream_cache_status, 32), sample_rate = rate,
    ja4 = site.protection and site.protection.log_ja4 and clean(require("edgeweir.ja4").value(), 64) or nil,
    waf_rule_ids = waf_ids and #waf_ids > 0 and setmetatable(waf_ids, json.array_mt) or nil,
    waf_blocked = waf_blocked or nil,
    -- The X-Request-Id the node answered with (also on error pages).
    request_id = clean(var.edgeweir_request_id, 128),
    rule_ids = rules and setmetatable({ unpack(rules, 1, math.min(#rules, 8)) }, json.array_mt) or nil,
  })
  if not raw or not dict:rpush("pending", raw) then dict:incr("dropped", 1, 0) end
end
function M.drain()
  local dict, entries = ngx.shared.edgeweir_logs, {}
  for _ = 1, 1000 do
    local raw = dict:lpop("pending")
    if not raw then break end
    local record = json.decode(raw)
    if record then entries[#entries+1] = record end
  end
  if json.array_mt then setmetatable(entries, json.array_mt) end
  return entries
end
return M
