-- Sampled request diagnostics. Never collect query strings, headers or bodies.
local json = require("cjson.safe")
local M = {}
local MAX_PENDING = 2000
local function clean(value, limit)
  return string.sub(tostring(value or ""):gsub("[%z\1-\31\127]", ""), 1, limit)
end
-- log(waf_ids, waf_blocked): the CRS rules that matched (at most 16) and
-- whether CRS blocked the request, for requests of CRS sites.
function M.log(waf_ids, waf_blocked)
  if ngx.is_subrequest then return end
  local site = ngx.ctx.edgeweir_site
  local rate = site and tonumber(site.log_sample_rate) or 0
  if not rate or rate <= 0 then return end
  local id = ngx.var.request_id or tostring(ngx.now()) .. tostring(ngx.worker.pid())
  if ngx.crc32_short(id) % 10000 >= rate then return end
  local dict = ngx.shared.edgeweir_logs
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
