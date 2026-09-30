-- edgeweir.stats: per-site, per-minute traffic counters.
--
-- log() runs in the log phase of the edge layer and increments counters in
-- lua_shared_dict "edgeweir_stats" under "<minute>|<site id>|<metric>".
-- drain() returns and deletes all completed minutes; the agent calls it
-- through the control API every minute and uploads the buckets with
-- ReportStats. Undrained counters expire after two hours.
local cjson = require("cjson.safe")
local top = require("edgeweir.topstats")

local _M = {}

local floor, sub = math.floor, string.sub
local TTL = 7200

local HIT = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }
local MISS = { MISS = true, EXPIRED = true }

-- MAX_WAF_RULES bounds the CRS rules of a site's minute (heaviest first).
_M.MAX_WAF_RULES = 20

-- log(waf_location): waf_location in the edge layer's CRS locations, where
-- the request context comes back first and matched CRS rules are counted.
function _M.log(waf_location)
  local waf_ids, waf_blocked
  if waf_location then
    local waf = require("edgeweir.waf")
    waf.restore()
    waf_ids, waf_blocked = waf.result()
  end
  local var = ngx.var
  local site = var.edgeweir_site
  if not site or site == "" then
    return
  end
  require("edgeweir.accesslogs").log(waf_ids, waf_blocked)
  local ctx_site = ngx.ctx.edgeweir_site
  if ctx_site and ctx_site._cc then require("edgeweir.cc").log(ctx_site) end
  local dict = ngx.shared.edgeweir_stats
  local p = (floor(ngx.time() / 60) * 60) .. "|" .. site .. "|"
  dict:incr(p .. "req", 1, 0, TTL)
  top.log(site, floor(ngx.time()/60)*60, ngx.ctx.edgeweir_original_path or var.uri, var.remote_addr)
  local out = tonumber(var.bytes_sent)
  if out and out > 0 then
    dict:incr(p .. "out", out, 0, TTL)
  end
  local inb = tonumber(var.request_length)
  if inb and inb > 0 then
    dict:incr(p .. "in", inb, 0, TTL)
  end
  local cs = var.upstream_cache_status
  if cs then
    if HIT[cs] then
      dict:incr(p .. "hit", 1, 0, TTL)
    elseif MISS[cs] then
      dict:incr(p .. "miss", 1, 0, TTL)
    end
  end
  dict:incr(p .. "s" .. ngx.status, 1, 0, TTL)
  if waf_ids then
    for i = 1, #waf_ids do
      dict:incr(p .. "w" .. waf_ids[i], 1, 0, TTL)
    end
  end
end

-- drain collects completed minutes (strictly before the minute containing
-- now) into buckets and deletes their counters.
function _M.drain(now)
  local dict = ngx.shared.edgeweir_stats
  local current = floor((now or ngx.time()) / 60) * 60
  local keys = dict:get_keys(0)
  local buckets, list = {}, {}
  for i = 1, #keys do
    local k = keys[i]
    local m, rest = k:match("^(%d+)|(.+)$")
    local minute = tonumber(m)
    if minute and minute < current then
      local site, metric = rest:match("^(.*)|([^|]+)$")
      local v = dict:get(k)
      dict:delete(k)
      if site and v then
        local bk = m .. "|" .. site
        local b = buckets[bk]
        if not b then
          b = {
            minute = minute, site_id = site, requests = 0, bytes_sent = 0, bytes_received = 0,
            cache_hits = 0, cache_misses = 0, status_codes = {},
          }
          buckets[bk] = b
          list[#list + 1] = b
        end
        if metric == "req" then
          b.requests = b.requests + v
        elseif metric == "out" then
          b.bytes_sent = b.bytes_sent + v
        elseif metric == "in" then
          b.bytes_received = b.bytes_received + v
        elseif metric == "hit" then
          b.cache_hits = b.cache_hits + v
        elseif metric == "miss" then
          b.cache_misses = b.cache_misses + v
        elseif sub(metric, 1, 1) == "s" then
          local code = sub(metric, 2)
          b.status_codes[code] = (b.status_codes[code] or 0) + v
        elseif sub(metric, 1, 1) == "w" then
          local id = sub(metric, 2)
          b.waf_rules = b.waf_rules or {}
          b.waf_rules[id] = (b.waf_rules[id] or 0) + v
        end
      end
    end
  end
  for _, record in ipairs(top.drain(now)) do
    local key = tostring(record.minute) .. "|" .. record.site_id
    local bucket = buckets[key]
    if not bucket then
      bucket = { minute=record.minute, site_id=record.site_id, requests=0, bytes_sent=0, bytes_received=0, cache_hits=0, cache_misses=0, status_codes={} }
      buckets[key] = bucket; list[#list+1] = bucket
    end
    bucket.top_urls = bucket.top_urls or {}; bucket.top_ips = bucket.top_ips or {}
    for value, count in pairs(record.urls or {}) do bucket.top_urls[value] = (bucket.top_urls[value] or 0) + count end
    for value, count in pairs(record.ips or {}) do bucket.top_ips[value] = (bucket.top_ips[value] or 0) + count end
  end
  for _, bucket in ipairs(list) do
    for _, field in ipairs({"top_urls", "top_ips", "waf_rules"}) do
      if field ~= "waf_rules" or bucket[field] then
        local limit = field == "waf_rules" and _M.MAX_WAF_RULES or 50
        local sorted = {}; for value,count in pairs(bucket[field] or {}) do sorted[#sorted+1] = {value=value,count=count} end
        table.sort(sorted,function(a,b) return a.count>b.count or (a.count==b.count and a.value<b.value) end)
        local selected = {}; for i=1,math.min(limit,#sorted) do selected[sorted[i].value] = sorted[i].count end
        bucket[field] = selected
      end
    end
  end
  if cjson.array_mt then
    setmetatable(list, cjson.array_mt)
  end
  return list
end

return _M
