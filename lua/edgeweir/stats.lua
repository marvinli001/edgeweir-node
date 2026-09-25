-- edgeweir.stats: per-site, per-minute traffic counters.
--
-- log() runs in the log phase of the edge layer and increments counters in
-- lua_shared_dict "edgeweir_stats" under "<minute>|<site id>|<metric>".
-- drain() returns and deletes all completed minutes; the agent calls it
-- through the control API every minute and uploads the buckets with
-- ReportStats. Undrained counters expire after two hours.
local cjson = require("cjson.safe")

local _M = {}

local floor, sub = math.floor, string.sub
local TTL = 7200

local HIT = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }
local MISS = { MISS = true, EXPIRED = true }

function _M.log()
  local var = ngx.var
  local site = var.edgeweir_site
  if not site or site == "" then
    return
  end
  local dict = ngx.shared.edgeweir_stats
  local p = (floor(ngx.time() / 60) * 60) .. "|" .. site .. "|"
  dict:incr(p .. "req", 1, 0, TTL)
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
        end
      end
    end
  end
  if cjson.array_mt then
    setmetatable(list, cjson.array_mt)
  end
  return list
end

return _M
