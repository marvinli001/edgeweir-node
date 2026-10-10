-- edgeweir.stats: per-site, per-minute traffic counters.
--
-- log() runs in the log phase of the edge layer and increments counters in
-- lua_shared_dict "edgeweir_stats" under "<minute>|<site id>|<metric>"
-- (not for the agent's prefetches on the local listeners), and counts the
-- request's URL, client address and dimensions in the worker's minute
-- summary (edgeweir.topstats): country and network from the access
-- phase's GeoIP record (or the worker's cache), referring host, user agent
-- classes (edgeweir.uaclass), HTTP and TLS versions and block reason
-- (edgeweir.reasons). Requests refused with a reason before the site was
-- set (client certificates, bans, maintenance) count for that site;
-- requests of no site, SNI mismatches and PURGE requests count for none
-- (the live view still sees them, edgeweir.tap). logged() counts the
-- matches of rules with the log action (edgeweir.policy, access phase).
-- drain() returns and deletes all completed minutes; the agent calls it
-- through the control API every minute and uploads the buckets with
-- ReportStats. Undrained counters expire after two hours.
local cjson = require("cjson.safe")
local top = require("edgeweir.topstats")
local reasons = require("edgeweir.reasons")
local uaclass = require("edgeweir.uaclass")
local accesslogs = require("edgeweir.accesslogs")
local access = require("edgeweir.access")
local geoip = require("edgeweir.geoip")

local _M = {}

local floor, sub = math.floor, string.sub
local TTL = 7200

local HIT = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }
local MISS = { MISS = true, EXPIRED = true }

-- MAX_WAF_RULES bounds the CRS rules of a site's minute (heaviest first).
_M.MAX_WAF_RULES = 20
-- MAX_LOGGED_RULES bounds the log rules of a site's minute (heaviest first).
_M.MAX_LOGGED_RULES = 20
-- Bounds of a site's minute dimensions (ADR-0041): countries by requests,
-- networks and referring hosts (heaviest first).
_M.MAX_COUNTRIES = 250
_M.MAX_TOP_DIMENSIONS = 50

local HTTP_KEYS, TLS_KEYS = accesslogs.HTTP_VERSIONS, accesslogs.TLS_VERSIONS

-- Known keys of the dimension maps (anything else is dropped by drain).
local function set(list)
  local out = {}
  for _, k in ipairs(list) do out[k] = true end
  return out
end
local KEYS = {
  browsers = set(uaclass.BROWSERS), operating_systems = set(uaclass.OSES), devices = set(uaclass.DEVICES),
  http_versions = set({ "1.0", "1.1", "2", "3", "other" }), tls_versions = set({ "1.2", "1.3", "none", "other" }),
  block_reasons = reasons.REASONS,
}
-- The worker summary's field of each map.
local SOURCES = { browsers = "browsers", operating_systems = "oses", devices = "devices", http_versions = "http",
  tls_versions = "tls", block_reasons = "reasons" }

-- referer_host returns the Referer's host for the statistics: a host name
-- (labels of [a-z0-9_-]) or IPv4 address of at most 253 bytes, lowercase,
-- without the port, not the request's own host; nil otherwise (IPv6
-- literals included).
function _M.referer_host(value, own)
  if type(value) == "table" then value = value[1] end
  if type(value) ~= "string" or value == "" then return nil end
  local host = access.referer_host(value)
  if not host or host == own or host:find(":", 1, true) then return nil end
  return host
end

-- dimensions returns a request's dimensions for edgeweir.topstats: geo is
-- its GeoIP record (nil: unknown), bytes the bytes sent.
function _M.dimensions(var, geo, bytes)
  local country, asn, as_name = accesslogs.geo_fields(geo)
  local ua = uaclass.classify(var.http_user_agent)
  local tls = var.ssl_protocol
  return {
    country = country, bytes = bytes, asn = asn > 0 and tostring(asn) or nil, as_name = as_name,
    referer = _M.referer_host(var.http_referer, var.host),
    browser = ua.browser, os = ua.os, device = ua.device,
    http = HTTP_KEYS[var.server_protocol] or "other",
    tls = (tls == nil or tls == "") and "none" or TLS_KEYS[tls] or "other",
    reason = (reasons.get()),
  }
end

-- geo returns the client's GeoIP record of the request: the access phase's
-- (ngx.ctx.edgeweir_geo), else the worker's cache: that lookup failed or
-- was the rules' own, or the context is new (requests nginx redirected to
-- its error page).
function _M.geo(ctx, addr)
  local geo = ctx.edgeweir_geo
  return geo or geoip.peek(addr)
end

-- logged counts a match of a rule with the log action for the site's minute
-- (metric "l<rule id>", reported as MinuteStats.logged_rules). Requests on
-- the local listeners (the agent's prefetches) are not counted.
function _M.logged(site_id, rule_id)
  if ngx.var.edgeweir_local == "1" then
    return
  end
  local minute = floor(ngx.time() / 60) * 60
  ngx.shared.edgeweir_stats:incr(minute .. "|" .. site_id .. "|l" .. rule_id, 1, 0, TTL)
end

-- auth_failed counts a request access authentication refused for the
-- site's minute (metric "a", reported as MinuteStats.auth_failures).
-- Requests on the local listeners are never checked.
function _M.auth_failed(site_id)
  if ngx.var.edgeweir_local == "1" then
    return
  end
  local minute = floor(ngx.time() / 60) * 60
  ngx.shared.edgeweir_stats:incr(minute .. "|" .. site_id .. "|a", 1, 0, TTL)
end

-- log(waf_location): waf_location in the edge layer's CRS and gRPC
-- locations and in its error page location (a request may come there from
-- either), where the request context comes back first and matched CRS
-- rules are counted.
function _M.log(waf_location)
  local waf_ids, waf_blocked
  if waf_location then
    local waf = require("edgeweir.waf")
    waf.restore()
    waf_ids, waf_blocked = waf.result()
  end
  local var = ngx.var
  -- Prefetches (the local listeners) are not traffic of the site.
  if var.edgeweir_local == "1" then
    return
  end
  local ctx = ngx.ctx
  if waf_blocked then reasons.set("crs") end
  local ctx_site = ctx.edgeweir_site
  local site = var.edgeweir_site
  if not site or site == "" then
    -- Refused with a reason before $edgeweir_site was set: the site's.
    if ctx_site and ctx.edgeweir_reason then
      site = ctx_site.id
    else
      -- The live view sees every other request (but the probes'), with
      -- the site it found (SNI mismatches, PURGE) or none.
      if not ctx.edgeweir_probe then
        accesslogs.log(nil, nil, ctx_site and ctx_site.id or "", _M.geo(ctx, var.remote_addr), true)
      end
      return
    end
  end
  local geo = _M.geo(ctx, var.remote_addr)
  accesslogs.log(waf_ids, waf_blocked, site, geo)
  if ctx_site and ctx_site._cc then require("edgeweir.cc").log(ctx_site) end
  local dict = ngx.shared.edgeweir_stats
  local minute = floor(ngx.time() / 60) * 60
  local p = minute .. "|" .. site .. "|"
  dict:incr(p .. "req", 1, 0, TTL)
  local out = tonumber(var.bytes_sent)
  top.log(site, minute, ctx.edgeweir_original_path or var.uri, var.remote_addr, _M.dimensions(var, geo, out or 0))
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

local function count(v)
  v = tonumber(v)
  if not v or v < 0 or v ~= v or v == math.huge then return 0 end
  return floor(v)
end

-- merge_dimensions adds a worker's minute summary's dimensions to the
-- site's bucket (in the fields _countries, _asns, _asn_names, _referers).
local function merge_dimensions(bucket, record)
  if type(record.countries) == "table" then
    local countries = bucket._countries or {}
    bucket._countries = countries
    for country, c in pairs(record.countries) do
      if type(country) == "string" and (country == "" or country:match("^%u%u$")) and type(c) == "table" then
        local t = countries[country] or { 0, 0 }
        t[1], t[2] = t[1] + count(c[1]), t[2] + count(c[2])
        countries[country] = t
      end
    end
  end
  for field, target in pairs({ asns = "_asns", referers = "_referers" }) do
    if type(record[field]) == "table" then
      local into = bucket[target] or {}
      bucket[target] = into
      for k, v in pairs(record[field]) do
        if type(k) == "string" then into[k] = (into[k] or 0) + count(v) end
      end
    end
  end
  if type(record.asn_names) == "table" then
    local names = bucket._asn_names or {}
    bucket._asn_names = names
    for k, v in pairs(record.asn_names) do
      if type(k) == "string" and type(v) == "string" then names[k] = v end
    end
  end
  for field, source in pairs(SOURCES) do
    local m = record[source]
    if type(m) == "table" then
      local keys, into = KEYS[field], bucket[field] or {}
      for k, v in pairs(m) do
        if keys[k] then into[k] = (into[k] or 0) + count(v) end
      end
      if next(into) then bucket[field] = into end
    end
  end
  for field, source in pairs({ challenges_issued = "ch_issued", challenges_passed = "ch_passed" }) do
    local n = count(record[source])
    if n > 0 then bucket[field] = (bucket[field] or 0) + n end
  end
end

-- heaviest returns the limit keys of counts with the most counts (ties:
-- the smaller key first), as a list.
local function heaviest(counts, limit, weight)
  local sorted = {}
  for k, v in pairs(counts) do sorted[#sorted + 1] = k end
  table.sort(sorted, function(a, b)
    local x, y = weight(counts[a]), weight(counts[b])
    return x > y or (x == y and a < b)
  end)
  local out = {}
  for i = 1, math.min(limit, #sorted) do out[i] = sorted[i] end
  return out
end

-- finish_dimensions bounds the merged dimensions of a bucket: countries
-- (at most MAX_COUNTRIES by requests) as {requests, bytes_sent}, networks
-- (the heaviest MAX_TOP_DIMENSIONS, with their names) as {requests, name},
-- referring hosts (the heaviest MAX_TOP_DIMENSIONS).
local function finish_dimensions(bucket)
  local countries = bucket._countries
  if countries then
    local out = {}
    for _, k in ipairs(heaviest(countries, _M.MAX_COUNTRIES, function(c) return c[1] end)) do
      out[k] = { requests = countries[k][1], bytes_sent = countries[k][2] }
    end
    if next(out) then bucket.countries = out end
  end
  local asns = bucket._asns
  if asns then
    local names, out = bucket._asn_names or {}, {}
    for _, k in ipairs(heaviest(asns, _M.MAX_TOP_DIMENSIONS, function(n) return n end)) do
      out[k] = { requests = asns[k], name = names[k] or "" }
    end
    if next(out) then bucket.asns = out end
  end
  local referers = bucket._referers
  if referers then
    local out = {}
    for _, k in ipairs(heaviest(referers, _M.MAX_TOP_DIMENSIONS, function(n) return n end)) do
      out[k] = referers[k]
    end
    if next(out) then bucket.referers = out end
  end
  bucket._countries, bucket._asns, bucket._asn_names, bucket._referers = nil, nil, nil, nil
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
        elseif metric == "a" then
          b.auth_failures = (b.auth_failures or 0) + v
        elseif sub(metric, 1, 1) == "s" then
          local code = sub(metric, 2)
          b.status_codes[code] = (b.status_codes[code] or 0) + v
        elseif sub(metric, 1, 1) == "w" then
          local id = sub(metric, 2)
          b.waf_rules = b.waf_rules or {}
          b.waf_rules[id] = (b.waf_rules[id] or 0) + v
        elseif sub(metric, 1, 1) == "l" then
          local id = sub(metric, 2)
          b.logged_rules = b.logged_rules or {}
          b.logged_rules[id] = (b.logged_rules[id] or 0) + v
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
    merge_dimensions(bucket, record)
  end
  -- Rule counters only where a rule matched; the Top-K summaries always.
  local limits = { waf_rules = _M.MAX_WAF_RULES, logged_rules = _M.MAX_LOGGED_RULES }
  for _, bucket in ipairs(list) do
    for _, field in ipairs({"top_urls", "top_ips", "waf_rules", "logged_rules"}) do
      if not limits[field] or bucket[field] then
        local limit = limits[field] or 50
        local sorted = {}; for value,count in pairs(bucket[field] or {}) do sorted[#sorted+1] = {value=value,count=count} end
        table.sort(sorted,function(a,b) return a.count>b.count or (a.count==b.count and a.value<b.value) end)
        local selected = {}; for i=1,math.min(limit,#sorted) do selected[sorted[i].value] = sorted[i].count end
        bucket[field] = selected
      end
    end
  end
  for _, bucket in ipairs(list) do
    finish_dimensions(bucket)
  end
  if cjson.array_mt then
    setmetatable(list, cjson.array_mt)
  end
  return list
end

return _M
