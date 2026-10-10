-- Per-worker, bounded minute summaries of a site's traffic: Space-Saving
-- heavy hitters (URLs and client addresses, 32 candidates each; networks
-- and referring hosts, 64 each) and the bounded dimensions of ADR-0041
-- (countries with requests and bytes, user agent classes, HTTP and TLS
-- versions, block reasons, challenges issued and passed). At most
-- MAX_BUCKETS sites per worker and minute. Only completed minute summaries
-- cross into shared memory (edgeweir_topstats, once per minute and
-- worker); raw request headers and query strings never do.
local cjson = require("cjson.safe")
local _M = {}
local CAPACITY, MAX_BUCKETS = 32, 128
-- Candidates per worker of the networks and referring hosts.
_M.DIM_CAPACITY = 64
_M.MAX_BUCKETS = MAX_BUCKETS
local buckets, size = {}, 0

-- observe counts value in a Space-Saving summary of capacity candidates
-- (default 32) and returns the candidate it evicted, if any.
local function observe(counts, value, capacity)
  if not value or value == "" then return end
  if counts[value] then counts[value] = counts[value] + 1; return end
  local count, minimum, victim = 0, math.huge, nil
  for key, n in pairs(counts) do
    count = count + 1
    if n < minimum or (n == minimum and (not victim or key < victim)) then minimum, victim = n, key end
  end
  if count < (capacity or CAPACITY) then counts[value] = 1; return end
  counts[victim] = nil; counts[value] = minimum + 1
  return victim
end
_M.observe = observe

local function bucket_for(site, minute)
  local key = tostring(minute) .. "|" .. site
  local bucket = buckets[key]
  if not bucket then
    if size >= MAX_BUCKETS then return nil end
    bucket = { minute = minute, site_id = site, urls = {}, ips = {} }
    buckets[key] = bucket; size = size + 1
  end
  return bucket
end

local function add(map, key)
  map[key] = (map[key] or 0) + 1
end

-- dimensions adds a request's dimensions d (see stats.dimensions) to b.
local function dimensions(b, d)
  local countries = b.countries
  if not countries then
    countries = {}
    b.countries, b.asns, b.asn_names, b.referers = countries, {}, {}, {}
    b.browsers, b.oses, b.devices, b.http, b.tls, b.reasons = {}, {}, {}, {}, {}, {}
  end
  local c = countries[d.country]
  if c then
    c[1], c[2] = c[1] + 1, c[2] + d.bytes
  else
    countries[d.country] = { 1, d.bytes }
  end
  if d.asn then
    local evicted = observe(b.asns, d.asn, _M.DIM_CAPACITY)
    if evicted then b.asn_names[evicted] = nil end
    if b.asns[d.asn] and d.as_name ~= "" then b.asn_names[d.asn] = d.as_name end
  end
  if d.referer then observe(b.referers, d.referer, _M.DIM_CAPACITY) end
  add(b.browsers, d.browser); add(b.oses, d.os); add(b.devices, d.device)
  add(b.http, d.http); add(b.tls, d.tls)
  if d.reason then add(b.reasons, d.reason) end
end

-- log counts a request of site in minute: its original path, client
-- address and, when given, its dimensions d.
function _M.log(site, minute, path, address, d)
  -- Drop oversize paths rather than exposing truncated query-like suffixes.
  if path and (#path > 512 or path:find("?", 1, true) or path:find("[%c]")) then path = nil end
  local bucket = bucket_for(site, minute)
  if not bucket then return end
  observe(bucket.urls, path)
  observe(bucket.ips, address)
  if d then dimensions(bucket, d) end
end

-- challenge counts a challenge sent ("issued": a challenge page or a
-- cookie302 redirect) or a pass issued after a verified answer ("passed")
-- for site in the current minute (access phase). The local listeners are
-- the operator's own.
function _M.challenge(site_id, kind)
  if ngx.var.edgeweir_local == "1" then return end
  local bucket = bucket_for(site_id, math.floor(ngx.time() / 60) * 60)
  if not bucket then return end
  local field = kind == "passed" and "ch_passed" or "ch_issued"
  bucket[field] = (bucket[field] or 0) + 1
end

function _M.flush(now)
  local current = math.floor((now or ngx.time()) / 60) * 60
  local dict = ngx.shared.edgeweir_topstats
  for key, bucket in pairs(buckets) do
    if bucket.minute < current then
      local encoded = cjson.encode(bucket)
      -- Never evict traffic totals, or another worker's queued Top-K snapshot.
      if encoded then dict:safe_set(key .. "|" .. tostring(ngx.worker.pid()), encoded, 7200) end
      buckets[key] = nil; size = size - 1
    end
  end
end
function _M.drain(now)
  local current = math.floor((now or ngx.time()) / 60) * 60
  local dict = ngx.shared.edgeweir_topstats
  local out = {}
  for _, key in ipairs(dict:get_keys(0)) do
    local minute = tonumber(key:match("^(%d+)|"))
    if minute and minute < current then
      local raw = dict:get(key); dict:delete(key)
      local record = raw and cjson.decode(raw)
      if record then out[#out + 1] = record end
    end
  end
  return out
end

-- reset drops the worker's buckets (tests).
function _M.reset()
  buckets, size = {}, 0
end

function _M.init_worker()
  local ok, err = ngx.timer.every(1, function(premature) if not premature then _M.flush() end end)
  if not ok then ngx.log(ngx.ERR, "edgeweir: Top-K timer unavailable: ", err) end
end
return _M
