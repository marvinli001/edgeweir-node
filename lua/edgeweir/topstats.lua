-- Per-worker, bounded Space-Saving heavy hitters. Only completed minute
-- summaries cross into shared memory; raw request headers/query strings never do.
local cjson = require("cjson.safe")
local _M = {}
local CAPACITY, MAX_BUCKETS = 32, 128
local buckets, size = {}, 0

local function observe(counts, value)
  if not value or value == "" then return end
  if counts[value] then counts[value] = counts[value] + 1; return end
  local count, minimum, victim = 0, math.huge, nil
  for key, n in pairs(counts) do
    count = count + 1
    if n < minimum or (n == minimum and (not victim or key < victim)) then minimum, victim = n, key end
  end
  if count < CAPACITY then counts[value] = 1
  else counts[victim] = nil; counts[value] = minimum + 1 end
end
_M.observe = observe
function _M.log(site, minute, path, address)
  -- Drop oversize paths rather than exposing truncated query-like suffixes.
  if path and (#path > 512 or path:find("?", 1, true) or path:find("[%c]")) then path = nil end
  local key = tostring(minute) .. "|" .. site
  local bucket = buckets[key]
  if not bucket then
    if size >= MAX_BUCKETS then return end
    bucket = { minute = minute, site_id = site, urls = {}, ips = {} }
    buckets[key] = bucket; size = size + 1
  end
  observe(bucket.urls, path)
  observe(bucket.ips, address)
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
function _M.init_worker()
  local ok, err = ngx.timer.every(1, function(premature) if not premature then _M.flush() end end)
  if not ok then ngx.log(ngx.ERR, "edgeweir: Top-K timer unavailable: ", err) end
end
return _M
