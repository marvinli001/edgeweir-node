-- edgeweir.purge: purge markers.
--
-- A purge never touches the disk. It records a marker with an epoch (the
-- task's creation time in milliseconds) and edgeweir.cachekey appends the
-- highest epoch of the markers that match a request to its cache key. The
-- next request of a purged URL therefore misses under a new key; the old
-- objects are never looked up again and are evicted by the cache manager
-- (inactive / max_size), exactly like objects of an older cache generation.
--
-- Markers live in lua_shared_dict "edgeweir_purge":
--
--   u|<site>|<path>  JSON [[host, query, epoch], ...]   URL markers
--   p|<site>         JSON [[host, prefix, epoch], ...]  prefix markers
--   s|<site>         epoch                              whole-site marker
--   #id              id of the marker set (for resync checks)
--   #ver             bumped on every change (invalidates worker caches)
--
-- Matching uses the site's current cache key policy: the host is ignored
-- when the key excludes it, and query strings are compared after the same
-- normalization as the key (edgeweir.cachekey.normalize_query). Marker
-- paths arrive percent-encoded as requested and are normalized like
-- nginx's $uri (edgeweir.cachekey.normalize_path), which is what requests
-- are matched with: a prefix purge of "/static/" covers "/%73tatic/x".
--
-- The agent persists the markers, drops them once no object keyed without
-- them can remain (cache inactive time), and replays them after an nginx
-- restart before the site table is pushed.
local cjson = require("cjson.safe")
local lrucache = require("resty.lrucache")
local cachekey = require("edgeweir.cachekey")

local _M = {}

local sub = string.sub
local dict = ngx.shared.edgeweir_purge

local cache

local function lru()
  if not cache then
    cache = assert(lrucache.new(4096))
  end
  return cache
end

local function decode_list(raw)
  local list = raw and cjson.decode(raw)
  return type(list) == "table" and list or {}
end

-- cached returns the decoded list stored under key, cached per version.
local function cached(key, ver)
  local c = lru()
  local hit = c:get(key)
  if hit and hit[1] == ver then
    return hit[2]
  end
  local list = decode_list(dict:get(key))
  c:set(key, { ver, list })
  return list
end

-- merge adds (host, value, epoch) to a list, keeping the highest epoch per
-- (host, value). Returns true when the list changed.
local function merge(list, host, value, epoch)
  for i = 1, #list do
    local m = list[i]
    if m[1] == host and m[2] == value then
      if epoch > m[3] then
        m[3] = epoch
        return true
      end
      return false
    end
  end
  list[#list + 1] = { host, value, epoch }
  return true
end

local function valid(m)
  return type(m) == "table" and type(m.site_id) == "string" and m.site_id ~= ""
    and (m.type == "url" or m.type == "prefix" or m.type == "site")
    and tonumber(m.epoch) and tonumber(m.epoch) > 0
end

-- build groups markers into dict entries: key -> list | epoch.
local function build(markers)
  local entries = {}
  for i = 1, #markers do
    local m = markers[i]
    local epoch = tonumber(m.epoch)
    if m.type == "site" then
      local k = "s|" .. m.site_id
      if not entries[k] or entries[k] < epoch then
        entries[k] = epoch
      end
    elseif m.type == "prefix" then
      local k = "p|" .. m.site_id
      entries[k] = entries[k] or {}
      merge(entries[k], m.host or "", cachekey.normalize_path(m.path or "/"), epoch)
    else
      local k = "u|" .. m.site_id .. "|" .. cachekey.normalize_path(m.path or "/")
      entries[k] = entries[k] or {}
      merge(entries[k], m.host or "", m.query or "", epoch)
    end
  end
  return entries
end

local function store(k, v)
  local value = type(v) == "table" and cjson.encode(v) or v
  local ok, err = dict:safe_set(k, value)
  if not ok then
    return nil, "shared dict edgeweir_purge: " .. tostring(err)
  end
  return true
end

local function validate(doc)
  if type(doc) ~= "table" or type(doc.markers) ~= "table" then
    return nil, "document must be an object with a markers array"
  end
  if type(doc.id) ~= "string" then
    return nil, "id must be a string"
  end
  for i = 1, #doc.markers do
    if not valid(doc.markers[i]) then
      return nil, "invalid marker #" .. i
    end
  end
  return true
end

-- replace installs exactly the given marker set. New entries are written
-- before stale ones are deleted, so a request never sees fewer markers than
-- both the old and the new set agree on. doc = { id, markers = [...] }.
function _M.replace(doc)
  local ok, err = validate(doc)
  if not ok then
    return nil, err, 400
  end
  local entries = build(doc.markers)
  for k, v in pairs(entries) do
    local sok, serr = store(k, v)
    if not sok then
      return nil, serr, 507
    end
  end
  local keys = dict:get_keys(0)
  for i = 1, #keys do
    local k = keys[i]
    if sub(k, 1, 1) ~= "#" and entries[k] == nil then
      dict:delete(k)
    end
  end
  dict:set("#id", doc.id)
  dict:incr("#ver", 1, 0)
  return _M.status()
end

-- add merges markers into the current set. doc = { id, markers = [...] }
-- where id identifies the resulting set.
function _M.add(doc)
  local ok, err = validate(doc)
  if not ok then
    return nil, err, 400
  end
  for k, v in pairs(build(doc.markers)) do
    local value = v
    if type(v) == "table" then
      local current = decode_list(dict:get(k))
      for i = 1, #v do
        merge(current, v[i][1], v[i][2], v[i][3])
      end
      value = current
    else
      local current = dict:get(k)
      if current and current > v then
        value = current
      end
    end
    local sok, serr = store(k, value)
    if not sok then
      return nil, serr, 507
    end
  end
  dict:set("#id", doc.id)
  dict:incr("#ver", 1, 0)
  return _M.status()
end

function _M.status()
  local count = 0
  local keys = dict:get_keys(0)
  for i = 1, #keys do
    if sub(keys[i], 1, 1) ~= "#" then
      count = count + 1
    end
  end
  return { id = dict:get("#id") or "", entries = count }
end

-- epoch returns the highest epoch of the markers matching a request, or 0.
-- key is the site's prepared cache key policy; path is the normalized
-- $uri, args the raw query string.
function _M.epoch(site_id, key, host, path, args)
  local ver = dict:get("#ver")
  if not ver then
    return 0
  end
  local epoch = dict:get("s|" .. site_id) or 0
  local any_host = key.exclude_host

  local prefixes = cached("p|" .. site_id, ver)
  for i = 1, #prefixes do
    local m = prefixes[i]
    if m[3] > epoch and (any_host or m[1] == host) and sub(path, 1, #m[2]) == m[2] then
      epoch = m[3]
    end
  end

  local urls = cached("u|" .. site_id .. "|" .. path, ver)
  if #urls > 0 then
    local q = cachekey.normalize_query(args, key)
    for i = 1, #urls do
      local m = urls[i]
      if m[3] > epoch and (any_host or m[1] == host) and cachekey.normalize_query(m[2], key) == q then
        epoch = m[3]
      end
    end
  end
  return epoch
end

return _M
