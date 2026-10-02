-- edgeweir.purge: purge markers.
--
-- A purge never touches the disk. It records a marker with an epoch (the
-- time in milliseconds the node assigned when it first applied the task)
-- and edgeweir.cachekey appends the highest epoch of the markers that match
-- a request to its cache key. The next request of a purged URL therefore
-- misses under a new key; the old objects are never looked up again and are
-- evicted by the cache manager (inactive / max_size), exactly like objects
-- of an older cache generation.
--
-- Markers live in lua_shared_dict "edgeweir_purge" (size: the agent's
-- --purge-dict-mb):
--
--   u|<site>|<path>  JSON [[host, query, epoch], ...]   URL markers
--   p|<site>         JSON [[host, prefix, epoch], ...]  prefix markers
--   s|<site>         epoch                              whole-site marker
--   t|<site>|<tag>   epoch                              tag marker
--   T|<site>         epoch                              highest tag epoch of the site
--   #id              id of the marker set (for resync checks)
--   #ver             bumped on every change (invalidates worker caches)
--   #entries         number of marker entries (keys above)
--   #markers         number of markers (T| is an entry, not a marker)
--   #lock            held while a change is written
--
-- Tag markers do not change the key by themselves: edgeweir.cachetags
-- looks up the tags an object was cached with and moves its key epoch
-- past the markers of those tags. T| tells the edge layer whether a site
-- has tag markers at all (one shared dict read per request).
--
-- The status is read from these counters; nothing walks the dict except a
-- full replacement (after an nginx restart or when markers expire).
--
-- Bounds: the agent caps the markers per site (collapsing a site's URL,
-- prefix and tag markers into one site-level marker beyond the cap). When
-- a full replacement still does not fit, the markers of each site that
-- does not fit, tag markers included, are replaced by one site-level
-- marker at their highest epoch (over-purging instead of failing) and the
-- site is reported in "collapsed".
--
-- Matching uses the site's current cache key policy: the host is ignored
-- when the key excludes it, and query strings are compared after the same
-- normalization as the key, percent-decoded (edgeweir.cachekey.purge_query:
-- the console re-encodes what was typed, clients encode as they like). Marker
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

local byte, find, lower, sub = string.byte, string.find, string.lower, string.sub
local dict = ngx.shared.edgeweir_purge

local cache, tag_cache

local function lru()
  if not cache then
    cache = assert(lrucache.new(4096))
  end
  return cache
end

-- tag_lru caches the epochs of tag markers per worker (per #ver).
local function tag_lru()
  if not tag_cache then
    tag_cache = assert(lrucache.new(16384))
  end
  return tag_cache
end

_M.MAX_TAG = 128

-- valid_tag reports whether tag is a valid Cache-Tag element: 1-128 bytes
-- of printable ASCII (0x20-0x7e) without commas and without leading or
-- trailing spaces.
function _M.valid_tag(tag)
  if type(tag) ~= "string" or tag == "" or #tag > _M.MAX_TAG then
    return false
  end
  if find(tag, "[^\32-\126]") or find(tag, ",", 1, true) then
    return false
  end
  return byte(tag, 1) ~= 32 and byte(tag, -1) ~= 32
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
    and (m.type == "url" or m.type == "prefix" or m.type == "site" or (m.type == "tag" and _M.valid_tag(m.tag)))
    and tonumber(m.epoch) and tonumber(m.epoch) > 0
end

-- raise sets entries[k] to epoch unless it holds a higher one.
local function raise(entries, k, epoch)
  if not entries[k] or entries[k] < epoch then
    entries[k] = epoch
  end
end

-- build groups markers into dict entries: key -> list | epoch. An index
-- per entry keeps it linear in the number of markers.
local function build(markers)
  local entries, index = {}, {}
  local function add(k, host, value, epoch)
    local list = entries[k]
    if not list then
      list = {}
      entries[k], index[k] = list, {}
    end
    local id = host .. "\0" .. value
    local m = index[k][id]
    if m then
      if epoch > m[3] then
        m[3] = epoch
      end
    else
      m = { host, value, epoch }
      list[#list + 1] = m
      index[k][id] = m
    end
  end
  for i = 1, #markers do
    local m = markers[i]
    local epoch = tonumber(m.epoch)
    if m.type == "site" then
      raise(entries, "s|" .. m.site_id, epoch)
    elseif m.type == "tag" then
      -- Tags compare in lowercase, like the Cache-Tag parser keeps them.
      raise(entries, "t|" .. m.site_id .. "|" .. lower(m.tag), epoch)
      raise(entries, "T|" .. m.site_id, epoch)
    elseif m.type == "prefix" then
      add("p|" .. m.site_id, m.host or "", cachekey.normalize_path(m.path or "/"), epoch)
    else
      add("u|" .. m.site_id .. "|" .. cachekey.normalize_path(m.path or "/"), m.host or "", m.query or "", epoch)
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

-- site_of returns the site id of a marker entry key (site ids never
-- contain "|"; paths and tags after it may).
local function site_of(k)
  local kind = sub(k, 1, 2)
  if kind == "s|" or kind == "p|" or kind == "T|" then
    return sub(k, 3)
  end
  local bar = find(k, "|", 3, true)
  return bar and sub(k, 3, bar - 1) or sub(k, 3)
end

-- size_of returns the number of markers entry k holds (T| only indexes
-- the site's tag markers).
local function size_of(k, v)
  if sub(k, 1, 2) == "T|" then
    return 0
  end
  return type(v) == "table" and #v or 1
end

local function lock()
  local ok, err = dict:add("#lock", true, 30)
  if not ok then
    if err == "exists" then
      return nil, "another purge update is in progress", 409
    end
    return nil, "lock: " .. tostring(err), 500
  end
  return true
end

local function unlock()
  dict:delete("#lock")
end

local function max_epoch(v)
  if type(v) ~= "table" then
    return v
  end
  local e = 0
  for i = 1, #v do
    if v[i][3] > e then
      e = v[i][3]
    end
  end
  return e
end

local function status_with(collapsed)
  local st = _M.status()
  if collapsed and #collapsed > 0 then
    st.collapsed = collapsed
  end
  return st
end

-- replace installs exactly the given marker set. New entries are written
-- before stale ones are deleted, so a request never sees fewer markers than
-- both the old and the new set agree on. A site whose entries do not fit is
-- collapsed into one site-level marker. doc = { id, markers = [...] }.
function _M.replace(doc)
  local ok, err, code = validate(doc)
  if not ok then
    return nil, err, 400
  end
  ok, err, code = lock()
  if not ok then
    return nil, err, code
  end
  local entries = build(doc.markers)
  local by_site, top = {}, {}
  for k, v in pairs(entries) do
    local site = site_of(k)
    by_site[site] = by_site[site] or {}
    by_site[site][#by_site[site] + 1] = k
    top[site] = math.max(top[site] or 0, max_epoch(v))
  end
  local collapsed = {}
  for site, keys in pairs(by_site) do
    local fits = true
    for i = 1, #keys do
      if not store(keys[i], entries[keys[i]]) then
        fits = false
        break
      end
    end
    if not fits then
      for i = 1, #keys do
        dict:delete(keys[i])
        entries[keys[i]] = nil
      end
      local sk = "s|" .. site
      entries[sk] = top[site]
      local sok, serr = store(sk, top[site])
      if not sok then
        unlock()
        return nil, serr, 507
      end
      collapsed[#collapsed + 1] = site
    end
  end
  local keys = dict:get_keys(0)
  for i = 1, #keys do
    local k = keys[i]
    if sub(k, 1, 1) ~= "#" and entries[k] == nil then
      dict:delete(k)
    end
  end
  local n, markers = 0, 0
  for k, v in pairs(entries) do
    n, markers = n + 1, markers + size_of(k, v)
  end
  dict:set("#entries", n)
  dict:set("#markers", markers)
  dict:set("#id", doc.id)
  dict:incr("#ver", 1, 0)
  unlock()
  if #collapsed > 0 then
    table.sort(collapsed)
    ngx.log(ngx.WARN, "edgeweir: purge markers of ", #collapsed, " site(s) did not fit and were replaced by site-level markers")
  end
  return status_with(collapsed)
end

-- add merges markers into the current set. doc = { id, markers = [...] }
-- where id identifies the resulting set. When an entry does not fit the
-- call fails (507) and the agent installs the full set with replace().
function _M.add(doc)
  local ok, err, code = validate(doc)
  if not ok then
    return nil, err, 400
  end
  ok, err, code = lock()
  if not ok then
    return nil, err, code
  end
  for k, v in pairs(build(doc.markers)) do
    local raw = dict:get(k)
    local value, before = v, 0
    if type(v) == "table" then
      local current = decode_list(raw)
      before = raw and #current or 0
      for i = 1, #v do
        merge(current, v[i][1], v[i][2], v[i][3])
      end
      value = current
    elseif raw then
      before = size_of(k, raw)
      if raw > v then
        value = raw
      end
    end
    local sok, serr = store(k, value)
    if not sok then
      dict:incr("#ver", 1, 0)
      unlock()
      return nil, serr, 507
    end
    if not raw then
      dict:incr("#entries", 1, 0)
    end
    dict:incr("#markers", size_of(k, value) - before, 0)
  end
  dict:set("#id", doc.id)
  dict:incr("#ver", 1, 0)
  unlock()
  return _M.status()
end

-- status reports the installed set from its counters (never walks the dict).
function _M.status()
  return { id = dict:get("#id") or "", entries = dict:get("#entries") or 0, markers = dict:get("#markers") or 0 }
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
    local q = cachekey.purge_query(args, key)
    for i = 1, #urls do
      local m = urls[i]
      if m[3] > epoch and (any_host or m[1] == host) and cachekey.purge_query(m[2], key) == q then
        epoch = m[3]
      end
    end
  end
  return epoch
end

-- tag_max returns the highest tag marker epoch of a site, or nil when it
-- has no tag marker: one shared dict read, the only per-request cost of
-- tag purges for sites that have none.
function _M.tag_max(site_id)
  return dict:get("T|" .. site_id)
end

-- tag_epoch returns the highest epoch of the tag markers of site_id among
-- tags (a list of parsed, lowercase tags), or 0.
function _M.tag_epoch(site_id, tags)
  local ver = dict:get("#ver")
  if not ver or #tags == 0 then
    return 0
  end
  local c = tag_lru()
  local epoch = 0
  for i = 1, #tags do
    local k = "t|" .. site_id .. "|" .. tags[i]
    local hit = c:get(k)
    local e
    if hit and hit[1] == ver then
      e = hit[2]
    else
      e = dict:get(k) or 0
      c:set(k, { ver, e })
    end
    if e > epoch then
      epoch = e
    end
  end
  return epoch
end

return _M
