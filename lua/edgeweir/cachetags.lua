-- edgeweir.cachetags: the Cache-Tag index behind purges by tag.
--
-- Origins name the tags of a response in the Cache-Tag header (comma
-- separated). Unlike URL and prefix markers, a tag marker (edgeweir.purge,
-- t|<site>|<tag>) cannot be matched before the cache lookup: only the
-- cached object knows its tags. The edge layer therefore remembers the tags
-- of cached objects and the key epoch they were stored under, in
-- lua_shared_dict edgeweir_tags (size: the agent's --tag-dict-mb):
--
--   <md5(B)>      "<E>|<tag>,<tag>,..."  (or "<E>*": every tag of the site)
--   s:<site id>   1 once a tagged response of the site was indexed
--
-- B is the cache key without its purge epoch; the cache key is B, or
-- B .. "#" .. E with the key epoch E (edgeweir.cachekey: "#" appears in a
-- key only before the epoch). Entries and site flags expire after the
-- longest inactive time of the cache zones (tag_ttl of the site table) and
-- are evicted least recently used when the dict is full.
--
-- Key epoch (edge access, cacheable requests; key_epoch). E_url is the
-- epoch of the URL, prefix and site markers (edgeweir.purge.epoch). When
-- the site has tag markers (T|<site>, tmax):
--   entry {E_e, tags}: E = max(E_url, E_e, highest epoch of the tags' markers)
--   no entry:          E = max(E_url, tmax) (an unknown object, e.g. after
--                      an eviction or an nginx restart, is fetched once more)
-- Without tag markers E = E_url and nothing is looked up. A tag purge thus
-- moves the key of every object carrying the tag, and all its slices at
-- once, exactly like a URL purge: the old object is never looked up again,
-- so it can be served neither fresh nor stale.
--
-- Write (edge header filter; record). Responses fetched for the cache
-- (MISS or EXPIRED) record {E, tags}, E being the epoch of the key they are
-- stored under ($edgeweir_cache_key), when the response has tags, the site
-- flag is set or the site has tag markers (so that untagged objects keep
-- their key when an unrelated tag is purged). Slice and background-update
-- subrequests write too: they share the main request's nginx variables
-- (not its ngx.ctx). An entry only grows: a higher E replaces it, the same
-- E adds the new tags (slices of one object fetched at different times are
-- stored under one key epoch), a lower E (a fetch that started before a
-- newer one was recorded) changes nothing. Tags beyond 4096 bytes in total
-- turn the entry into "<E>*", which every tag marker of the site moves.
--
-- Correctness: epochs are node-assigned and strictly increase in the order
-- markers are applied. A request that computed key epoch E saw every marker
-- applied before it started; a tag marker m it did not see was applied
-- later, so m > E. Once the object's entry lists its tags, the next request
-- computes a key epoch >= m; without the entry it computes max(E_url, tmax)
-- >= m. Either way the purged object is never looked up again. Writes of
-- one entry are not atomic across workers: two fetches of the same object
-- under the same key epoch that finish at the same instant with different
-- tags may keep only one writer's additions.
local purge = require("edgeweir.purge")

local _M = {}

local byte, concat, find, format, gmatch, lower, match, sub =
  string.byte, table.concat, string.find, string.format, string.gmatch, string.lower, string.match, string.sub
local max, tonumber, type = math.max, tonumber, type
local md5_bin = ngx.md5_bin

_M.MAX_HEADER = 4096
_M.MAX_TAG = 128

local function dict()
  return ngx.shared.edgeweir_tags
end

-- parse returns the tags of a Cache-Tag value (a string, or the table of
-- the header's values, joined with ","), in order: only the first 4096
-- bytes are read (the element cut at that boundary is dropped unless byte
-- 4097 is a ","); elements are split on ",", trimmed of spaces and tabs and
-- lowercased; empty elements, elements longer than 128 bytes and elements
-- with a byte outside 0x20-0x7e are dropped; duplicates keep their first
-- occurrence.
function _M.parse(value)
  if type(value) == "table" then
    value = concat(value, ",")
  end
  local out = {}
  if type(value) ~= "string" or value == "" then
    return out
  end
  if #value > _M.MAX_HEADER then
    local cut = sub(value, 1, _M.MAX_HEADER)
    if byte(value, _M.MAX_HEADER + 1) ~= 44 then -- ","
      local last = find(cut, ",[^,]*$")
      cut = last and sub(cut, 1, last - 1) or ""
    end
    value = cut
  end
  local seen = {}
  for element in gmatch(value, "[^,]+") do
    local tag = lower(match(element, "^[ \t]*(.-)[ \t]*$"))
    if tag ~= "" and #tag <= _M.MAX_TAG and not find(tag, "[^\32-\126]") and not seen[tag] then
      seen[tag] = true
      out[#out + 1] = tag
    end
  end
  return out
end

-- encode returns an index entry: tags is a list, or true for every tag.
function _M.encode(epoch, tags)
  if tags == true then
    return format("%.0f*", epoch)
  end
  return format("%.0f", epoch) .. "|" .. concat(tags, ",")
end

-- decode returns the epoch and the tags (a list, or true for every tag) of
-- an index entry, or nil.
function _M.decode(raw)
  if type(raw) ~= "string" then
    return nil
  end
  local e, kind, rest = match(raw, "^(%d+)([|*])(.*)$")
  if not e then
    return nil
  end
  if kind == "*" then
    return tonumber(e), true
  end
  local tags = {}
  for tag in gmatch(rest, "[^,]+") do
    tags[#tags + 1] = tag
  end
  return tonumber(e), tags
end

-- merge returns the entry that replaces old after recording tags under
-- epoch, or nil when old stays (see the module comment).
function _M.merge(old, epoch, tags)
  local e, current = _M.decode(old)
  if not e or epoch > e then
    return _M.encode(epoch, tags)
  end
  if epoch < e or current == true then
    return nil
  end
  local seen, out, n, added = {}, {}, #current, false
  for i = 1, n do
    seen[current[i]] = true
    out[i] = current[i]
  end
  for i = 1, #tags do
    local tag = tags[i]
    if not seen[tag] then
      seen[tag] = true
      n = n + 1
      out[n] = tag
      added = true
    end
  end
  if not added then
    return nil
  end
  if #concat(out, ",") > _M.MAX_HEADER then
    return _M.encode(epoch, true)
  end
  return _M.encode(epoch, out)
end

-- split_key returns the base key B and the key epoch of a cache key.
function _M.split_key(key)
  local base, e = match(key, "^(.*)#(%d+)$")
  if base then
    return base, tonumber(e)
  end
  return key, 0
end

-- key_epoch returns the key epoch of a request of site_id with base key
-- base, given the epoch of its URL, prefix and site markers (e_url) and
-- the site's highest tag marker epoch (tmax, not nil).
function _M.key_epoch(site_id, base, e_url, tmax)
  local d = dict()
  local e, tags = _M.decode(d and d:get(md5_bin(base)))
  local t
  if not e then
    e, t = 0, tmax
  elseif tags == true then
    t = tmax
  else
    t = purge.tag_epoch(site_id, tags)
  end
  return max(e_url, e, t)
end

local warned = false

-- record indexes a response fetched for the cache: key is its cache key
-- ($edgeweir_cache_key), header its Cache-Tag value, ttl the lifetime of
-- the entry.
function _M.record(site_id, key, header, ttl)
  local d = dict()
  if not d or not site_id or site_id == "" or not key or key == "" then
    return -- an nginx.conf without edgeweir_tags indexes nothing
  end
  local tags = _M.parse(header)
  local flag = "s:" .. site_id
  if #tags == 0 and not d:get(flag) and not purge.tag_max(site_id) then
    return
  end
  local base, epoch = _M.split_key(key)
  local k = md5_bin(base)
  local value = _M.merge(d:get(k), epoch, tags)
  if value then
    local ok, err = d:set(k, value, ttl)
    if not ok and not warned then
      warned = true
      ngx.log(ngx.ERR, "edgeweir: cannot index Cache-Tag: ", err)
    end
  end
  if #tags > 0 then
    d:set(flag, 1, ttl)
  end
end

return _M
