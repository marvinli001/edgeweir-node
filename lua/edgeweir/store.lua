-- edgeweir.store: the site table.
--
-- The agent replaces the whole table atomically through the control API.
-- Entries live in lua_shared_dict "edgeweir_sites" under a version prefix:
--
--   v<N>:site:<id>    JSON of the site
--   v<N>:host:<name>  site id for an exact host name
--   v<N>:wild:<name>  site id for a wildcard suffix ("*.<name>")
--
-- A replacement writes table N+1 next to table N, then flips
-- edgeweir_meta["version"]; requests never observe a half-written table.
-- The previous table is kept until the next replacement so requests that
-- started before the flip can still resolve. Each worker caches decoded
-- sites and host lookups in a lua-resty-lrucache keyed by version, so a
-- flip invalidates the cache implicitly.
local cjson = require("cjson.safe")
local lrucache = require("resty.lrucache")
local rules = require("edgeweir.rules")

local _M = {}

local sub, find = string.sub, string.find

local sites = ngx.shared.edgeweir_sites
local meta = ngx.shared.edgeweir_meta

local LRU_SIZE = 20000
local cache

local function lru()
  if not cache then
    local c, err = lrucache.new(LRU_SIZE)
    if not c then
      error("failed to create lrucache: " .. tostring(err))
    end
    cache = c
  end
  return cache
end

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

local function validate(site)
  if type(site) ~= "table" then
    return "site must be an object"
  end
  if not is_nonempty_string(site.id) then
    return "site id must be a non-empty string"
  end
  if type(site.domains) ~= "table" or #site.domains == 0 then
    return "site " .. site.id .. ": domains must be a non-empty array"
  end
  for _, d in ipairs(site.domains) do
    if type(d) ~= "table" or not is_nonempty_string(d.name) then
      return "site " .. site.id .. ": invalid domain"
    end
  end
  if type(site.origins) ~= "table" or #site.origins == 0 then
    return "site " .. site.id .. ": origins must be a non-empty array"
  end
  for _, o in ipairs(site.origins) do
    if type(o) ~= "table" or not is_nonempty_string(o.address) or type(o.port) ~= "number"
      or (o.scheme ~= "http" and o.scheme ~= "https") then
      return "site " .. site.id .. ": invalid origin"
    end
  end
  if not is_nonempty_string(site.cache_zone) then
    return "site " .. site.id .. ": cache_zone must be a non-empty string"
  end
  return nil
end

-- prepare precomputes per-site data used on the hot path.
function _M.prepare(s)
  s.cache_generation = tostring(s.cache_generation or "0")
  local primaries, backups, pw, bw = {}, {}, 0, 0
  for _, o in ipairs(s.origins or {}) do
    local w = tonumber(o.weight) or 1
    if w < 1 then
      w = 1
    end
    o.weight = w
    local host = o.address
    if find(host, ":", 1, true) then
      host = "[" .. host .. "]" -- IPv6 literal
    end
    o.url = o.scheme .. "://" .. host .. ":" .. tostring(o.port)
    local sni = o.sni
    if not is_nonempty_string(sni) then
      sni = o.host_header
      if is_nonempty_string(sni) then
        sni = sni:gsub(":%d+$", "")
      else
        sni = o.address
      end
    end
    o.sni_name = sni
    if o.backup == true then
      backups[#backups + 1] = o
      bw = bw + w
    else
      primaries[#primaries + 1] = o
      pw = pw + w
    end
  end
  s._primaries, s._backups, s._pw, s._bw = primaries, backups, pw, bw
  if type(s.cache_rules) == "table" then
    for i = 1, #s.cache_rules do
      rules.prepare(s.cache_rules[i])
    end
  else
    s.cache_rules = nil
  end
  return s
end

-- replace installs a new site table. doc = { revision, content_hash, sites }.
-- Returns the new status, or nil, error message, HTTP status.
function _M.replace(doc)
  if type(doc) ~= "table" then
    return nil, "document must be an object", 400
  end
  local list = doc.sites
  if list == nil or list == cjson.null then
    list = {}
  end
  if type(list) ~= "table" then
    return nil, "sites must be an array", 400
  end

  local locked, lerr = meta:add("lock", true, 30)
  if not locked then
    if lerr == "exists" then
      return nil, "another update is in progress", 409
    end
    return nil, "lock: " .. tostring(lerr), 500
  end

  local ver, verr = meta:incr("version_seq", 1, 0)
  if not ver then
    meta:delete("lock")
    return nil, "version: " .. tostring(verr), 500
  end
  local prefix = "v" .. ver .. ":"
  local written = {}
  local failure, failure_status

  local function put(key, value)
    local full = prefix .. key
    local ok, err = sites:safe_set(full, value)
    if not ok then
      failure = "shared dict edgeweir_sites: " .. tostring(err)
      failure_status = (err == "no memory") and 507 or 500
      return false
    end
    written[#written + 1] = full
    return true
  end

  local count = 0
  for i = 1, #list do
    local site = list[i]
    local err = validate(site)
    if err then
      failure, failure_status = err, 400
      break
    end
    if not put("site:" .. site.id, cjson.encode(site)) then
      break
    end
    for _, d in ipairs(site.domains) do
      local kind = (d.wildcard == true) and "wild:" or "host:"
      if not put(kind .. d.name, site.id) then
        break
      end
    end
    if failure then
      break
    end
    count = count + 1
  end

  if failure then
    for i = 1, #written do
      sites:delete(written[i])
    end
    meta:delete("lock")
    return nil, failure, failure_status
  end

  local old = meta:get("version") or 0
  local status = {
    version = ver,
    revision = tostring(doc.revision or "0"),
    content_hash = type(doc.content_hash) == "string" and doc.content_hash or "",
    site_count = count,
    pushed_at = ngx.now(),
  }
  meta:set("status", cjson.encode(status))
  meta:set("prev_version", old)
  meta:set("version", ver) -- the atomic flip

  -- Drop every table except the new one and the previous one.
  local keep_new, keep_old = prefix, "v" .. old .. ":"
  local keys = sites:get_keys(0)
  for i = 1, #keys do
    local k = keys[i]
    if sub(k, 1, #keep_new) ~= keep_new and sub(k, 1, #keep_old) ~= keep_old then
      sites:delete(k)
    end
  end
  meta:delete("lock")
  return status
end

-- status returns the current table metadata (version 0 = never pushed,
-- e.g. right after nginx started: the agent must push again).
function _M.status()
  local raw = meta:get("status")
  local st = raw and cjson.decode(raw)
  if type(st) ~= "table" then
    st = { revision = "0", content_hash = "", site_count = 0 }
  end
  st.version = meta:get("version") or 0
  return st
end

-- site returns the decoded site with id from table version ver.
function _M.site(ver, id)
  local c = lru()
  local ck = "s:" .. ver .. ":" .. id
  local s = c:get(ck)
  if s then
    return s
  end
  local raw = sites:get("v" .. ver .. ":site:" .. id)
  if not raw then
    return nil
  end
  s = cjson.decode(raw)
  if type(s) ~= "table" then
    return nil
  end
  _M.prepare(s)
  c:set(ck, s)
  return s
end

-- site_current returns the site with id from the current table, falling
-- back to the previous table for requests that raced a flip.
function _M.site_current(id)
  local ver = meta:get("version")
  if not ver then
    return nil
  end
  local s = _M.site(ver, id)
  if s then
    return s
  end
  local prev = meta:get("prev_version")
  if prev and prev > 0 then
    return _M.site(prev, id)
  end
  return nil
end

-- lookup_host resolves a lowercase host name: exact match first, then a
-- wildcard on the parent domain (single left-most label).
function _M.lookup_host(host)
  local ver = meta:get("version")
  if not ver or not host or host == "" then
    return nil
  end
  local c = lru()
  local ck = "h:" .. host
  local hit = c:get(ck)
  if hit and hit[1] == ver then
    return hit[2] or nil
  end
  local id = sites:get("v" .. ver .. ":host:" .. host)
  if not id then
    local dot = find(host, ".", 1, true)
    if dot then
      id = sites:get("v" .. ver .. ":wild:" .. sub(host, dot + 1))
    end
  end
  local site = false
  if id then
    site = _M.site(ver, id) or false
  end
  c:set(ck, { ver, site })
  return site or nil
end

return _M
