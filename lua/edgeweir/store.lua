-- edgeweir.store: the site table.
--
-- The agent replaces the whole table atomically through the control API.
-- Entries live in lua_shared_dict "edgeweir_sites" under a version prefix:
--
--   v<N>:site:<id>    JSON of the site
--   v<N>:host:<name>  site id for an exact host name
--   v<N>:wild:<name>  site id for a wildcard suffix ("*.<name>")
--   v<N>:cfg          JSON of the table settings (origin allow list,
--                     cdn_id, HTTP-01 answers, IP lists, platform rules,
--                     platform protection, ids of the sites with CC, the
--                     lifetime of Cache-Tag index entries, the platform's
--                     error pages and the offline hosts)
--
-- A replacement writes table N+1 next to table N, then flips
-- edgeweir_meta["version"]; requests never observe a half-written table.
-- The previous table is kept until the next replacement so requests that
-- started before the flip can still resolve. Each worker caches decoded
-- sites and host lookups in lua-resty-lrucache instances keyed by version,
-- so a flip invalidates them implicitly:
--
--   sites   decoded sites (with their round-robin and hash-ring state)
--           and table settings;
--   hosts   host -> site id for exact names, "*.<parent>" -> site id for
--           wildcards (random subdomains of a wildcard site add nothing);
--   misses  unknown hosts, a small separate cache: a flood of made-up Host
--           headers only churns this one and never evicts sites or hosts.
local cjson = require("cjson.safe")
local lrucache = require("resty.lrucache")
local rules = require("edgeweir.rules")
local cachekey = require("edgeweir.cachekey")
local ipaddr = require("edgeweir.ipaddr")
local policy = require("edgeweir.policy")
local ratelimit = require("edgeweir.ratelimit")
local cc = require("edgeweir.cc")
local errorpages = require("edgeweir.errorpages")

local _M = {}

local sub, find = string.sub, string.find

local sites = ngx.shared.edgeweir_sites
local meta = ngx.shared.edgeweir_meta

_M.SITE_CACHE_SIZE = 20000
_M.HOST_CACHE_SIZE = 20000
_M.MISS_CACHE_SIZE = 1024

local caches = {}

local function new_cache(name, size)
  local c = caches[name]
  if not c then
    local err
    c, err = lrucache.new(size)
    if not c then
      error("failed to create lrucache: " .. tostring(err))
    end
    caches[name] = c
  end
  return c
end

local function lru()
  return new_cache("sites", _M.SITE_CACHE_SIZE)
end

local function hosts()
  return new_cache("hosts", _M.HOST_CACHE_SIZE)
end

local function misses()
  return new_cache("misses", _M.MISS_CACHE_SIZE)
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

local DEFAULT_HEALTH = { max_fails = 3, recovery_seconds = 30 }
local DEFAULT_CONN = {
  connect_timeout_ms = 10000, send_timeout_ms = 60000, read_timeout_ms = 60000,
  keepalive = true, keepalive_idle = 60, keepalive_requests = 1000,
}

local function with_defaults(t, defaults)
  t = type(t) == "table" and t or {}
  for k, v in pairs(defaults) do
    if t[k] == nil or t[k] == 0 then
      t[k] = v
    end
  end
  return t
end

-- prepare precomputes per-site data used on the hot path. Missing fields
-- (site tables pushed by older agents) take the defaults.
function _M.prepare(s, cfg)
  s._rate_limit_dict = ngx.shared[ratelimit.dict_name(s.id)]
  s._config = cfg or policy.prepare_config({})
  s._rule_groups = policy.prepare_rules(s.rules, s._config.lists)
  local function geo(r)
    if (r.field or ""):sub(1,9) == "ip.geoip." then return true end
    for _, c in ipairs(r.children or {}) do if geo(c) then return true end end
    return false
  end
  for _, r in ipairs(s.rules or {}) do if geo(r.expression) then s._geo = true end end
  for _, r in ipairs(s._config.platform_rules or {}) do if geo(r.expression) then s._geo = true end end
  -- JA4 is computed at the handshake only for sites that read it.
  local function ja4(r)
    if (r.field or "") == "tls.ja4" then return true end
    for _, c in ipairs(r.children or {}) do if ja4(c) then return true end end
    return false
  end
  local function uses_ja4(r)
    return type(r) == "table" and ((r.expression and ja4(r.expression)) or (type(r.action) == "table" and r.action.key == "tls.ja4"))
  end
  if type(s.protection) ~= "table" then s.protection = nil end
  if type(s.waf) ~= "table" then s.waf = nil end
  if type(s.tls) ~= "table" then s.tls = nil end
  s._ja4 = s.protection ~= nil and s.protection.log_ja4 == true
  for _, r in ipairs(s.rules or {}) do if uses_ja4(r) then s._ja4 = true end end
  for _, r in ipairs(s._config.platform_rules or {}) do if uses_ja4(r) then s._ja4 = true end end
  cc.prepare(s)
  -- _guard: Under Attack (platform or site) or CC may challenge requests.
  local pp = s._config.platform_protection
  s._guard = (type(pp) == "table" and pp.under_attack == true)
    or (s.protection ~= nil and (s.protection.under_attack == true or s._cc ~= nil)) or false
  s.cache_generation = tostring(s.cache_generation or "0")
  s.tls_verify = s.tls_verify ~= false
  s.websocket = s.websocket ~= false
  s.slice = s.slice == true
  s.keep_cache_tag = s.keep_cache_tag == true
  -- Active health checks (the agent's marks count for this site), session
  -- affinity (cookie lifetime) and error pages (compiled templates).
  s._active = s.active_health == true
  local ttl = type(s.affinity) == "table" and tonumber(s.affinity.ttl)
  s._affinity_ttl = (ttl and ttl >= 1) and ttl or nil
  local pages = type(s.error_pages) == "table" and s.error_pages or nil
  s._error_pages = pages and errorpages.compile_pages(pages.pages)
  s._intercept = s._error_pages ~= nil and pages.intercept == true
  s.health = with_defaults(s.health, DEFAULT_HEALTH)
  s.conn = with_defaults(s.conn, DEFAULT_CONN)
  s.cache_key = cachekey.prepare(s.cache_key)
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
    -- Host header for S3 origins without an explicit one: the default port
    -- of the scheme is left out, as HTTP clients (and SigV4 signers) do.
    local default_port = (o.scheme == "https") and 443 or 80
    o._s3_host = (o.port == default_port) and host or (host .. ":" .. tostring(o.port))
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

  local allowed = doc.origin_allowed_cidrs
  if type(allowed) ~= "table" then
    allowed = {}
  end
  local cc_sites = {}
  for _, site in ipairs(list) do
    if type(site) == "table" and type(site.protection) == "table" and type(site.protection.cc) == "table" and type(site.id) == "string" then
      cc_sites[#cc_sites + 1] = site.id
    end
  end
  if cjson.empty_array_mt and #cc_sites == 0 then setmetatable(cc_sites, cjson.empty_array_mt) end
  local pp = doc.platform_protection
  if type(pp) ~= "table" then pp = nil end
  local cfg = { origin_allowed_cidrs = allowed, cdn_id = type(doc.cdn_id) == "string" and doc.cdn_id or "", http_challenges = doc.http_challenges or {}, ip_lists = doc.ip_lists or {}, platform_rules = doc.platform_rules or {}, platform_protection = pp, cc_sites = cc_sites }
  cfg.tag_ttl = tonumber(doc.tag_ttl)
  if type(doc.platform_error_pages) == "table" then cfg.platform_error_pages = doc.platform_error_pages end
  if type(doc.offline_hosts) == "table" and #doc.offline_hosts > 0 then cfg.offline_hosts = doc.offline_hosts end
  if cjson.empty_array_mt and #allowed == 0 then
    setmetatable(allowed, cjson.empty_array_mt)
  end
  local compiled_ok, compiled_cfg = pcall(policy.prepare_config, {ip_lists = cfg.ip_lists, platform_rules = cfg.platform_rules})
  if not compiled_ok then meta:delete("lock"); return nil, "invalid policy configuration", 400 end
  local count = 0
  local n = put("cfg", cjson.encode(cfg)) and #list or 0
  for i = 1, n do
    local site = list[i]
    local err = validate(site)
    if not err then
      local ok = pcall(policy.prepare_rules, site.rules, compiled_cfg.lists)
      if not ok then err = "invalid site policy" end
    end
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
    cdn_id = cfg.cdn_id,
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

-- DEFAULT_TAG_TTL is the lifetime of Cache-Tag index entries when the
-- site table does not set it (the default inactive time of cache zones).
_M.DEFAULT_TAG_TTL = 3600

-- offline_hosts indexes the offline hosts of a table: exact names and
-- wildcard suffixes to their reason (disabled or suspended).
local function offline_hosts(list)
  if type(list) ~= "table" or #list == 0 then
    return nil
  end
  local out = { exact = {}, wild = {} }
  for _, h in ipairs(list) do
    if type(h) == "table" and type(h.name) == "string" and (h.reason == "disabled" or h.reason == "suspended") then
      local t = h.wildcard == true and out.wild or out.exact
      if not t[h.name] then
        t[h.name] = h.reason
      end
    end
  end
  return out
end

-- config returns the table-wide settings of the current table:
-- { allowed = parsed origin allow list (edgeweir.ipaddr.prefixes),
--   cdn_id = CDN-Loop identifier or "", tag_ttl = lifetime of Cache-Tag
--   index entries, platform_pages = compiled platform error pages,
--   offline = offline hosts (nil without any) }.
local EMPTY_CONFIG = { allowed = {}, cdn_id = "", tag_ttl = _M.DEFAULT_TAG_TTL, platform_pages = {} }

function _M.config(version)
  local ver = version or meta:get("version")
  if not ver then
    return EMPTY_CONFIG
  end
  local c = lru()
  local ck = "c:" .. ver
  local hit = c:get(ck)
  if hit then
    return hit
  end
  local raw = sites:get("v" .. ver .. ":cfg")
  local doc = raw and cjson.decode(raw)
  local cfg = EMPTY_CONFIG
  if type(doc) == "table" then
    cfg = {
      allowed = ipaddr.prefixes(doc.origin_allowed_cidrs),
      cdn_id = type(doc.cdn_id) == "string" and doc.cdn_id or "",
      http_challenges = doc.http_challenges or {},
      ip_lists = doc.ip_lists or {}, platform_rules = doc.platform_rules or {},
      platform_protection = type(doc.platform_protection) == "table" and doc.platform_protection or nil,
      cc_sites = type(doc.cc_sites) == "table" and doc.cc_sites or {},
      platform_pages = errorpages.compile_platform(doc.platform_error_pages),
      offline = offline_hosts(doc.offline_hosts),
    }
    local tag_ttl = tonumber(doc.tag_ttl)
    cfg.tag_ttl = (tag_ttl and tag_ttl >= 1) and tag_ttl or _M.DEFAULT_TAG_TTL
    policy.prepare_config(cfg)
  end
  c:set(ck, cfg)
  return cfg
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
  _M.prepare(s, _M.config(ver))
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
-- wildcard on the parent domain (single left-most label). Without a site
-- it also returns the table version it looked in (for config(ver)).
function _M.lookup_host(host)
  local ver = meta:get("version")
  if not ver or not host or host == "" then
    return nil, ver
  end
  local hc = hosts()
  local hit = hc:get(host)
  if hit and hit[1] == ver then
    return _M.site(ver, hit[2])
  end
  local mc = misses()
  if mc:get(host) == ver then
    return nil, ver
  end
  local id = sites:get("v" .. ver .. ":host:" .. host)
  if id then
    hc:set(host, { ver, id })
    return _M.site(ver, id)
  end
  local dot = find(host, ".", 1, true)
  if dot then
    local parent = sub(host, dot + 1)
    local wk = "*." .. parent
    local w = hc:get(wk)
    if w and w[1] == ver then
      return _M.site(ver, w[2])
    end
    id = sites:get("v" .. ver .. ":wild:" .. parent)
    if id then
      hc:set(wk, { ver, id })
      return _M.site(ver, id)
    end
  end
  mc:set(host, ver)
  return nil, ver
end

return _M
