-- edgeweir.store: the site table.
--
-- The agent replaces the whole table atomically through the control API.
-- Entries live in lua_shared_dict "edgeweir_sites" under a version prefix:
--
--   v<N>:site:<id>    JSON of the site
--   v<N>:host:<name>  site id for an exact host name
--   v<N>:wild:<name>  site id for a wildcard suffix ("*.<name>")
--   v<N>:sfx:<name>   site id for a suffix of any depth (".<name>",
--                     domains-v2)
--   v<N>:cfg          JSON of the table settings (origin allow list,
--                     cdn_id, HTTP-01 answers, IP lists, platform rules,
--                     platform protection, ids of the sites with CC, the
--                     lifetime of Cache-Tag index entries, the platform's
--                     error pages, the offline hosts, the node's health
--                     certificate, the site patterns ("~pattern" domains
--                     in precedence order, domains-v2) and the unknown host
--                     handling (unknown-host-v1))
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
--   matched host -> site id found through a suffix or a pattern, a cache
--           of its own: random subdomains under a suffix only churn this
--           one and never evict exact names;
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
local expressions = require("edgeweir.expressions")
local probehealth = require("edgeweir.probehealth")

local _M = {}

local sub, find = string.sub, string.find

local sites = ngx.shared.edgeweir_sites
local meta = ngx.shared.edgeweir_meta

_M.SITE_CACHE_SIZE = 20000
_M.HOST_CACHE_SIZE = 20000
_M.MISS_CACHE_SIZE = 1024
_M.MATCH_CACHE_SIZE = 4096

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

local function matched()
  return new_cache("matched", _M.MATCH_CACHE_SIZE)
end

-- host_pattern is the PCRE2 source of a "~pattern" domain: the whole host
-- (^(?:pattern)$, `$` as \z) with a match limit high enough that a host of
-- at most 253 characters never reaches it for a pattern the console
-- accepts (its shape is bounded there): nginx tries the same pattern in
-- server_name without a limit, and the two must agree.
function _M.host_pattern(pattern)
  local source = expressions.pcre_pattern("^(?:" .. pattern .. ")$")
  return (source:gsub("^%(%*LIMIT_MATCH=%d+%)", "(*LIMIT_MATCH=1000000)", 1))
end

-- MAX_HOST is the longest host name looked up through suffixes and
-- patterns (a DNS name): nginx's guard server takes longer ones first.
_M.MAX_HOST = 253

-- patterns lists the "~pattern" domains of the sites (and of offline hosts
-- with offline = true) by precedence: order, then site id.
local function patterns_of(list)
  local out = {}
  for _, site in ipairs(list) do
    if type(site) == "table" and type(site.domains) == "table" then
      for _, d in ipairs(site.domains) do
        if type(d) == "table" and d.match == "regex" then
          out[#out + 1] = { pattern = d.name, order = tonumber(d.order) or 0, site = site.id }
        end
      end
    end
  end
  table.sort(out, function(a, b)
    if a.order ~= b.order then return a.order < b.order end
    return a.site < b.site
  end)
  return out
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

-- derive_origin (re)computes the derived fields of an origin: its URL, the
-- Host of S3 origins without an explicit one (the default port of the
-- scheme left out, as HTTP clients and SigV4 signers do) and the TLS name
-- (sni, else the host_header without its port, else the address). The
-- origin layer calls it again on copies with an origin rule's overrides.
function _M.derive_origin(o)
  local host = o.address
  if find(host, ":", 1, true) then
    host = "[" .. host .. "]" -- IPv6 literal
  end
  o.url = o.scheme .. "://" .. host .. ":" .. tostring(o.port)
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
  return o
end

-- rule_expressions calls fn with every expression of the site's rules
-- lists (conditions, value expressions of targets, header values and set
-- query parameters) and of its cache rule conditions until fn returns true.
local function rule_expressions(rule_lists, cache_rules, fn)
  for _, list in ipairs(rule_lists) do
    for _, r in ipairs(list or {}) do
      if type(r) == "table" then
        if fn(r.expression) then return true end
        local a = r.action
        if type(a) == "table" then
          if fn(a.target) then return true end
          for _, p in ipairs(type(a.set_query) == "table" and a.set_query or {}) do
            if type(p) == "table" and fn(p.expression) then return true end
          end
        end
      end
    end
  end
  for _, r in ipairs(type(cache_rules) == "table" and cache_rules or {}) do
    if type(r) == "table" and fn(r.condition) then return true end
  end
  return false
end

-- reads_field reports whether any rule (condition or value expression) or
-- cache rule condition of the site's rules list reads a field for which
-- test(field) is true.
local function reads_field(rule_lists, cache_rules, test)
  return rule_expressions(rule_lists, cache_rules, function(e) return expressions.reads(e, test) end)
end

-- field_names returns the set of names after prefix of the fields the
-- site's rules read (cookies, query parameters), nil when there are none.
local function field_names(rule_lists, cache_rules, prefix)
  local names = {}
  rule_expressions(rule_lists, cache_rules, function(e) expressions.names(e, prefix, names); return false end)
  return next(names) and names or nil
end

local function is_geo(field) return field:sub(1, 9) == "ip.geoip." end
local function is_ja4(field) return field == "tls.ja4" end
local function is_field(name) return function(field) return field == name end end
local is_full_uri = is_field("http.request.full_uri")
local is_extension = is_field("http.request.uri.path.extension")
local is_media_type = is_field("http.response.content_type.media_type")
local is_cache_status = is_field("http.response.cache_status")
-- rules-v3 request fields (edgeweir.policy.request), computed together.
local REQUEST_V3 = { ["http.referer"] = true, ["http.user_agent"] = true, ["http.request.version"] = true,
  ["http.request.scheme"] = true, ["http.request.id"] = true, ["http.request.timestamp.sec"] = true, ["edge.server_port"] = true }
local function is_request_v3(field) return REQUEST_V3[field] == true end
local is_peer = is_field("ip.peer")

-- prepare precomputes per-site data used on the hot path. Missing fields
-- (site tables pushed by older agents) take the defaults.
function _M.prepare(s, cfg)
  s._rate_limit_dict = ngx.shared[ratelimit.dict_name(s.id)]
  s._config = cfg or policy.prepare_config({})
  s._rule_groups = policy.prepare_rules(s.rules, s._config.lists)
  s._bulk = policy.prepare_bulk(s.bulk_redirects)
  s._tls_pending = policy.prepare_tls_pending(s.domains)
  -- The listener ports the site is served on (edge-ports-v1); nil: every
  -- listener. The HTTPS redirect's excluded domains, by name.
  if type(s.ports) == "table" and #s.ports > 0 then
    s._ports = {}
    for _, port in ipairs(s.ports) do s._ports[port] = true end
  end
  if type(s.tls) == "table" and type(s.tls.redirect_excluded) == "table" and #s.tls.redirect_excluded > 0 then
    s._redirect_excluded = {}
    for _, name in ipairs(s.tls.redirect_excluded) do s._redirect_excluded[name] = true end
  end
  -- GeoIP is looked up and JA4 computed at the handshake only for sites
  -- whose rules (conditions, value expressions, cache rule conditions,
  -- rate limit keys) read them.
  local rule_lists = { s.rules or {}, s._config.platform_rules or {} }
  s._geo = reads_field(rule_lists, s.cache_rules, is_geo) or nil
  if type(s.protection) ~= "table" then s.protection = nil end
  if type(s.waf) ~= "table" then s.waf = nil end
  if type(s.tls) ~= "table" then s.tls = nil end
  s._ja4 = s.protection ~= nil and s.protection.log_ja4 == true
  if reads_field(rule_lists, s.cache_rules, is_ja4) then s._ja4 = true end
  -- Derived fields are computed per request only for sites whose rules
  -- read them; the response phases run only when some rule is in them.
  s._full_uri = reads_field(rule_lists, s.cache_rules, is_full_uri) or nil
  s._extension = reads_field(rule_lists, s.cache_rules, is_extension) or nil
  s._media_type = reads_field(rule_lists, s.cache_rules, is_media_type) or nil
  s._cache_status = reads_field(rule_lists, s.cache_rules, is_cache_status) or nil
  s._request_v3 = reads_field(rule_lists, s.cache_rules, is_request_v3) or nil
  s._peer = reads_field(rule_lists, s.cache_rules, is_peer) or nil
  s._cookies = field_names(rule_lists, s.cache_rules, "http.request.cookies.")
  s._args = field_names(rule_lists, s.cache_rules, "http.request.uri.args.")
  local platform_groups = s._config.groups or {}
  s._response_rules = (platform_groups["response-transform"] or platform_groups.compression
    or s._rule_groups["response-transform"] or s._rule_groups.compression) ~= nil
  for _, list in ipairs(rule_lists) do
    for _, r in ipairs(list or {}) do
      if type(r) == "table" and type(r.action) == "table" and r.action.key == "tls.ja4" then s._ja4 = true end
    end
  end
  cc.prepare(s)
  -- _guard: Under Attack (platform or site) or CC may challenge requests.
  local pp = s._config.platform_protection
  s._guard = (type(pp) == "table" and pp.under_attack == true)
    or (s.protection ~= nil and (s.protection.under_attack == true or s._cc ~= nil)) or false
  s.cache_generation = tostring(s.cache_generation or "0")
  s.tls_verify = s.tls_verify ~= false
  s.websocket = s.websocket ~= false
  -- HTTP/2 towards the origins, gRPC proxied end to end (only with it).
  s.origin_http2 = s.origin_http2 == true
  s.grpc = s.grpc == true and s.origin_http2
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
  -- Settings of proto v0.24.0 (feature site-content-v1): PURGE, X-Cache,
  -- maintenance (allowed addresses and the compiled page), charset, the
  -- body limit and origin tries.
  s.purge = s.purge == true
  s.hide_x_cache = s.hide_x_cache == true
  s.no_status_retry = s.no_status_retry == true
  s.tries = tonumber(s.tries) or 3
  if type(s.maintenance) == "table" then
    local cidrs = s.maintenance.allow_cidrs
    s._maintenance_allow = type(cidrs) == "table" and #cidrs > 0 and expressions.ip_set(cidrs) or nil
    local page = s.maintenance.template
    s._maintenance_page = type(page) == "string" and page ~= "" and errorpages.compile(page) or nil
  else
    s.maintenance = nil
  end
  if type(s.charset) ~= "table" or type(s.charset.name) ~= "string" then s.charset = nil end
  s.health = with_defaults(s.health, DEFAULT_HEALTH)
  s.conn = with_defaults(s.conn, DEFAULT_CONN)
  s.cache_key = cachekey.prepare(s.cache_key)
  -- Origin pools by group ("" is the default group; origin rules choose
  -- the others): primaries and backups with their total weights.
  local pools = {}
  for _, o in ipairs(s.origins or {}) do
    local w = tonumber(o.weight) or 1
    if w < 1 then
      w = 1
    end
    o.weight = w
    _M.derive_origin(o)
    local group = is_nonempty_string(o.group) and o.group or ""
    local pool = pools[group]
    if not pool then
      pool = { primaries = {}, backups = {}, pw = 0, bw = 0 }
      pools[group] = pool
    end
    if o.backup == true then
      pool.backups[#pool.backups + 1] = o
      pool.bw = pool.bw + w
    else
      pool.primaries[#pool.primaries + 1] = o
      pool.pw = pool.pw + w
    end
  end
  local default = pools[""] or { primaries = {}, backups = {}, pw = 0, bw = 0 }
  s._pools = pools
  s._primaries, s._backups, s._pw, s._bw = default.primaries, default.backups, default.pw, default.bw
  s._browser_ttl = nil
  if type(s.cache_rules) == "table" then
    for i = 1, #s.cache_rules do
      rules.prepare(s.cache_rules[i], s._config.lists)
      -- The edge header filter looks for a browser TTL only on such sites.
      if s.cache_rules[i].browser_ttl > 0 then s._browser_ttl = true end
    end
  else
    s.cache_rules = nil
  end
  return s
end

-- check_site compiles what prepare compiles from a pushed site (rules,
-- cache rule conditions, the redirect table) and raises an error when
-- something does not compile.
local function check_site(site, lists)
  policy.prepare_rules(site.rules, lists)
  policy.prepare_bulk(site.bulk_redirects)
  for _, r in ipairs(type(site.cache_rules) == "table" and site.cache_rules or {}) do
    if type(r) == "table" and type(r.condition) == "table" then
      expressions.compile(r.condition, lists)
    end
  end
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
  -- Site patterns in precedence order; each compiles (checked here so a
  -- pattern PCRE2 refuses rejects the table instead of every request).
  local patterns = patterns_of(list)
  for _, p in ipairs(patterns) do
    local _, _, perr = ngx.re.find("", _M.host_pattern(p.pattern), "jo")
    if perr then meta:delete("lock"); return nil, "invalid domain pattern of site " .. tostring(p.site), 400 end
  end
  if #patterns > 0 then cfg.patterns = patterns end
  if type(doc.unknown_hosts) == "table" then cfg.unknown_hosts = doc.unknown_hosts end
  -- The trusted proxies of the client address setting (client-ip-v1):
  -- never banned, not counted per address by CC.
  local ca = doc.client_address
  if type(ca) == "table" and type(ca.trusted_cidrs) == "table" and #ca.trusted_cidrs > 0 then cfg.trusted_proxies = ca.trusted_cidrs end
  if doc.health_certificate ~= nil and doc.health_certificate ~= cjson.null then
    cfg.health_certificate = probehealth.material(doc)
    if not cfg.health_certificate then
      ngx.log(ngx.WARN, "edgeweir: invalid health_certificate in the site table; ignored")
    end
  end
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
      local ok = pcall(check_site, site, compiled_cfg.lists)
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
      local kind = (d.match == "suffix" and "sfx:") or (d.wildcard == true and "wild:") or "host:"
      -- Patterns live in cfg.patterns.
      if d.match ~= "regex" and not put(kind .. d.name, site.id) then
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

-- offline_hosts indexes the offline hosts of a table: exact names,
-- wildcard suffixes and suffixes of any depth to their reason (disabled),
-- and the patterns (compiled sources) in order.
local function offline_hosts(list)
  if type(list) ~= "table" or #list == 0 then
    return nil
  end
  local out = { exact = {}, wild = {}, suffix = {}, patterns = {} }
  for _, h in ipairs(list) do
    if type(h) == "table" and type(h.name) == "string" and h.reason == "disabled" then
      if h.match == "regex" then
        out.patterns[#out.patterns + 1] = { source = _M.host_pattern(h.name), reason = h.reason }
      else
        local t = (h.match == "suffix" and out.suffix) or (h.wildcard == true and out.wild) or out.exact
        if not t[h.name] then
          t[h.name] = h.reason
        end
      end
    end
  end
  return out
end

-- unknown_hosts validates the unknown host handling of a table (nil: the
-- defaults): { unknown_host, ip_access = "page" | "close" | "site",
-- default_site_id, default_certificate, scan_threshold, scan_ban_seconds }.
local ACTIONS = { page = true, close = true, site = true }
local function unknown_hosts(u)
  if type(u) ~= "table" then return nil end
  local out = {
    unknown_host = ACTIONS[u.unknown_host] and u.unknown_host or "page",
    ip_access = ACTIONS[u.ip_access] and u.ip_access or "page",
    default_site_id = type(u.default_site_id) == "string" and u.default_site_id ~= "" and u.default_site_id or nil,
    default_certificate = u.default_certificate == true,
    scan_threshold = math.floor(tonumber(u.scan_threshold) or 0),
    scan_ban_seconds = math.floor(tonumber(u.scan_ban_seconds) or 0),
  }
  if out.scan_threshold < 1 or out.scan_ban_seconds < 1 then
    out.scan_threshold, out.scan_ban_seconds = 0, 0
  end
  return out
end

-- config returns the table-wide settings of the current table:
-- { allowed = parsed origin allow list (edgeweir.ipaddr.prefixes),
--   cdn_id = CDN-Loop identifier or "", tag_ttl = lifetime of Cache-Tag
--   index entries, platform_pages = compiled platform error pages,
--   offline = offline hosts (nil without any), health_certificate = the
--   node's health certificate (nil without one) }.
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
      health_certificate = probehealth.material(doc),
      trusted = type(doc.trusted_proxies) == "table" and #doc.trusted_proxies > 0 and expressions.ip_set(doc.trusted_proxies) or nil,
      unknown = unknown_hosts(doc.unknown_hosts),
    }
    if type(doc.patterns) == "table" and #doc.patterns > 0 then
      cfg.patterns = {}
      for i, p in ipairs(doc.patterns) do
        cfg.patterns[i] = { source = _M.host_pattern(p.pattern), site = p.site }
      end
    end
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
-- wildcard on the parent domain (single left-most label), then the longest
-- suffix of any depth, then the first site pattern that matches the whole
-- host (domains-v2). Returns the site (nil without one), the table version
-- it looked in (for config(ver)) and how the site was found: "exact",
-- "wildcard" or "match" (a suffix or a pattern: TLS completes only where
-- the site's certificate covers the host, edgeweir.tls).
-- ip_host tells whether a host names no host: "_" (no Host), an IPv4
-- address or an IPv6 address in brackets (node IP access).
local function ip_host(host)
  return host == "_" or find(host, "^%[") ~= nil or find(host, "^%d+%.%d+%.%d+%.%d+$") ~= nil
end

function _M.lookup_host(host)
  local ver = meta:get("version")
  if not ver or not host or host == "" then
    return nil, ver
  end
  local hc = hosts()
  local hit = hc:get(host)
  if hit and hit[1] == ver then
    return _M.site(ver, hit[2]), ver, "exact"
  end
  local mc = misses()
  if mc:get(host) == ver then
    return nil, ver
  end
  local id = sites:get("v" .. ver .. ":host:" .. host)
  if id then
    hc:set(host, { ver, id })
    return _M.site(ver, id), ver, "exact"
  end
  -- Node IP access (an IP literal, "_") is matched by exact names only: no
  -- wildcard, suffix or pattern takes it.
  if ip_host(host) then
    return nil, ver
  end
  local dot = find(host, ".", 1, true)
  -- A host that starts with a dot has no parent (as nginx's server names,
  -- Go's HostMatcher and the console see it): only patterns can match it.
  if dot == 1 then
    dot = nil
  end
  if dot then
    local parent = sub(host, dot + 1)
    local wk = "*." .. parent
    local w = hc:get(wk)
    if w and w[1] == ver then
      return _M.site(ver, w[2]), ver, "wildcard"
    end
    id = sites:get("v" .. ver .. ":wild:" .. parent)
    if id then
      hc:set(wk, { ver, id })
      return _M.site(ver, id), ver, "wildcard"
    end
  end
  local pc = matched()
  local m = pc:get(host)
  if m and m[1] == ver then
    return _M.site(ver, m[2]), ver, "match"
  end
  -- The longest suffix first: drop one label at a time.
  while dot do
    id = sites:get("v" .. ver .. ":sfx:" .. sub(host, dot + 1))
    if id then
      pc:set(host, { ver, id })
      return _M.site(ver, id), ver, "match"
    end
    dot = find(host, ".", dot + 1, true)
  end
  local patterns = #host <= _M.MAX_HOST and _M.config(ver).patterns
  if patterns then
    for i = 1, #patterns do
      local p = patterns[i]
      if ngx.re.find(host, p.source, "jo") then
        pc:set(host, { ver, p.site })
        return _M.site(ver, p.site), ver, "match"
      end
    end
  end
  mc:set(host, ver)
  return nil, ver
end

-- serves_port tells whether site is served on a listener port (a number
-- or the decimal $server_port): sites without ports (configurations
-- without edge-ports-v1) on every listener.
function _M.serves_port(site, port)
  local ports = site._ports
  if not ports then return true end
  return ports[tonumber(port) or -1] == true
end

-- trusted_proxy tells whether addr is a trusted proxy of the client
-- address setting of the table the site came from (client-ip-v1).
function _M.trusted_proxy(site, addr)
  local m = site._config and site._config.trusted
  return m ~= nil and addr ~= nil and m(addr) == true
end

return _M
