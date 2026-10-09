-- edgeweir.access: a site's access control (Site.access_control, proto
-- v0.28.0, feature access-control-v1, ADR-0039).
--
-- The decisions are a port of the console's packages/rule-engine
-- access-control.ts and pass its vectors (test/lua/access_vectors.json):
-- host forms ("a.com", "*.a.com" one label below, ".a.com" any depth below,
-- "*" any host), the host of a Referer, origin forms and request Origins
-- (scheme, lowercase host and port; the default port left out; "*." one
-- label), path scopes (prefixes of the normalized path, $uri with a signed
-- URL's signature removed), user agent rules (the rule engine's wildcard,
-- edgeweir.expressions), hotlink, geo, the Access-Control-Allow-Origin of
-- an Origin and WebSocket origins.
--
-- prepare(site) compiles a site's settings when the site table is
-- installed (site._access, nil without access control; the IP lists are
-- the table's matchers, cfg.lists) and the idle timeout of its upgraded
-- connections (site._ws_idle_ms, read by the origin layer).
--
-- The edge layer's access phase, in the order of ADR-0039 §1:
--   site_allowed(site, addr) (edgeweir.router, before the bans): ip.src is
--     on one of the site's allow lists. Such clients skip the site's bans,
--     CC bans, Under Attack and CC challenges, and check's steps but CORS.
--   check(site, values, platform_allowed, site_allowed) (edgeweir.policy,
--     after the platform lists, before access authentication): the site's
--     block lists (403 ip-blocked, not for platform-allowed clients), geo
--     (403 geo-denied; a failing GeoIP lookup raises, so the router answers
--     503 policy-unavailable as for rules), CORS preflights answered here
--     (204, or 403 cors-origin-denied), hotlink (403 hotlink-denied or a 302
--     to the site's target) and user agents (403 ua-denied). It returns nil
--     or a result of edgeweir.policy ({ status, code } or { respond }). The
--     caller leaves out the local listeners and HTTP-01 requests for the
--     origin.
--   websocket_allowed(site, origin) (edgeweir.router, after the WebSocket
--     switch): 403 websocket-origin-denied otherwise.
-- The header filter (edgeweir.router, after its own steps and before the
-- response phases, so rules win; also nginx's own error pages):
--   response_headers(site, h, path): CORS response headers (a preflight
--     the origin answered gets those of the edge's own preflight answer) and
--     the security headers, on cache hits, origin responses and the node's
--     own answers alike.
local expressions = require("edgeweir.expressions")

local _M = {}

local byte, find, gmatch, lower, match, sub = string.byte, string.find, string.gmatch, string.lower, string.match, string.sub
local concat = table.concat
local ipairs, pairs, tonumber, tostring, type = ipairs, pairs, tonumber, tostring, type

-- Results of check.
local IP_BLOCKED = { status = 403, code = "ip-blocked" }
local GEO_DENIED = { status = 403, code = "geo-denied" }
local CORS_DENIED = { status = 403, code = "cors-origin-denied" }
local HOTLINK_DENIED = { status = 403, code = "hotlink-denied" }
local UA_DENIED = { status = 403, code = "ua-denied" }

_M.DEFAULT_WEBSOCKET_IDLE = 3600
_M.PREFLIGHT_VARY = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"

-- split splits s at every plain sep, empty fields kept (JavaScript's
-- String.prototype.split with a string).
local function split(s, sep)
  local out, start = {}, 1
  while true do
    local i, j = find(s, sep, start, true)
    if not i then
      out[#out + 1] = sub(s, start)
      return out
    end
    out[#out + 1] = sub(s, start, i - 1)
    start = j + 1
  end
end

-- is_ipv4 reports whether s is a dotted IPv4 address without leading zeros.
local function is_ipv4(s)
  local parts = { match(s, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
  if #parts ~= 4 then return false end
  for i = 1, 4 do
    local p = parts[i]
    if #p > 3 or (#p > 1 and byte(p, 1) == 48) or tonumber(p) > 255 then return false end
  end
  return true
end

-- valid_label: [a-z0-9_] at both ends, [a-z0-9_-] between, 1-63 bytes.
local function valid_label(l)
  local n = #l
  return n >= 1 and n <= 63 and not find(l, "[^a-z0-9_%-]") and byte(l, 1) ~= 45 and byte(l, n) ~= 45
end

-- valid_host_name: a lowercase host name (labels of [a-z0-9_-], at most 253
-- bytes) or an IPv4 address.
function _M.valid_host_name(host)
  if type(host) ~= "string" or #host == 0 or #host > 253 then return false end
  if is_ipv4(host) then return true end
  for _, label in ipairs(split(host, ".")) do
    if not valid_label(label) then return false end
  end
  return true
end
local valid_host_name = _M.valid_host_name

-- valid_ipv6 reports whether text is an IPv6 address as written between
-- brackets in a URL (lowercase, no zone).
local function valid_ipv6(text)
  if find(text, "[^0-9a-f:.]") or not find(text, ":", 1, true) then return false end
  local v4 = find(text, ".", 1, true) ~= nil
  local parts = split(text, "::")
  if #parts > 2 then return false end
  local function groups(s) return s == "" and {} or split(s, ":") end
  local all = groups(parts[1])
  if #parts == 2 then
    for _, g in ipairs(groups(parts[2])) do all[#all + 1] = g end
  end
  local count = #all
  for i, g in ipairs(all) do
    if v4 and i == #all then
      if not is_ipv4(g) then return false end
      count = count + 1
    elseif not match(g, "^[0-9a-f][0-9a-f]?[0-9a-f]?[0-9a-f]?$") then
      return false
    end
  end
  if #parts == 2 then return count <= 7 end
  return count == 8
end

local function trim(s)
  return (match(s, "^%s*(.-)%s*$"))
end

-- normalize_host_form returns a hotlink source as stored ("a.com",
-- "*.a.com", ".a.com" or "*", lowercase, one trailing dot removed), or nil.
function _M.normalize_host_form(text)
  local form = lower(trim(text))
  if form == "*" then return form end
  if #form > 1 and sub(form, -1) == "." then form = sub(form, 1, -2) end
  if sub(form, 1, 2) == "*." then
    local rest = sub(form, 3)
    return (valid_host_name(rest) and not is_ipv4(rest)) and form or nil
  end
  if sub(form, 1, 1) == "." then
    local rest = sub(form, 2)
    return (valid_host_name(rest) and not is_ipv4(rest)) and form or nil
  end
  return valid_host_name(form) and form or nil
end

-- host_form_matches tells whether a stored host form matches a host
-- (lowercase, no trailing dot).
function _M.host_form_matches(form, host)
  if form == "*" then return true end
  if sub(form, 1, 2) == "*." then
    local rest = sub(form, 2)
    if #host <= #rest or sub(host, -#rest) ~= rest then return false end
    return not find(sub(host, 1, #host - #rest), ".", 1, true)
  end
  if sub(form, 1, 1) == "." then
    return #host > #form and sub(host, -#form) == form
  end
  return host == form
end
local host_form_matches = _M.host_form_matches

-- referer_host returns the host of a Referer (or Origin) value: an http(s)
-- URL's host, lowercase, without user information, port and one trailing
-- dot, IPv6 without brackets; nil when the value is no such URL or its host
-- is invalid.
function _M.referer_host(value)
  if type(value) ~= "string" then return nil end
  local authority = match(value, "^[Hh][Tt][Tt][Pp][Ss]?://([^/?#]*)")
  if not authority then return nil end
  authority = match(authority, "^.*@(.*)$") or authority
  local host, port
  if sub(authority, 1, 1) == "[" then
    local close = find(authority, "]", 1, true)
    if not close then return nil end
    host = lower(sub(authority, 2, close - 1))
    local rest = sub(authority, close + 1)
    if rest ~= "" and sub(rest, 1, 1) ~= ":" then return nil end
    port = sub(rest, 2)
    if not valid_ipv6(host) then return nil end
  else
    local colon = find(authority, ":", 1, true)
    host = lower(colon and sub(authority, 1, colon - 1) or authority)
    port = colon and sub(authority, colon + 1) or ""
    if sub(host, -1) == "." then host = sub(host, 1, -2) end
    if not valid_host_name(host) then return nil end
  end
  if port ~= "" and (not match(port, "^%d%d?%d?%d?%d?$") or tonumber(port) > 65535) then return nil end
  return host
end

local DEFAULT_PORTS = { http = "80", https = "443" }

-- parse_origin splits an origin ("scheme://host[:port]", http or https,
-- nothing else) into { scheme, host, port } (lowercase, the default port
-- ""), or nil. wildcard: the host may start with "*." (a form).
local function parse_origin(text, wildcard)
  if type(text) ~= "string" then return nil end
  local scheme, authority = match(text, "^([Hh][Tt][Tt][Pp][Ss]?)://([^/?#@%s]+)$")
  if not scheme then return nil end
  scheme = lower(scheme)
  local colon = match(authority, "^.*():")
  local host = lower(colon and sub(authority, 1, colon - 1) or authority)
  local port = colon and sub(authority, colon + 1) or ""
  if port ~= "" then
    if not match(port, "^[1-9]%d?%d?%d?%d?$") or tonumber(port) > 65535 then return nil end
    if port == DEFAULT_PORTS[scheme] then port = "" end
  end
  if wildcard and sub(host, 1, 2) == "*." then
    local rest = sub(host, 3)
    if not valid_host_name(rest) or is_ipv4(rest) then return nil end
  elseif not valid_host_name(host) then
    return nil
  end
  return { scheme = scheme, host = host, port = port }
end

local function format_origin(o)
  return o.scheme .. "://" .. o.host .. (o.port ~= "" and (":" .. o.port) or "")
end

-- normalize_origin_form returns a CORS or WebSocket origin as stored, "*"
-- alone only when star; nil when invalid.
function _M.normalize_origin_form(text, star)
  local t = trim(text)
  if t == "*" then return star and "*" or nil end
  local o = parse_origin(t, true)
  return o and format_origin(o) or nil
end

-- normalize_origin normalizes a request's Origin like the forms; nil when
-- it is no such origin ("null" included).
function _M.normalize_origin(value)
  local o = parse_origin(value, false)
  return o and format_origin(o) or nil
end

-- origin_form_matches tells whether an origin form (not "*") matches a
-- normalized origin.
function _M.origin_form_matches(form, origin)
  local f, o = parse_origin(form, true), parse_origin(origin, false)
  if not f or not o or f.scheme ~= o.scheme or f.port ~= o.port then return false end
  if sub(f.host, 1, 2) == "*." then return host_form_matches(f.host, o.host) end
  return f.host == o.host
end

local function starts_with_any(path, prefixes)
  for i = 1, #prefixes do
    local p = prefixes[i]
    if sub(path, 1, #p) == p then return true end
  end
  return false
end

-- path_in_scope tells whether path is under a prefix (none: every path) and
-- under no excluded one.
function _M.path_in_scope(path, prefixes, excluded)
  if prefixes and #prefixes > 0 and not starts_with_any(path, prefixes) then return false end
  return not (excluded and starts_with_any(path, excluded))
end
local path_in_scope = _M.path_in_scope

-- valid_user_agent_pattern: "" or 1-512 printable ASCII bytes forming a
-- wildcard (a backslash only before "*" or "\", at most 8 "*").
function _M.valid_user_agent_pattern(pattern)
  if pattern == "" then return true end
  if #pattern > 512 or find(pattern, "[^\32-\126]") then return false end
  local stars, i = 0, 1
  while i <= #pattern do
    local c = sub(pattern, i, i)
    if c == "\\" then
      local n = sub(pattern, i + 1, i + 1)
      if n ~= "*" and n ~= "\\" then return false end
      i = i + 2
    else
      if c == "*" then stars = stars + 1 end
      i = i + 1
    end
  end
  return stars <= 8
end

local function empty_user_agent(ua) return ua == "" end

-- compile_user_agents compiles user agent rules ({ pattern, allow }) into
-- { allow, match } in order.
function _M.compile_user_agents(list)
  local out = {}
  for i, r in ipairs(list or {}) do
    local pattern = type(r.pattern) == "string" and r.pattern or ""
    out[i] = { allow = r.allow == true, match = pattern == "" and empty_user_agent or expressions.wildcard_matcher(pattern) }
  end
  return out
end

-- user_agent_decision: an allow rule matching passes; else a deny rule
-- matching denies; else the request passes. ua: the User-Agent (several
-- headers joined with ", "), "" when missing.
function _M.user_agent_decision(rules, ua)
  for i = 1, #rules do
    if rules[i].allow and rules[i].match(ua) then return "pass" end
  end
  for i = 1, #rules do
    if not rules[i].allow and rules[i].match(ua) then return "deny" end
  end
  return "pass"
end

local function set_of(list)
  if type(list) ~= "table" or #list == 0 then return nil end
  local out = {}
  for _, v in ipairs(list) do out[v] = true end
  return out
end

local function list_of(v)
  return type(v) == "table" and v or {}
end

-- host_set compiles host forms: exact names in a set, the others in order.
local function host_set(forms)
  local set = { exact = {}, wild = {} }
  for _, f in ipairs(list_of(forms)) do
    if f == "*" or sub(f, 1, 1) == "." or sub(f, 1, 2) == "*." then
      set.wild[#set.wild + 1] = f
    else
      set.exact[f] = true
    end
  end
  return set
end

local function host_in(set, host)
  if set.exact[host] then return true end
  local wild = set.wild
  for i = 1, #wild do
    if host_form_matches(wild[i], host) then return true end
  end
  return false
end

-- compile_hotlink compiles a site's hotlink settings (snake_case, as the
-- site table has them).
function _M.compile_hotlink(h)
  local c = {
    allow_empty = h.allow_empty == true, allow_site_domains = h.allow_site_domains == true,
    check_origin = h.check_origin == true, allowed = host_set(h.allowed), denied = host_set(h.denied),
    extensions = set_of(h.extensions), prefixes = list_of(h.path_prefixes), excludes = list_of(h.exclude_path_prefixes),
  }
  c.everything = c.extensions == nil and #c.prefixes == 0
  if type(h.redirect_url) == "string" and h.redirect_url ~= "" then
    c.redirect = h.redirect_url
    -- Requests for the target itself are not checked (no loop).
    if sub(c.redirect, 1, 1) == "/" then c.redirect_path = match(c.redirect, "^[^?#]*") end
  end
  return c
end

-- hotlink_decision returns "skip" for requests out of scope, else "pass"
-- or "deny". extension: http.request.uri.path.extension; site_host(host)
-- tells whether the node resolves host to the site.
function _M.hotlink_decision(c, path, extension, referer, origin, site_host)
  local selected = c.everything or (c.extensions ~= nil and c.extensions[extension] == true) or starts_with_any(path, c.prefixes)
  if not selected or starts_with_any(path, c.excludes) then return "skip" end
  if c.redirect_path and path == c.redirect_path then return "skip" end
  local values = {}
  if referer and referer ~= "" then values[#values + 1] = referer end
  if c.check_origin and origin and origin ~= "" then values[#values + 1] = origin end
  if #values == 0 then return c.allow_empty and "pass" or "deny" end
  for i = 1, #values do
    local host = _M.referer_host(values[i])
    if not host or host_in(c.denied, host) then return "deny" end
    if not host_in(c.allowed, host) and not (c.allow_site_domains and site_host(host)) then return "deny" end
  end
  return "pass"
end

-- compile_geo compiles a site's geo settings: subdivisions compare ASCII
-- case-insensitively, ASNs as numbers.
function _M.compile_geo(g)
  local c = {
    allow_only = g.allow_only == true, countries = set_of(g.countries) or {}, subdivisions = {}, asns = {},
    prefixes = list_of(g.path_prefixes), excepts = list_of(g.except_path_prefixes),
  }
  local entries = #list_of(g.countries)
  for _, s in ipairs(list_of(g.subdivisions)) do
    c.subdivisions[lower(s)] = true
    entries = entries + 1
  end
  for _, n in ipairs(list_of(g.asns)) do
    if tonumber(n) then
      c.asns[tonumber(n)] = true
      entries = entries + 1
    end
  end
  -- Without entries nothing matches: no GeoIP lookup is needed.
  c.empty = entries == 0
  return c
end

-- geo_matches tells whether a GeoIP record ({ country, subdivision, asnum };
-- country "" without a record) matches any of the lists.
function _M.geo_matches(c, geo)
  local country, subdivision, asnum = geo.country or "", geo.subdivision or "", tonumber(geo.asnum) or 0
  if country ~= "" and c.countries[country] then return true end
  if country ~= "" and subdivision ~= "" and c.subdivisions[lower(country .. "-" .. subdivision)] then return true end
  return asnum > 0 and c.asns[asnum] == true
end

-- geo_decision is "pass" or "deny" for a request in scope.
function _M.geo_decision(c, geo)
  return _M.geo_matches(c, geo) == c.allow_only and "pass" or "deny"
end

-- origin_set compiles origin forms: normalized exact origins in a set,
-- "*." forms in order, "*" a flag.
local function origin_set(forms)
  local set = { exact = {}, wild = {}, star = false, any = false }
  for _, f in ipairs(list_of(forms)) do
    if f == "*" then
      set.star = true
    else
      local o = parse_origin(f, true)
      if o then
        set.any = true
        if sub(o.host, 1, 2) == "*." then
          set.wild[#set.wild + 1] = o
        else
          set.exact[format_origin(o)] = true
        end
      end
    end
  end
  return set
end

-- origin_allowed tells whether a request's Origin matches a form of set
-- ("*" aside).
local function origin_allowed(set, value)
  if not set.any or type(value) ~= "string" or value == "" then return false end
  local o = parse_origin(value, false)
  if not o then return false end
  if set.exact[format_origin(o)] then return true end
  local wild = set.wild
  for i = 1, #wild do
    local w = wild[i]
    if w.scheme == o.scheme and w.port == o.port and host_form_matches(w.host, o.host) then return true end
  end
  return false
end

local function joined(list)
  list = list_of(list)
  return #list > 0 and concat(list, ", ") or nil
end

-- compile_cors compiles a site's CORS settings.
function _M.compile_cors(c)
  return {
    origins = origin_set(c.allowed_origins), credentials = c.allow_credentials == true,
    methods = concat(list_of(c.allowed_methods), ", "), headers = joined(c.allowed_headers),
    echo = c.echo_request_headers == true, exposed = joined(c.exposed_headers),
    max_age = tostring(tonumber(c.max_age_seconds) or 0), to_origin = c.preflight_to_origin == true,
    keep = c.keep_origin_headers == true, prefixes = list_of(c.path_prefixes),
  }
end

-- cors_allow_origin returns the Access-Control-Allow-Origin of a request's
-- Origin: "*" for "*" without credentials, the Origin itself when a form
-- matches it, nil when it is not allowed (or missing).
function _M.cors_allow_origin(c, origin)
  if type(origin) ~= "string" or origin == "" then return nil end
  if not c.credentials and c.origins.star then return "*" end
  return origin_allowed(c.origins, origin) and origin or nil
end

-- websocket_origin_allowed tells whether a WebSocket upgrade's Origin
-- passes compiled origins (nil: every origin).
function _M.websocket_origin_allowed(origins, origin)
  if origins == nil then return true end
  return origin_allowed(origins, origin)
end

-- compile_websocket compiles a list of WebSocket origins (empty: nil,
-- every origin).
function _M.compile_websocket(w)
  local origins = list_of(w.origins)
  return { origins = #origins > 0 and origin_set(origins) or nil }
end

local function compile_security(s)
  local out = {
    nosniff = s.nosniff == true, hide_server = s.hide_server == true, remove_powered_by = s.remove_powered_by == true,
  }
  for _, k in ipairs({ "frame_options", "referrer_policy", "permissions_policy" }) do
    if type(s[k]) == "string" and s[k] ~= "" then out[k] = s[k] end
  end
  return out
end

local function matchers(ids, lists)
  ids = list_of(ids)
  if #ids == 0 then return nil end
  local out = {}
  for i, id in ipairs(ids) do
    out[i] = assert(lists[id], "unknown IP list")
  end
  return out
end

-- compile compiles a site's access control; lists are the site table's IP
-- list matchers by id (edgeweir.policy.prepare_config). It raises on a list
-- the table does not have.
function _M.compile(a, lists)
  local c = { block = matchers(a.block_list_ids, lists), allow = matchers(a.allow_list_ids, lists) }
  if type(a.hotlink) == "table" then c.hotlink = _M.compile_hotlink(a.hotlink) end
  if type(a.user_agents) == "table" then
    local u = a.user_agents
    c.user_agents = { rules = _M.compile_user_agents(u.rules), prefixes = list_of(u.path_prefixes), excludes = list_of(u.exclude_path_prefixes) }
  end
  if type(a.cors) == "table" then c.cors = _M.compile_cors(a.cors) end
  if type(a.geo) == "table" then c.geo = _M.compile_geo(a.geo) end
  if type(a.websocket) == "table" then c.websocket = _M.compile_websocket(a.websocket) end
  if type(a.security_headers) == "table" then c.security = compile_security(a.security_headers) end
  return c
end

-- prepare compiles a site's access control (see the module comment).
function _M.prepare(site)
  site._access, site._ws_idle_ms = nil, nil
  local a = site.access_control
  if type(a) ~= "table" then
    site.access_control = nil
    return
  end
  site._access = _M.compile(a, site._config and site._config.lists or {})
  if type(a.websocket) == "table" then
    local idle = tonumber(a.websocket.idle_timeout_seconds) or 0
    if idle <= 0 then idle = _M.DEFAULT_WEBSOCKET_IDLE end
    site._ws_idle_ms = idle * 1000
  end
end

-- site_allowed tells whether addr (ip.src) is on one of the site's allow
-- lists.
function _M.site_allowed(site, addr)
  local a = site._access
  local allow = a and a.allow
  if not allow or not addr then return false end
  for i = 1, #allow do
    if allow[i](addr) then return true end
  end
  return false
end

-- geo_record returns the client's GeoIP record: the rules' when they read
-- GeoIP (edgeweir.policy.request), else a lookup; it raises when GeoIP is
-- unavailable.
local function geo_record(values, addr)
  if values["ip.geoip.country"] ~= nil then
    return { country = values["ip.geoip.country"], subdivision = values["ip.geoip.subdivision"], asnum = values["ip.geoip.asnum"] }
  end
  return assert(require("edgeweir.geoip").lookup(addr), "GeoIP unavailable")
end

-- site_host returns whether the node resolves a host to site (exact,
-- wildcard, suffix and pattern domains alike).
local function site_host(site)
  return function(host)
    local s = require("edgeweir.store").lookup_host(host)
    return s ~= nil and s.id == site.id
  end
end

-- redirect answers a hotlink with a 302 to the site's target.
local function redirect(url)
  return function()
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Edgeweir-Error"] = "hotlink-denied"
    return ngx.redirect(url, 302)
  end
end

-- set_preflight sets the preflight headers of an allowed Origin on h
-- (allow: its Access-Control-Allow-Origin): credentials, the methods, the
-- request headers (the list, or with echo the request's
-- Access-Control-Request-Headers; neither: none) and the max age.
local function set_preflight(c, h, allow, requested)
  h["Access-Control-Allow-Origin"] = allow
  if c.credentials then h["Access-Control-Allow-Credentials"] = "true" end
  h["Access-Control-Allow-Methods"] = c.methods
  local headers = c.headers
  if c.echo then
    headers = requested ~= nil and requested ~= "" and requested or nil
  end
  if headers then h["Access-Control-Allow-Headers"] = headers end
  h["Access-Control-Max-Age"] = c.max_age
end

-- preflight answers a CORS preflight with 204 (allow: its
-- Access-Control-Allow-Origin; request_headers: its
-- Access-Control-Request-Headers). The response is not cached anywhere and
-- keeps these headers in the header filter.
function _M.preflight(c, allow, request_headers)
  ngx.ctx.edgeweir_preflight = true
  local h = ngx.header
  set_preflight(c, h, allow, request_headers)
  h["Vary"] = _M.PREFLIGHT_VARY
  h["Cache-Control"] = "no-store"
  return ngx.exit(ngx.HTTP_NO_CONTENT)
end

-- check runs the access phase's steps 4-8 (see the module comment). values
-- are edgeweir.policy's request values (ip.src, the normalized path and the
-- request headers).
function _M.check(site, values, platform_allowed, site_allowed)
  local a = site._access
  local path = values["http.request.uri.path"] or ""
  if not site_allowed then
    local block = a.block
    if block and not platform_allowed then
      local addr = values["ip.src"]
      for i = 1, #block do
        if block[i](addr) then return IP_BLOCKED end
      end
    end
    local geo = a.geo
    if geo and path_in_scope(path, geo.prefixes, geo.excepts) then
      local record = geo.empty and {} or geo_record(values, values["ip.src"])
      if _M.geo_decision(geo, record) == "deny" then return GEO_DENIED end
    end
  end
  local var = ngx.var
  local cors = a.cors
  if cors and not cors.to_origin and ngx.req.get_method() == "OPTIONS" then
    local origin, method = var.http_origin, var.http_access_control_request_method
    if origin and origin ~= "" and method and method ~= "" and path_in_scope(path, cors.prefixes) then
      local allow = _M.cors_allow_origin(cors, origin)
      if not allow then return CORS_DENIED end
      local requested = values["http.request.headers.access-control-request-headers"]
      return { respond = function() return _M.preflight(cors, allow, requested) end }
    end
  end
  if site_allowed then return nil end
  local hotlink = a.hotlink
  if hotlink then
    local d = _M.hotlink_decision(hotlink, path, expressions.path_extension(path),
      values["http.request.headers.referer"], var.http_origin, site_host(site))
    if d == "deny" then
      if hotlink.redirect then return { respond = redirect(hotlink.redirect) } end
      return HOTLINK_DENIED
    end
  end
  local ua = a.user_agents
  if ua and path_in_scope(path, ua.prefixes, ua.excludes)
    and _M.user_agent_decision(ua.rules, values["http.request.headers.user-agent"] or "") == "deny" then
    return UA_DENIED
  end
  return nil
end

-- websocket_allowed tells whether a WebSocket upgrade's Origin passes the
-- site's WebSocket origins (none set: every origin).
function _M.websocket_allowed(site, origin)
  local ws = site._access and site._access.websocket
  return ws == nil or _M.websocket_origin_allowed(ws.origins, origin or "")
end

local ORIGIN_VARY = { "Origin" }
local PREFLIGHT_VARY_NAMES = { "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers" }

-- vary_with returns a Vary value (string or lines) with the names it does
-- not name yet added (compared case-insensitively), unchanged when it names
-- them all or "*".
function _M.vary_with(vary, names)
  local value = type(vary) == "table" and concat(vary, ", ") or vary
  local present = {}
  for token in gmatch(value or "", "[^,]+") do
    local t = lower(trim(token))
    if t == "*" then return vary end
    present[t] = true
  end
  local added = {}
  for _, n in ipairs(names) do
    if not present[lower(n)] then added[#added + 1] = n end
  end
  if #added == 0 then return vary end
  local tail = concat(added, ", ")
  if value == nil or value == "" then return tail end
  return value .. ", " .. tail
end

-- vary_with_origin returns a Vary value with Origin added (see vary_with).
function _M.vary_with_origin(vary)
  return _M.vary_with(vary, ORIGIN_VARY)
end

-- origin_preflight tells whether the request is a CORS preflight: OPTIONS
-- with Origin and Access-Control-Request-Method.
local function origin_preflight()
  local var = ngx.var
  local origin, method = var.http_origin, var.http_access_control_request_method
  return origin ~= nil and origin ~= "" and method ~= nil and method ~= "" and ngx.req.get_method() == "OPTIONS"
end

-- requested_headers returns the request's Access-Control-Request-Headers
-- (several joined with ", "), nil without them.
local function requested_headers()
  local v = ngx.req.get_headers(0)["access-control-request-headers"]
  return type(v) == "table" and concat(v, ", ") or v
end

-- strip_cors removes every Access-Control-* response header.
local function strip_cors(h)
  for name in pairs(ngx.resp.get_headers(0, true)) do
    if lower(sub(name, 1, 15)) == "access-control-" then h[name] = nil end
  end
end

-- response_headers sets a response's CORS headers (path: the request's
-- normalized path) and the site's security headers. Without
-- keep_origin_headers, or when the response has no
-- Access-Control-Allow-Origin, every Access-Control-* header is replaced
-- by the site's for an allowed Origin; Vary always names Origin within the
-- CORS scope. A preflight the origin answered (preflight_to_origin) gets
-- the headers of the edge's own preflight answer instead, with its status
-- and body: Access-Control-Allow-Origin (and credentials), methods,
-- request headers, max age, and Origin, Access-Control-Request-Method and
-- Access-Control-Request-Headers in Vary. The preflight answered at the
-- edge keeps its own headers.
function _M.response_headers(site, h, path)
  local a = site._access
  if not a then return end
  local cors = a.cors
  if cors and not ngx.ctx.edgeweir_preflight and path_in_scope(path or "", cors.prefixes) then
    local names = ORIGIN_VARY
    if not (cors.keep and h["Access-Control-Allow-Origin"] ~= nil) then
      strip_cors(h)
      local allow = _M.cors_allow_origin(cors, ngx.var.http_origin)
      if allow and cors.to_origin and origin_preflight() then
        set_preflight(cors, h, allow, requested_headers())
        names = PREFLIGHT_VARY_NAMES
      elseif allow then
        h["Access-Control-Allow-Origin"] = allow
        if cors.credentials then h["Access-Control-Allow-Credentials"] = "true" end
        if cors.exposed then h["Access-Control-Expose-Headers"] = cors.exposed end
      end
    end
    local vary = h["Vary"]
    local with = _M.vary_with(vary, names)
    if with ~= vary then h["Vary"] = with end
  end
  local s = a.security
  if s then
    if s.nosniff then h["X-Content-Type-Options"] = "nosniff" end
    if s.frame_options then h["X-Frame-Options"] = s.frame_options end
    if s.referrer_policy then h["Referrer-Policy"] = s.referrer_policy end
    if s.permissions_policy then h["Permissions-Policy"] = s.permissions_policy end
    -- Verified on the node's OpenResty: a nil Server leaves the header out
    -- (HTTP/1.1 and HTTP/2) instead of nginx's own.
    if s.hide_server then h["Server"] = nil end
    if s.remove_powered_by then h["X-Powered-By"] = nil end
  end
end

return _M
