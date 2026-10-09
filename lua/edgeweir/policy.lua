-- edgeweir.policy: platform and site rules (edge layer).
--
-- access() runs the request phases (platform rules, then the site's, in
-- each phase), response() the response phases in the header filter:
-- response-transform, then compression (proto v0.13.0, feature rules-v2).
-- Before the request phases come the platform allow and block lists, the
-- site's access control (edgeweir.access) and access authentication
-- (edgeweir.auth).
--
-- The request values (field name -> value) are built once per request.
-- Rewrites and request header changes write to a copy: ctx.original keeps
-- the client's request for the site's exact-match redirect table (looked
-- up after the redirect rules) and for the conditions of cache rules,
-- which see the request as the client sent it, like the cache key.
--
-- Header actions may compute their value (proto v0.22.0, feature
-- rules-v3): a value that comes out invalid (see
-- edgeweir.expressions.header_value) skips the action, with one NOTICE per
-- rule and node every 60 seconds; response headers may add a line
-- (append); redirects and rewrites may compute the values of the query
-- parameters they set.
--
-- Results of the rules travel in the request's policy context
-- (ngx.ctx.edgeweir_policy): cache bypass, force HTTPS, compression
-- switches and the compression rule's codings, WebSocket, Under Attack, CC,
-- the sampled log rate, and the origin override (origin rules' group, Host,
-- SNI and port, config rules' timeouts) that the router sends to the
-- origin layer (origin_header / parse_origin_header).
local expressions = require("edgeweir.expressions")
local ratelimit = require("edgeweir.ratelimit")
local compress = require("edgeweir.compress")
local clientcert = require("edgeweir.clientcert")
local auth = require("edgeweir.auth")
local access = require("edgeweir.access")
local _M = {}
_M.phases = { "request-transform", "redirect", "config", "waf-custom", "ratelimit", "cache", "origin" }

local byte, find, format, gmatch, gsub, match, sub = string.byte, string.find, string.format, string.gmatch, string.gsub, string.match, string.sub
local concat = table.concat

function _M.prepare_rules(rules, lists)
  local groups = {}
  for _, rule in ipairs(rules or {}) do
    local group = groups[rule.phase] or {}; groups[rule.phase] = group
    local compiled = { id = rule.id, match = expressions.compile(rule.expression, lists), action = rule.action }
    if type(rule.action) == "table" and type(rule.action.target) == "table" then
      compiled.target = expressions.compile_value(rule.action.target)
    end
    -- Computed query parameters (rules-v3), by position in set_query.
    for i, p in ipairs(type(rule.action) == "table" and type(rule.action.set_query) == "table" and rule.action.set_query or {}) do
      if type(p) == "table" and type(p.expression) == "table" then
        compiled.query = compiled.query or {}
        compiled.query[i] = expressions.compile_value(p.expression)
      end
    end
    group[#group + 1] = compiled
  end
  return groups
end
function _M.prepare_config(cfg)
  cfg.lists, cfg.blocks, cfg.allows = {}, {}, {}
  for _, list in ipairs(cfg.ip_lists or {}) do
    local matcher = expressions.ip_set(list.entries)
    cfg.lists[list.id] = matcher
    if list.platform then
      if list.kind == "allow" then cfg.allows[#cfg.allows + 1] = matcher end
      if list.kind == "block" then cfg.blocks[#cfg.blocks + 1] = matcher end
    end
  end
  cfg.groups = _M.prepare_rules(cfg.platform_rules, cfg.lists)
  return cfg
end

-- prepare_bulk indexes a site's exact-match redirect table by source.
function _M.prepare_bulk(list)
  if type(list) ~= "table" or #list == 0 then return nil end
  local out = {}
  for _, b in ipairs(list) do
    assert(type(b) == "table" and type(b.source) == "string" and type(b.target) == "string", "invalid bulk redirect")
    out[b.source] = b
  end
  return out
end

-- prepare_tls_pending returns the site's domains that its certificate does
-- not cover yet (tls_pending, proto v0.19.0, feature
-- tls-pending-domains-v1): exact names, parents of wildcards, and every
-- exact name of the site (an exact name wins over a wildcard); nil when
-- there are none. Suffix and pattern domains (domains-v2) are neither:
-- their names are no hosts, and their hosts complete TLS only where the
-- certificate names them (names_cover).
function _M.prepare_tls_pending(domains)
  local pending, any = { exact = {}, wild = {}, hosts = {} }, false
  for _, d in ipairs(domains or {}) do
    if type(d) == "table" and type(d.name) == "string" and not d.match then
      local wildcard = d.wildcard == true
      if not wildcard then pending.hosts[d.name] = true end
      if d.tls_pending == true then
        any = true
        pending[wildcard and "wild" or "exact"][d.name] = true
      end
    end
  end
  return any and pending or nil
end

-- tls_pending tells whether host (lowercase) reaches the site through a
-- domain that waits for the certificate: it is served over HTTP only, with
-- no TLS handshake and no HTTPS redirect.
function _M.tls_pending(site, host)
  local pending = site and site._tls_pending
  if not pending or type(host) ~= "string" then return false end
  if pending.hosts[host] then return pending.exact[host] == true end
  local dot = find(host, ".", 1, true)
  return dot ~= nil and pending.wild[sub(host, dot + 1)] == true
end

-- redirect_excluded tells whether host (lowercase) reaches the site
-- through a domain the HTTPS redirect leaves alone (edge-ports-v1): an
-- exact name, else the wildcard of its parent (as the site resolves it).
function _M.redirect_excluded(site, host)
  local excluded = site._redirect_excluded
  if not excluded or type(host) ~= "string" then return false end
  if excluded[host] then return true end
  local hosts = site._exact_hosts
  if hosts == nil then
    hosts = {}
    for _, d in ipairs(site.domains or {}) do
      if type(d) == "table" and d.wildcard ~= true and not d.match and type(d.name) == "string" then hosts[d.name] = true end
    end
    site._exact_hosts = hosts
  end
  if hosts[host] then return false end
  local dot = find(host, ".", 1, true)
  return dot ~= nil and excluded["*." .. sub(host, dot + 1)] == true
end

-- names_cover tells whether a certificate's DNS names cover host: the
-- same name, or a wildcard over its parent (a host that starts with a dot
-- has none).
function _M.names_cover(names, host)
  if type(names) ~= "table" or type(host) ~= "string" then return false end
  local dot = find(host, ".", 1, true)
  local wild = dot and dot > 1 and "*." .. sub(host, dot + 1)
  for i = 1, #names do
    if names[i] == host or names[i] == wild then return true end
  end
  return false
end

-- uncovered tells whether an HTTPS request for host would not complete
-- its handshake (edgeweir.tls), so the HTTP request gets no HTTPS
-- redirect: one that reached the site through a suffix or pattern domain
-- (found "match") whose certificate does not name the host, or one handed
-- to the default site (found "handed") unless unknown names get the
-- default site's certificate (default_certificate) and it names the host.
function _M.uncovered(site, host, found, default_certificate)
  if found ~= "match" and found ~= "handed" then return false end
  if found == "handed" and not default_certificate then return true end
  -- The names of all of the site's certificates (edgeweir.store).
  local names = site and site._cert_names
  if names == nil then
    local cert = site and site.certificate
    names = cert and cert.dns_names
  end
  return not _M.names_cover(names, host)
end

-- site_https_redirect is the HTTPS redirect the site's own Force HTTPS
-- gives a plain HTTP request for host (nil: none): not for domains waiting
-- for the certificate, excluded domains or hosts its certificates do not
-- cover. Config rules are not run (edgeweir.router asks before the site
-- logic, for sites that require client certificates).
function _M.site_https_redirect(site, host, request_uri, found, default_certificate)
  local tls = site.tls
  if not (tls and tls.force_https) or not site.certificate_id or site.certificate_id == ""
    or _M.tls_pending(site, host) or _M.redirect_excluded(site, host)
    or _M.uncovered(site, host, found, default_certificate) then
    return nil
  end
  return _M.https_redirect(tls, host, request_uri)
end

-- https_redirect is the HTTPS redirect of a request for host with
-- request_uri: the site's status (301 by default) to its port (443 by
-- default, left out of the URL).
function _M.https_redirect(tls, host, request_uri)
  local status = tls and tonumber(tls.redirect_status) or 0
  local port = tls and tonumber(tls.redirect_port) or 0
  local authority = host
  if port ~= 0 and port ~= 443 then authority = host .. ":" .. port end
  return { status = status ~= 0 and status or 301, location = "https://" .. authority .. request_uri }
end

-- bulk_lookup returns the entry of table bulk for host and path: the
-- "host/path" entry first, then the "/path" one.
function _M.bulk_lookup(bulk, host, path)
  if not bulk or not path then return nil end
  return (host and bulk[host .. path]) or bulk[path]
end

-- percent_encode encodes every byte but the RFC 3986 unreserved characters.
function _M.percent_encode(value)
  return (gsub(value or "", "[^A-Za-z0-9%-._~]", function(c) return format("%%%02X", byte(c)) end))
end

-- edit_query removes the parameters named in remove_query or set_query
-- (raw name: the text before the first "=" of an element, compared
-- exactly; empty elements go too) from query and appends set_query in
-- order, values percent-encoded. Returns the new query ("" when empty).
function _M.edit_query(query, set_query, remove_query)
  local drop = {}
  for _, name in ipairs(remove_query or {}) do drop[name] = true end
  for _, p in ipairs(set_query or {}) do drop[p.name] = true end
  local kept = {}
  for element in gmatch(query or "", "[^&]+") do
    if not drop[match(element, "^[^=]*")] then kept[#kept + 1] = element end
  end
  for _, p in ipairs(set_query or {}) do
    kept[#kept + 1] = p.name .. "=" .. _M.percent_encode(p.value)
  end
  return concat(kept, "&")
end

local function has_edits(set_query, remove_query)
  return (type(set_query) == "table" and #set_query > 0) or (type(remove_query) == "table" and #remove_query > 0)
end

-- redirect_location applies a redirect's query handling to location. args
-- is the request's query string; preserve appends it ("?" or "&"), then
-- the edits of set_query and remove_query apply to the whole query. The
-- fragment stays last; a "?" without parameters is dropped.
function _M.redirect_location(location, args, preserve, set_query, remove_query)
  local append = preserve == true and args ~= nil and args ~= ""
  local edits = has_edits(set_query, remove_query)
  if not append and not edits then return location end
  local hash = find(location, "#", 1, true)
  local fragment = hash and sub(location, hash) or ""
  local base = hash and sub(location, 1, hash - 1) or location
  local q = find(base, "?", 1, true)
  local path, query = base, ""
  if q then path, query = sub(base, 1, q - 1), sub(base, q + 1) end
  if append then query = query ~= "" and (query .. "&" .. args) or args end
  if edits then query = _M.edit_query(query, set_query, remove_query) end
  if query ~= "" then path = path .. "?" .. query end
  return path .. fragment
end

-- valid_location reports whether a computed redirect target is an
-- absolute http(s) URL with a host (no user information) or a path
-- starting with a single "/", without whitespace, control characters or
-- backslashes.
function _M.valid_location(v)
  if type(v) ~= "string" or v == "" or find(v, "[%s%c\\]") then return false end
  if sub(v, 1, 1) == "/" then return sub(v, 2, 2) ~= "/" end
  local authority = match(v, "^[Hh][Tt][Tt][Pp][Ss]?://([^/?#]*)")
  return authority ~= nil and authority ~= "" and not find(authority, "@", 1, true)
end

-- valid_rewrite reports whether a computed rewrite path starts with a
-- single "/" and has no "?", "#", backslash or control character.
function _M.valid_rewrite(v)
  return type(v) == "string" and sub(v, 1, 1) == "/" and sub(v, 2, 2) ~= "/" and not find(v, "[%?#\\%c]")
end

-- origin_header encodes the origin override of a policy context for the
-- origin layer (X-Edgeweir-Origin): "k=v" pairs joined by ";", g group,
-- h Host, s SNI, p port, c/w/r connect/send/read timeouts in ms. Values
-- were validated by configir and never contain ";" or "=". "" without an
-- override.
function _M.origin_header(ctx)
  local o = ctx and ctx.origin
  if not o then return "" end
  local out = {}
  for _, k in ipairs({ "g", "h", "s", "p", "c", "w", "r" }) do
    local v = o[k]
    if v ~= nil and v ~= "" and v ~= 0 then out[#out + 1] = k .. "=" .. tostring(v) end
  end
  return concat(out, ";")
end

local ORIGIN_KEYS = { g = "group", h = "host", s = "sni", p = "port", c = "connect", w = "send", r = "read" }
local ORIGIN_NUMBERS = { p = { 1, 65535 }, c = { 1, 3600000 }, w = { 1, 3600000 }, r = { 1, 3600000 } }

-- parse_origin_header decodes origin_header's value: { group, host, sni,
-- port, connect, send, read } (absent fields nil), or nil without any.
function _M.parse_origin_header(value)
  if type(value) ~= "string" or value == "" then return nil end
  local out, any = {}, false
  for k, v in gmatch(value, "([ghspcwr])=([^;]*)") do
    local range = ORIGIN_NUMBERS[k]
    if range then
      v = tonumber(v)
      if v and v >= range[1] and v <= range[2] and v == math.floor(v) then out[ORIGIN_KEYS[k]] = v; any = true end
    elseif v ~= "" then
      out[ORIGIN_KEYS[k]] = v; any = true
    end
  end
  return any and out or nil
end

-- set_named sets the fields of the names (a set) after prefix from what
-- parse (edgeweir.expressions.cookies or args) finds in text ("" for
-- names it does not find).
local function set_named(values, prefix, names, parse, text)
  local found = parse(text or "", names, {})
  for name in pairs(names) do values[prefix .. name] = found[name] or "" end
end

-- HEADER_FIELDS are the fields that read a request header (rules-v3).
local HEADER_FIELDS = { referer = "http.referer", ["user-agent"] = "http.user_agent" }

-- request builds the request values of a request. The derived fields
-- http.request.full_uri and http.request.uri.path.extension, and the
-- rules-v3 fields, are computed only for sites whose rules read them
-- (site._full_uri, site._extension, site._request_v3, site._peer, site._cookies,
-- site._args, see edgeweir.store).
function _M.request(site, headers)
  local var = ngx.var
  local scheme = var.scheme
  local values = {
    ["http.host"] = var.host, ["http.request.method"] = ngx.req.get_method(),
    ["http.request.uri.path"] = var.uri, ["http.request.uri.query"] = var.args or "",
    -- Without a signed URL's signature (edgeweir.auth).
    ["http.request.uri"] = auth.request_uri(), ["ip.src"] = var.remote_addr,
    ssl = scheme == "https",
  }
  if site._full_uri then
    values["http.request.full_uri"] = expressions.full_uri(scheme, values["http.host"], values["http.request.uri"])
  end
  if site._extension then
    values["http.request.uri.path.extension"] = expressions.path_extension(values["http.request.uri.path"] or "")
  end
  for name, value in pairs(headers) do
    values["http.request.headers." .. name:lower()] = type(value) == "table" and table.concat(value, ", ") or value
  end
  if site._request_v3 then
    values["http.referer"] = values["http.request.headers.referer"]
    values["http.user_agent"] = values["http.request.headers.user-agent"]
    values["http.request.version"] = var.server_protocol
    values["http.request.scheme"] = scheme
    values["http.request.id"] = var.edgeweir_request_id or var.request_id
    values["http.request.timestamp.sec"] = math.floor(ngx.req.start_time())
    values["edge.server_port"] = tonumber(var.server_port) or 0
  end
  -- ip.peer (client-ip-v1): the connection's peer before realip; the
  -- local listeners' peer is the address the agent names.
  if site._peer then
    local peer = var.realip_remote_addr
    values["ip.peer"] = (peer and peer ~= "unix:") and peer or var.remote_addr
  end
  if site._cookies then
    local cookie = headers.cookie
    set_named(values, "http.request.cookies.", site._cookies, expressions.cookies, type(cookie) == "table" and concat(cookie, "; ") or cookie)
  end
  if site._args then set_named(values, "http.request.uri.args.", site._args, expressions.args, values["http.request.uri.query"]) end
  -- JA4 comes from the TLS handshake (edgeweir.ja4); "" on plain HTTP.
  if site._ja4 then values["tls.ja4"] = require("edgeweir.ja4").value() end
  -- The client certificate of the connection (client-cert-v1): false and
  -- "" without a verified one.
  if site._client_fields then
    local client = clientcert.values()
    values["tls.client.verified"], values["tls.client.cert_sha256"], values["tls.client.subject"] = client.verified, client.sha256, client.subject
  end
  -- GeoIP is read once in the access phase; response filters cannot yield.
  if site._geo then
    local geo = assert(require("edgeweir.geoip").lookup(var.remote_addr), "GeoIP unavailable")
    values["ip.geoip.country"], values["ip.geoip.subdivision"], values["ip.geoip.asnum"] = geo.country or "", geo.subdivision or "", geo.asnum or 0
    values["ip.geoip.as_name"] = geo.as_name or ""
  end
  return values
end

-- writable returns the request values rules may change: a copy, the first
-- time, so that ctx.original stays the client's request.
local function writable(ctx)
  local values = ctx.values
  if values == ctx.original then
    local copy = {}
    for k, v in pairs(values) do copy[k] = v end
    ctx.values = copy
    return copy
  end
  return values
end

-- set_query returns the parameters a redirect or rewrite sets, the
-- computed ones (rules-v3) with their value for this request.
local function set_query(rule, a, values)
  local query = rule.query
  if not query then return a.set_query end
  local out = {}
  for i, p in ipairs(a.set_query) do
    local fn = query[i]
    out[i] = fn and { name = p.name, value = fn(values) } or p
  end
  return out
end

local function rewrite(rule, a, ctx, site)
  local path = a.value
  if rule.target then
    path = rule.target(ctx.values)
    if not _M.valid_rewrite(path) then error("invalid rewrite path") end
  end
  local params = set_query(rule, a, ctx.values)
  ngx.req.set_uri(path, false)
  local args = ngx.var.args or ""
  local query = args
  if a.preserve_query == false then query = "" end
  if has_edits(params, a.remove_query) then query = _M.edit_query(query, params, a.remove_query) end
  if query ~= args then ngx.req.set_uri_args(query) end
  local values = writable(ctx)
  values["http.request.uri.path"] = path
  values["http.request.uri.path.extension"] = expressions.path_extension(path)
  values["http.request.uri.query"] = query
  values["http.request.uri"] = query ~= "" and (path .. "?" .. query) or path
  if site._args then set_named(values, "http.request.uri.args.", site._args, expressions.args, query) end
end

local function redirect(rule, a, ctx)
  local location = a.value
  if rule.target then
    location = rule.target(ctx.values)
    if not _M.valid_location(location) then error("invalid redirect target") end
  end
  location = _M.redirect_location(location, ngx.var.args, a.preserve_query, set_query(rule, a, ctx.values), a.remove_query)
  return { status = a.status_code, location = location }
end

-- header_value returns the value a header action sets: the static value,
-- or its value expression's (rules-v3); nil skips the action (logged once
-- per rule and node every 60 seconds, IDs only).
function _M.header_value(rule, a, site, values)
  if not rule.target then return a.value or "" end
  local v = expressions.header_value(rule.target, values)
  if v == nil and ngx.shared.edgeweir_policy_logs:safe_add("header:" .. rule.id, true, 60) then
    ngx.log(ngx.NOTICE, "edgeweir: header value skipped site=", site.id, " rule=", rule.id)
  end
  return v
end

-- add_header_line appends value as another line of response header name.
local function add_header_line(name, value)
  local current = ngx.header[name]
  if current == nil then
    ngx.header[name] = value
  elseif type(current) == "table" then
    current[#current + 1] = value
    ngx.header[name] = current
  else
    ngx.header[name] = { current, value }
  end
  local lines = ngx.header[name]
  return type(lines) == "table" and concat(lines, ", ") or lines
end

local LEVELS = { cookie302 = 1, js = 2, pow = 3, captcha = 4 }
local TIMEOUTS = { origin_connect_timeout_ms = "c", origin_send_timeout_ms = "w", origin_read_timeout_ms = "r" }

local function config(a, ctx)
  if a.cache_bypass ~= nil then ctx.cache_bypass = a.cache_bypass end
  if a.force_https ~= nil then ctx.force_https, ctx.force_https_rule = a.force_https, a.force_https end
  -- Compression switches (edgeweir.compress): false drops the coding for
  -- this response, true allows it again among the site's codings.
  if a.gzip ~= nil then ctx.gzip = a.gzip end
  if a.brotli ~= nil then ctx.br = a.brotli end
  if a.zstd ~= nil then ctx.zstd = a.zstd end
  if a.websocket ~= nil then ctx.websocket = a.websocket end
  if a.under_attack ~= nil then ctx.under_attack = a.under_attack end
  if a.cc_enabled ~= nil then ctx.cc_enabled = a.cc_enabled end
  if LEVELS[a.cc_max_level] then ctx.cc_max_level = LEVELS[a.cc_max_level] end
  if tonumber(a.log_sample_rate) then ctx.log_sample_rate = tonumber(a.log_sample_rate) end
  -- The request's body limit in bytes (0: none), feature site-content-v1.
  if tonumber(a.request_body_limit) then ctx.body_limit = tonumber(a.request_body_limit) end
  for field, key in pairs(TIMEOUTS) do
    local ms = tonumber(a[field])
    if ms and ms > 0 then
      ctx.origin = ctx.origin or {}
      ctx.origin[key] = ms
    end
  end
end

local function origin(a, ctx)
  local o = ctx.origin or {}
  ctx.origin = o
  if a.origin_group and a.origin_group ~= "" then o.g = a.origin_group end
  if a.host_header and a.host_header ~= "" then o.h = a.host_header end
  if a.sni and a.sni ~= "" then o.s = a.sni end
  local port = tonumber(a.port)
  if port and port > 0 then o.p = port end
end

local function run_group(group, site, ctx, phase, namespace)
  if not group then return end
  for _, rule in ipairs(group) do
    if rule.match(ctx.values) then
      local a = rule.action
      if a.kind == "block" then return { status = a.status_code } end
      if a.kind == "allow" then -- this WAF scope only; never skips platform rules or rate limits
        ctx.allowed = true -- but exempts the request from Under Attack and CC challenges
        break
      end
      if a.kind == "challenge" then
        -- A sufficient pass continues with the next rules; otherwise the
        -- request is challenged here.
        local challenge = require("edgeweir.challenge")
        local level = challenge.LEVELS[a.challenge]
        if not level then return { status = 503 } end
        if challenge.pass_level(site) < level then return { challenge = a.challenge, level = level } end
      end
      if a.kind == "log" then
        -- Counted per rule and minute for the console (feature rule-log-v1).
        require("edgeweir.stats").logged(site.id, rule.id)
        -- IDs only: expressions, URL, headers and client addresses are never logged.
        local key = "log:" .. site.id .. ":" .. rule.id
        if ngx.shared.edgeweir_policy_logs:safe_add(key, true, 60) then
          ngx.log(ngx.NOTICE, "edgeweir: WAF match site=", site.id, " rule=", rule.id)
        end
      elseif a.kind == "redirect" then return redirect(rule, a, ctx)
      elseif a.kind == "rewrite" then rewrite(rule, a, ctx, site)
      elseif a.kind == "request_header" then
        local value = a.remove and "" or _M.header_value(rule, a, site, ctx.values)
        if value then
          if a.remove then ngx.req.clear_header(a.header) else ngx.req.set_header(a.header, value) end
          local values = writable(ctx)
          values["http.request.headers." .. a.header] = value
          local alias = HEADER_FIELDS[a.header]
          if alias and site._request_v3 then values[alias] = value end
        end
      elseif a.kind == "response_header" then
        local value = a.remove and "" or _M.header_value(rule, a, site, ctx.values)
        if value then
          if a.remove then ngx.header[a.header] = nil
          elseif a.append then value = add_header_line(a.header, value)
          else ngx.header[a.header] = value end
          local values = writable(ctx)
          values["http.response.headers." .. a.header] = value
          if a.header == "content-type" and site._media_type then
            values["http.response.content_type.media_type"] = expressions.media_type(not a.remove and value or nil)
          end
        end
      elseif a.kind == "config" then config(a, ctx)
      elseif a.kind == "origin" then origin(a, ctx)
      elseif a.kind == "compression" then
        local list = {}
        for i, coding in ipairs(type(a.compression) == "table" and a.compression or {}) do list[i] = coding end
        ctx.compression = list
      elseif a.kind == "rate_limit" then
        local result = ratelimit.check(site._rate_limit_dict, site.id, namespace, rule.id, a, ctx.values[a.key])
        if result then return result end
      end
    end
  end
end

-- access runs the request phases. acme: an HTTP-01 request for the
-- origin; site_allowed: ip.src is on one of the site's allow lists
-- (edgeweir.access.site_allowed).
function _M.access(site, headers, acme, site_allowed)
  local values = _M.request(site, headers)
  local cfg = site._config
  local ctx = { values = values, original = values, force_https = site.tls and site.tls.force_https }
  ngx.ctx.edgeweir_policy = ctx
  local allowed = false
  for _, m in ipairs(cfg.allows or {}) do if m(values["ip.src"]) then allowed = true; break end end
  ctx.platform_allowed = allowed
  ctx.site_allowed = site_allowed == true
  if not allowed then
    for _, m in ipairs(cfg.blocks or {}) do if m(values["ip.src"]) then return { status = 403 } end end
  end
  -- Access control (edgeweir.access): the site's block lists, geo, CORS
  -- preflights, hotlink and user agents, after the platform lists and
  -- before access authentication; not for the local listeners (the
  -- operator's own requests) and HTTP-01 requests for the origin.
  if site._access and not acme and ngx.var.edgeweir_local ~= "1" then
    local result = access.check(site, values, allowed, ctx.site_allowed)
    if result then return result end
  end
  -- Access authentication: after the lists, before the rule phases and the
  -- cache (edgeweir.auth).
  if site._auth then
    local result = auth.check(site, _M.site_https_redirect)
    if result then return result end
  end
  for _, phase in ipairs(_M.phases) do
    local result = run_group(cfg.groups and cfg.groups[phase], site, ctx, phase, "platform")
    if result then return result end
    result = run_group(site._rule_groups[phase], site, ctx, phase, "site")
    if result then return result end
    if phase == "redirect" and site._bulk then
      -- The exact-match table, with the client's Host and path.
      local b = _M.bulk_lookup(site._bulk, values["http.host"], values["http.request.uri.path"])
      if b then
        return { status = b.status, location = _M.redirect_location(b.target, values["http.request.uri.query"], b.preserve_query) }
      end
    end
  end
  if ctx.force_https and ngx.var.scheme ~= "https" and not _M.tls_pending(site, ngx.var.host)
    and (ctx.force_https_rule or not _M.redirect_excluded(site, ngx.var.host)) then
    -- Without a certificate nothing is served over HTTP either (fail closed).
    if not site.certificate_id or site.certificate_id == "" then return { status = 503 } end
    local gctx = ngx.ctx
    if not _M.uncovered(site, ngx.var.host, gctx.edgeweir_found, gctx.edgeweir_default_certificate) then
      return _M.https_redirect(site.tls, ngx.var.host, ngx.var.request_uri)
    end
  end
  -- gzip switched off for a site the edge does not compress: the origin
  -- gets no Accept-Encoding, and the cache's Vary tells the variants apart
  -- (sites the edge compresses drop gzip in edgeweir.compress).
  if ctx.gzip == false and not compress.enabled(site) then
    ngx.req.clear_header("Accept-Encoding")
  end
end

-- response runs the response phases in the edge header filter, only for
-- sites with rules in them (site._response_rules, platform rules
-- included). The client's original request is no longer needed then (the
-- cache decision was made in the access phase): response values go into
-- the request values without a copy.
function _M.response(site)
  if not site._response_rules then return end
  local ctx = ngx.ctx.edgeweir_policy
  if not ctx then return end
  ctx.original = nil
  local values = ctx.values
  values["http.response.code"] = ngx.status
  local headers = ngx.resp.get_headers(0)
  for name, value in pairs(headers) do
    values["http.response.headers." .. name:lower()] = type(value) == "table" and table.concat(value, ", ") or value
  end
  if site._media_type then
    local content_type = headers["content-type"]
    if type(content_type) == "table" then content_type = content_type[1] end
    values["http.response.content_type.media_type"] = expressions.media_type(content_type)
  end
  -- The edge cache's status (rules-v3); "" for responses the node made
  -- itself and for those that never pass the cache (WebSocket, gRPC).
  if site._cache_status then values["http.response.cache_status"] = ngx.var.upstream_cache_status or "" end
  local groups = site._config.groups
  for _, phase in ipairs({ "response-transform", "compression" }) do
    run_group(groups and groups[phase], site, ctx, phase, "platform")
    run_group(site._rule_groups[phase], site, ctx, phase, "site")
  end
end

-- cc_level applies a request's CC overrides to the site's CC level: 0 when
-- config rules turned CC off, at most their highest level.
function _M.cc_level(ctx, level)
  if not ctx then return level end
  if ctx.cc_enabled == false then return 0 end
  if ctx.cc_max_level and level > ctx.cc_max_level then return ctx.cc_max_level end
  return level
end
-- config_action applies a config action to a request's policy context
-- (exported for tests).
_M.config_action = config

return _M
