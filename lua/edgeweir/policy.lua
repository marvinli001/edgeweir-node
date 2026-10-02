-- edgeweir.policy: platform and site rules (edge layer).
--
-- access() runs the request phases (platform rules, then the site's, in
-- each phase), response() the response phases in the header filter:
-- response-transform, then compression (proto v0.13.0, feature rules-v2).
--
-- The request values (field name -> value) are built once per request.
-- Rewrites and request header changes write to a copy: ctx.original keeps
-- the client's request for the site's exact-match redirect table (looked
-- up after the redirect rules) and for the conditions of cache rules,
-- which see the request as the client sent it, like the cache key.
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
-- there are none.
function _M.prepare_tls_pending(domains)
  local pending, any = { exact = {}, wild = {}, hosts = {} }, false
  for _, d in ipairs(domains or {}) do
    if type(d) == "table" and type(d.name) == "string" then
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

-- request builds the request values of a request. The derived fields
-- http.request.full_uri and http.request.uri.path.extension are computed
-- only for sites whose rules read them (site._full_uri, site._extension,
-- see edgeweir.store).
function _M.request(site, headers)
  local var = ngx.var
  local scheme = var.scheme
  local values = {
    ["http.host"] = var.host, ["http.request.method"] = ngx.req.get_method(),
    ["http.request.uri.path"] = var.uri, ["http.request.uri.query"] = var.args or "",
    ["http.request.uri"] = var.request_uri, ["ip.src"] = var.remote_addr,
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
  -- JA4 comes from the TLS handshake (edgeweir.ja4); "" on plain HTTP.
  if site._ja4 then values["tls.ja4"] = require("edgeweir.ja4").value() end
  -- GeoIP is read once in the access phase; response filters cannot yield.
  if site._geo then
    local geo = assert(require("edgeweir.geoip").lookup(var.remote_addr), "GeoIP unavailable")
    values["ip.geoip.country"], values["ip.geoip.subdivision"], values["ip.geoip.asnum"] = geo.country or "", geo.subdivision or "", geo.asnum or 0
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

local function rewrite(rule, a, ctx)
  local path = a.value
  if rule.target then
    path = rule.target(ctx.values)
    if not _M.valid_rewrite(path) then error("invalid rewrite path") end
  end
  ngx.req.set_uri(path, false)
  local args = ngx.var.args or ""
  local query = args
  if a.preserve_query == false then query = "" end
  if has_edits(a.set_query, a.remove_query) then query = _M.edit_query(query, a.set_query, a.remove_query) end
  if query ~= args then ngx.req.set_uri_args(query) end
  local values = writable(ctx)
  values["http.request.uri.path"] = path
  values["http.request.uri.path.extension"] = expressions.path_extension(path)
  values["http.request.uri.query"] = query
  values["http.request.uri"] = query ~= "" and (path .. "?" .. query) or path
end

local function redirect(rule, a, ctx)
  local location = a.value
  if rule.target then
    location = rule.target(ctx.values)
    if not _M.valid_location(location) then error("invalid redirect target") end
  end
  location = _M.redirect_location(location, ngx.var.args, a.preserve_query, a.set_query, a.remove_query)
  return { status = a.status_code, location = location }
end

local LEVELS = { cookie302 = 1, js = 2, pow = 3, captcha = 4 }
local TIMEOUTS = { origin_connect_timeout_ms = "c", origin_send_timeout_ms = "w", origin_read_timeout_ms = "r" }

local function config(a, ctx)
  if a.cache_bypass ~= nil then ctx.cache_bypass = a.cache_bypass end
  if a.force_https ~= nil then ctx.force_https = a.force_https end
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
      elseif a.kind == "rewrite" then rewrite(rule, a, ctx)
      elseif a.kind == "request_header" then
        if a.remove then ngx.req.clear_header(a.header) else ngx.req.set_header(a.header, a.value or "") end
        writable(ctx)["http.request.headers." .. a.header] = a.remove and "" or (a.value or "")
      elseif a.kind == "response_header" then
        ngx.header[a.header] = not a.remove and (a.value or "") or nil
        local values = writable(ctx)
        values["http.response.headers." .. a.header] = a.remove and "" or (a.value or "")
        if a.header == "content-type" and site._media_type then
          values["http.response.content_type.media_type"] = expressions.media_type(not a.remove and a.value or nil)
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

function _M.access(site, headers)
  local values = _M.request(site, headers)
  local cfg = site._config
  local ctx = { values = values, original = values, force_https = site.tls and site.tls.force_https }
  ngx.ctx.edgeweir_policy = ctx
  local allowed = false
  for _, m in ipairs(cfg.allows or {}) do if m(values["ip.src"]) then allowed = true; break end end
  ctx.platform_allowed = allowed
  if not allowed then
    for _, m in ipairs(cfg.blocks or {}) do if m(values["ip.src"]) then return { status = 403 } end end
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
  if ctx.force_https and ngx.var.scheme ~= "https" and not _M.tls_pending(site, ngx.var.host) then
    if not site.certificate_id or site.certificate_id == "" then return { status = 503 } end
    return { status = 301, location = "https://" .. ngx.var.host .. ngx.var.request_uri }
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
return _M
