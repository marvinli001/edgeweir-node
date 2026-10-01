-- edgeweir.router: edge layer (public listeners).
--
-- access(): rejects requests that already passed this node (CDN-Loop,
-- 508), resolves the site by Host (404 for unknown hosts), rejects banned
-- client addresses (403 ip-banned, edgeweir.bans), handles
-- WebSocket upgrades, evaluates the request conditions of the cache rules
-- and prepares the variables used by proxy_cache in nginx.conf: the cache
-- key (edgeweir.cachekey, including the purge epoch from edgeweir.purge),
-- whether to look up / store, the Range mode (slice, pass or strip) and the
-- origin layer (with or without TLS verification). Challenges come after
-- the rules (edgeweir.challenge, edgeweir.cc): the reserved prefix
-- /.edgeweir/ is answered at the edge, requests without a sufficient pass
-- are challenged for Under Attack and CC levels unless an allow rule or a
-- platform allow list exempts them. The chosen rules travel
-- to the origin layer in X-Edgeweir-Rules, which decides the TTL once the
-- response status and size are known.
--
-- Sites that run the OWASP CRS continue in the edge layer's CRS location
-- once these checks pass (edgeweir.waf); sites the edge compresses ask the
-- origin for uncompressed responses (edgeweir.compress).
--
-- header_filter(): restores the origin's Cache-Control header that the
-- origin layer replaced to carry stale-* extensions for nginx's cache, and
-- chooses the response's content coding (edgeweir.compress).
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local cachekey = require("edgeweir.cachekey")
local purge = require("edgeweir.purge")
local policy = require("edgeweir.policy")
local ipaddr = require("edgeweir.ipaddr")
local bans = require("edgeweir.bans")
local cc = require("edgeweir.cc")
local challenge = require("edgeweir.challenge")
local compress = require("edgeweir.compress")
local waf = require("edgeweir.waf")

local _M = {}

local concat = table.concat
local lower, sub = string.lower, string.sub

local function deny(status, code, message)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(message, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- strip_internal_headers removes client-supplied X-Edgeweir-* headers so
-- that clients can never inject internal routing or caching hints. It
-- reads every request header (no limit) and returns them: the cache key
-- is built from the same table, so a header can never be invisible to
-- one and visible to the other.
local function strip_internal_headers()
  local headers = ngx.req.get_headers(0)
  for name in pairs(headers) do
    if sub(name, 1, 11) == "x-edgeweir-" then
      ngx.req.clear_header(name)
      headers[name] = nil
    end
  end
  return headers
end

-- cdn_loop_contains reports whether a CDN-Loop header value (RFC 8586:
-- comma-separated cdn-info, each a cdn-id with optional ";" parameters)
-- names cdn_id (compared case-insensitively).
function _M.cdn_loop_contains(value, cdn_id)
  if not value or value == "" then
    return false
  end
  local want = lower(cdn_id)
  for info in string.gmatch(value, "[^,]+") do
    local id = info:match("^%s*([^;%s]+)")
    if id and lower(id) == want then
      return true
    end
  end
  return false
end

-- cdn_loop_value is the CDN-Loop header sent upstream: the incoming value
-- with this node's cdn-id appended.
function _M.cdn_loop_value(incoming, cdn_id)
  if incoming and incoming ~= "" then
    return incoming .. ", " .. cdn_id
  end
  return cdn_id
end

-- remote_addr is read only when some ban could apply (edgeweir.bans).
local function remote_addr()
  return ngx.var.remote_addr
end

-- platform_allowed reports whether addr is on a platform allow list of
-- the site's table.
function _M.platform_allowed(site, addr)
  local allows = site._config and site._config.allows
  if allows then
    for i = 1, #allows do
      if allows[i](addr) then
        return true
      end
    end
  end
  return false
end

-- run_challenge answers with a challenge; failures fail closed (503).
local function run_challenge(site, kind, level)
  local ok, err = pcall(challenge.respond, site, kind, level)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: challenge failed site=", site.id, ": ", err)
    return deny(503, "challenge-unavailable", "challenge unavailable")
  end
end

local function rule_ids(chain)
  local ids = {}
  for i = 1, #chain do
    ids[i] = chain[i].id
  end
  return concat(ids, ",")
end

-- key_request collects what the cache key policy of site needs. path is
-- the normalized $uri, headers every request header.
local function key_request(site, var, path, headers)
  local key = site.cache_key
  local req = {
    scheme = var.scheme,
    host = var.host,
    path = path,
    args = var.args,
  }
  if key.device then
    req.user_agent = var.http_user_agent
  end
  if #key.headers > 0 then
    req.headers = headers
  end
  if #key.cookies > 0 then
    req.cookie = function(name)
      return ngx.var["cookie_" .. name]
    end
  end
  return req
end

-- access returns true when the request goes on to the cache and origin;
-- every other outcome has answered the request already.
local function access()
  local headers = strip_internal_headers()

  local var = ngx.var
  -- Loop detection (RFC 8586) comes before any origin or cache work: an
  -- origin that points back at this node (directly or through other CDNs
  -- that keep the header) would otherwise recurse until connections run
  -- out.
  local cdn_id = store.config().cdn_id
  if cdn_id ~= "" then
    local loop = var.http_cdn_loop
    if _M.cdn_loop_contains(loop, cdn_id) then
      return deny(508, "loop-detected", "loop detected")
    end
    var.edgeweir_cdn_loop = _M.cdn_loop_value(loop, cdn_id)
  end

  local host = var.host
  local token = var.uri:match("^/%.well%-known/acme%-challenge/([A-Za-z0-9_-]+)$")
  if token then
    for _, challenge in ipairs(store.config().http_challenges or {}) do
      if challenge.domain == host and challenge.token == token and challenge.expires_at > ngx.time() then
        ngx.header["Content-Type"] = "text/plain"
        ngx.header["Cache-Control"] = "no-store"
        ngx.print(challenge.key_authorization)
        return ngx.exit(ngx.HTTP_OK)
      end
    end
    return deny(404, "challenge-not-found", "challenge not found")
  end
  local site = store.lookup_host(host)
  if not site then
    return deny(ngx.HTTP_NOT_FOUND, "unknown-host", "unknown host")
  end

  ngx.ctx.edgeweir_site = site
  if var.scheme == "https" and (not var.ssl_server_name or string.lower(var.ssl_server_name) ~= host) then
    return deny(421, "sni-host-mismatch", "SNI and Host must match")
  end
  -- Dynamic bans: platform scope, then the site's; addresses on a
  -- platform allow list are never banned.
  if bans.match(site.id, remote_addr) and not _M.platform_allowed(site, var.remote_addr) then
    return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
  end
  local original_path = var.uri
  ngx.ctx.edgeweir_original_path = original_path
  var.edgeweir_site = site.id
  -- CC counts every request of the site (edgeweir.cc).
  local cc_n, cc_w, cc_now
  if site._cc then
    cc_n, cc_w, cc_now = cc.count(site, var.remote_addr, original_path)
  end
  -- The reserved prefix is answered here and never reaches the origin.
  if sub(original_path, 1, 11) == "/.edgeweir/" then
    if cc_n and not _M.platform_allowed(site, var.remote_addr) and cc.check_ip(site, var.remote_addr, cc_n, cc_w, cc_now) then
      return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
    end
    local rok, err = pcall(challenge.reserved, site)
    if not rok then
      ngx.log(ngx.ERR, "edgeweir: challenge endpoint failed site=", site.id, ": ", err)
      return deny(503, "challenge-unavailable", "challenge unavailable")
    end
    return
  end
  local ok, result = pcall(policy.access, site, headers)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: policy evaluation failed site=", site.id)
    return deny(503, "policy-unavailable", "policy unavailable")
  end
  -- allow rules and platform allow lists exempt from CC bans and from
  -- Under Attack and CC challenges.
  local pctx = ngx.ctx.edgeweir_policy
  local exempt = pctx and (pctx.allowed or pctx.platform_allowed)
  if cc_n and not exempt and cc.check_ip(site, var.remote_addr, cc_n, cc_w, cc_now) then
    return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
  end
  if result then
    if result.challenge then return run_challenge(site, result.challenge, result.level) end
    if result.location then return ngx.redirect(result.location, result.status) end
    if result.retry_after then ngx.header["Retry-After"] = tostring(result.retry_after) end
    return deny(result.status, result.code or "policy-denied", result.message or "request denied")
  end
  if site._guard and not exempt then
    local level, kind = challenge.required(site, site._cc and cc.level(site, original_path) or 0)
    if level > 0 and challenge.pass_level(site) < level then
      return run_challenge(site, kind, level)
    end
  end
  headers = ngx.req.get_headers(0)

  var.edgeweir_site = site.id
  var.edgeweir_cache_zone = site.cache_zone
  if not site.tls_verify then
    var.edgeweir_origin_layer = "edgeweir_origin_noverify"
  end
  -- The edge compresses: the origin sends (and the cache keeps) identity.
  if compress.enabled(site) then
    var.edgeweir_strip_ae = "1"
  end

  local upgrade = var.http_upgrade
  if upgrade and lower(upgrade) == "websocket" then
    if not site.websocket then
      return deny(ngx.HTTP_FORBIDDEN, "websocket-disabled", "websocket disabled")
    end
    -- Proxied as is, never cached.
    var.edgeweir_upgrade = "websocket"
    var.edgeweir_connection = "upgrade"
    return true
  end

  local method = ngx.req.get_method()
  if method ~= "GET" and method ~= "HEAD" then
    var.edgeweir_range_mode = "pass"
    return true
  end
  -- RFC 9111, section 3.5: responses to requests with Authorization are
  -- shared only when the applying rule allows it (cache_authorized).
  local authorized = var.http_authorization ~= nil
  if ngx.ctx.edgeweir_policy and ngx.ctx.edgeweir_policy.cache_bypass then
    var.edgeweir_range_mode = "pass"
    return true
  end
  local chain = rules.chain(site, original_path, authorized)
  if not rules.may_cache(chain, authorized) then
    var.edgeweir_range_mode = "pass"
    return true
  end

  var.edgeweir_cache_bypass = "0"
  var.edgeweir_no_cache = "0"
  var.edgeweir_rules = rule_ids(chain)
  if site.slice then
    var.edgeweir_range_mode = "slice"
  end

  -- Cache rules, purge markers and the key all use nginx's normalized
  -- path, so an encoded variant of a URL can never escape a purge.
  local path = original_path
  local epoch = purge.epoch(site.id, site.cache_key, host, path, var.args)
  var.edgeweir_cache_key = cachekey.build(site, key_request(site, var, path, headers), epoch)
  return true
end

function _M.access()
  if access() then
    local site = ngx.ctx.edgeweir_site
    if site and site.waf then
      return waf.enter(site)
    end
  end
end

local function port_number(value)
  value = tostring(value or "")
  if not value:match("^%d+$") then return nil end
  local port = tonumber(value)
  if port and port >= 1 and port <= 65535 then return port end
end

-- Host describes the public authority, including when a proxy forwards to a
-- different local port. An authority without a port uses the HTTPS default.
function _M.http3_port(authority, listener_port)
  if type(authority) ~= "string" or authority == "" then
    return port_number(listener_port) or 443
  end
  if authority:sub(1, 1) == "[" then
    local host, suffix = authority:match("^%[([^%]]+)%](.*)$")
    local address = host and ipaddr.parse(host)
    if not address or #address ~= 16 then return nil end
    if suffix == "" then return 443 end
    return port_number(suffix:match("^:(%d+)$"))
  end
  if authority:match("^[A-Za-z0-9][A-Za-z0-9.-]*$") then return 443 end
  local host, port = authority:match("^([A-Za-z0-9][A-Za-z0-9.-]*):(%d+)$")
  if host then return port_number(port) end
end

-- header_filter(waf_location): waf_location in the CRS locations, where the
-- request context must come back first (a request ModSecurity blocks never
-- reaches their access phase).
function _M.header_filter(waf_location)
  local h = ngx.header
  if waf_location then
    waf.restore()
    if ngx.var.modsecurity_intervention == "1" then
      h["X-Edgeweir-Error"] = "waf-blocked"
      h["Cache-Control"] = "no-store"
    end
  end
  local site = ngx.ctx.edgeweir_site
  if ngx.var.scheme == "https" and site and site.tls and site.tls.hsts_max_age > 0 then
    local value = "max-age=" .. tostring(site.tls.hsts_max_age)
    if site.tls.hsts_include_subdomains then value = value .. "; includeSubDomains" end
    if site.tls.hsts_preload then value = value .. "; preload" end
    h["Strict-Transport-Security"] = value
  end
  if ngx.var.scheme == "https" and site and site.tls and site.tls.http3 then
    local port = _M.http3_port(ngx.var.http_host, ngx.var.server_port)
    h["Alt-Svc"] = port and ('h3=":' .. tostring(port) .. '"; ma=86400') or nil
  end
  local stashed = h["X-Edgeweir-CC"]
  if stashed then
    h["X-Edgeweir-CC"] = nil
    if stashed == "-" then
      h["Cache-Control"] = nil
    else
      h["Cache-Control"] = stashed
    end
  end
  if site then
    local ok = pcall(policy.response, site)
    if not ok then ngx.log(ngx.ERR, "edgeweir: response policy failed site=", site.id); ngx.status = 503 end
    compress.header_filter(site)
  end
end

return _M
