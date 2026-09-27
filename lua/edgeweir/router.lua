-- edgeweir.router: edge layer (public listeners).
--
-- access(): rejects requests that already passed this node (CDN-Loop,
-- 508), resolves the site by Host (404 for unknown hosts), handles
-- WebSocket upgrades, evaluates the request conditions of the cache rules
-- and prepares the variables used by proxy_cache in nginx.conf: the cache
-- key (edgeweir.cachekey, including the purge epoch from edgeweir.purge),
-- whether to look up / store, the Range mode (slice, pass or strip) and the
-- origin layer (with or without TLS verification). The chosen rules travel
-- to the origin layer in X-Edgeweir-Rules, which decides the TTL once the
-- response status and size are known.
--
-- header_filter(): restores the origin's Cache-Control header that the
-- origin layer replaced to carry stale-* extensions for nginx's cache.
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local cachekey = require("edgeweir.cachekey")
local purge = require("edgeweir.purge")
local policy = require("edgeweir.policy")
local ipaddr = require("edgeweir.ipaddr")

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

function _M.access()
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
  local original_path = var.uri
  ngx.ctx.edgeweir_original_path = original_path
  var.edgeweir_site = site.id
  local ok, result = pcall(policy.access, site, headers)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: policy evaluation failed site=", site.id)
    return deny(503, "policy-unavailable", "policy unavailable")
  end
  if result then
    if result.location then return ngx.redirect(result.location, result.status) end
    if result.retry_after then ngx.header["Retry-After"] = tostring(result.retry_after) end
    return deny(result.status, "policy-denied", "request denied")
  end
  headers = ngx.req.get_headers(0)

  var.edgeweir_site = site.id
  var.edgeweir_cache_zone = site.cache_zone
  if not site.tls_verify then
    var.edgeweir_origin_layer = "edgeweir_origin_noverify"
  end

  local upgrade = var.http_upgrade
  if upgrade and lower(upgrade) == "websocket" then
    if not site.websocket then
      return deny(ngx.HTTP_FORBIDDEN, "websocket-disabled", "websocket disabled")
    end
    -- Proxied as is, never cached.
    var.edgeweir_upgrade = "websocket"
    var.edgeweir_connection = "upgrade"
    return
  end

  local method = ngx.req.get_method()
  if method ~= "GET" and method ~= "HEAD" then
    var.edgeweir_range_mode = "pass"
    return
  end
  -- RFC 9111, section 3.5: responses to requests with Authorization are
  -- shared only when the applying rule allows it (cache_authorized).
  local authorized = var.http_authorization ~= nil
  if ngx.ctx.edgeweir_policy and ngx.ctx.edgeweir_policy.cache_bypass then
    var.edgeweir_range_mode = "pass"
    return
  end
  local chain = rules.chain(site, original_path, authorized)
  if not rules.may_cache(chain, authorized) then
    var.edgeweir_range_mode = "pass"
    return
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

function _M.header_filter()
  local h = ngx.header
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
  end
end

return _M
