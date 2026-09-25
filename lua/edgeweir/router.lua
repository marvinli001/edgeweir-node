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

local _M = {}

local concat = table.concat
local find, lower, sub = string.find, string.lower, string.sub

local function deny(status, code, message)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(message, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- strip_internal_headers removes client-supplied X-Edgeweir-* headers so
-- that clients can never inject internal routing or caching hints.
local function strip_internal_headers()
  local headers = ngx.req.get_headers(0)
  for name in pairs(headers) do
    if sub(name, 1, 11) == "x-edgeweir-" then
      ngx.req.clear_header(name)
    end
  end
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

-- key_request collects what the cache key policy of site needs.
local function key_request(site, var, path)
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
    req.headers = ngx.req.get_headers(100)
  end
  if #key.cookies > 0 then
    req.cookie = function(name)
      return ngx.var["cookie_" .. name]
    end
  end
  return req
end

function _M.access()
  strip_internal_headers()

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
  local site = store.lookup_host(host)
  if not site then
    return deny(ngx.HTTP_NOT_FOUND, "unknown-host", "unknown host")
  end

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
  local chain = rules.chain(site, var.uri)
  if not rules.may_cache(chain) then
    var.edgeweir_range_mode = "pass"
    return
  end

  var.edgeweir_cache_bypass = "0"
  var.edgeweir_no_cache = "0"
  var.edgeweir_rules = rule_ids(chain)
  if site.slice then
    var.edgeweir_range_mode = "slice"
  end

  local request_uri = var.request_uri
  local q = find(request_uri, "?", 1, true)
  local path = q and sub(request_uri, 1, q - 1) or request_uri
  local epoch = purge.epoch(site.id, site.cache_key, host, path, var.args)
  var.edgeweir_cache_key = cachekey.build(site, key_request(site, var, path), epoch)
end

function _M.header_filter()
  local h = ngx.header
  local stashed = h["X-Edgeweir-CC"]
  if stashed then
    h["X-Edgeweir-CC"] = nil
    if stashed == "-" then
      h["Cache-Control"] = nil
    else
      h["Cache-Control"] = stashed
    end
  end
end

return _M
