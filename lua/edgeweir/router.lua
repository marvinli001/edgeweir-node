-- edgeweir.router: edge layer (public listeners).
--
-- access(): answers the probes' health endpoint before anything else and
-- keeps connections with the health SNI to it (edgeweir.probehealth),
-- rejects requests that already passed this node (CDN-Loop,
-- 508), answers the HTTP-01 challenges of the node's certificates (others
-- go to the origin uncached and unchallenged), resolves the site by Host
-- (404 for unknown hosts), rejects banned
-- client addresses (403 ip-banned, edgeweir.bans), handles
-- WebSocket upgrades, evaluates the request conditions of the cache rules
-- and prepares the variables used by proxy_cache in nginx.conf: the cache
-- key (edgeweir.cachekey, including the purge epoch from edgeweir.purge),
-- whether to look up / store, the Range mode (slice, pass or strip) and the
-- origin layer (with or without TLS verification). Challenges come after
-- the rules (edgeweir.challenge, edgeweir.cc): the reserved prefix
-- /.edgeweir/ is answered at the edge, requests without a sufficient pass
-- are challenged for Under Attack and CC levels unless an allow rule or a
-- platform allow list exempts them. Config rules may turn Under Attack on
-- or off, CC off or cap its level, and WebSocket off or on for a request
-- (edgeweir.policy). The chosen cache rules (whose conditions see the
-- client's original request) travel to the origin layer in
-- X-Edgeweir-Rules, which decides the TTL once the response status and
-- size are known; origin rules' overrides travel in X-Edgeweir-Origin.
--
-- A site's access control (edgeweir.access, ADR-0039): clients on its
-- allow lists skip its bans, CC bans and challenges (and, in
-- edgeweir.policy, its block lists, geo, hotlink and user agent checks);
-- WebSocket upgrades must come from its origins (403
-- websocket-origin-denied). header_filter() and error_page() add its CORS
-- and security headers to every response of the site.
--
-- Proto v0.29.0 (ADR-0040): rules may ban (403 ip-banned), answer
-- themselves, close the connection (444) or skip challenges and the CRS
-- (edgeweir.policy); sites that let verified search engine crawlers skip
-- Under Attack and CC challenges verify a crawler only when it would be
-- challenged (edgeweir.bots); failed challenge answers count towards the
-- site's failure ban (edgeweir.challenge), never for addresses on a
-- platform allow list, the site's allow lists or trusted proxies.
--
-- Sites that run the OWASP CRS continue in the edge layer's CRS location
-- once these checks pass (edgeweir.waf); sites the edge compresses ask the
-- origin for uncompressed responses (edgeweir.compress). The origin layer
-- of a request follows the site's protocol towards the origins
-- (origin_layer()): HTTP/1.1 or HTTP/2, HTTP/1.1 for WebSocket upgrades.
-- gRPC requests of sites that proxy gRPC go to @edgeweir_grpc instead,
-- past the cache and the CRS, over HTTP/2 to the origin end to end.
--
-- The local listeners ($edgeweir_local) serve the agent's prefetches, the
-- operator's own requests: bans, CC, challenges, rules that deny and the
-- CRS do not apply there (redirects do), and edgeweir.stats does not count
-- them. Their responses that the edge made itself (no cache or origin
-- involved: redirects, error pages) carry X-Edgeweir-Edge-Response.
--
-- Purged objects: the key epoch combines the URL, prefix and site markers
-- (edgeweir.purge) with the tag markers of the object's Cache-Tag
-- (edgeweir.cachetags) for sites that have tag markers. Denials with a
-- status error pages apply to (403, 429, 503 here) and hosts no site
-- serves are answered with error pages (edgeweir.errorpages).
--
-- header_filter(): restores the origin's Cache-Control header that the
-- origin layer replaced to carry stale-* extensions for nginx's cache,
-- indexes the Cache-Tag of responses fetched for the cache (also in slice
-- and background-update subrequests), forwards Cache-Tag only for sites
-- that keep it, issues session affinity cookies (edgeweir.affinity),
-- replaces CRS blocks with error pages, applies the browser TTL of the cache
-- rule that decided the response, runs the response phases
-- (response-transform, compression) and chooses the response's content
-- coding (edgeweir.compress).
--
-- error_page(): answers nginx's own errors with error pages (error_page in
-- nginx.conf): malformed requests, too large requests, plain HTTP on an
-- HTTPS port, uncaught Lua errors and failures towards the origin layer.
--
-- Proto v0.30.0 (ADR-0041): every refusal records its block reason
-- (edgeweir.reasons) where it happens: bans (ip_banned), CC bans (cc),
-- client certificates (client_cert), maintenance (maintenance), WebSocket
-- origins (websocket_origin) and the reasons edgeweir.policy's results
-- carry; challenges record theirs (edgeweir.challenge). Once the site is
-- known (not on the local listeners), the client's GeoIP record is looked
-- up softly (edgeweir.geoip: 50 ms, skipped for 5 s after a failure) for
-- the access logs and statistics, unless the site's rules read GeoIP
-- anyway; sites that record request headers or the query string keep the
-- client's (edgeweir.accesslogs).
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local cachekey = require("edgeweir.cachekey")
local purge = require("edgeweir.purge")
local cachetags = require("edgeweir.cachetags")
local policy = require("edgeweir.policy")
local ipaddr = require("edgeweir.ipaddr")
local bans = require("edgeweir.bans")
local cc = require("edgeweir.cc")
local challenge = require("edgeweir.challenge")
local compress = require("edgeweir.compress")
local waf = require("edgeweir.waf")
local errorpages = require("edgeweir.errorpages")
local unknownhost = require("edgeweir.unknownhost")
local affinity = require("edgeweir.affinity")
local probehealth = require("edgeweir.probehealth")
local setcookie = require("edgeweir.setcookie")
local charset = require("edgeweir.charset")
local purgemethod = require("edgeweir.purgemethod")
local clientcert = require("edgeweir.clientcert")
local auth = require("edgeweir.auth")
local accesscontrol = require("edgeweir.access")
local bots = require("edgeweir.bots")
local reasons = require("edgeweir.reasons")
local geoip = require("edgeweir.geoip")
local accesslogs = require("edgeweir.accesslogs")

local _M = {}

local concat = table.concat
local lower, sub = string.lower, string.sub

-- deny answers with status and X-Edgeweir-Error code: the site's error
-- page (or the built-in one) for the statuses pages apply to, plain text
-- otherwise.
local function deny(status, code, message)
  if errorpages.STATUSES[status] then
    return errorpages.respond(status, code, ngx.ctx.edgeweir_site)
  end
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(message, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- strip_internal_headers removes client-supplied X-Edgeweir-* headers so
-- that clients can never inject internal routing or caching hints, and
-- their X-Client-Verify, X-Client-Cert-SHA256, X-Client-Cert-Subject and
-- X-Client-Cert-Serial on every site (only the node sends those, for
-- sites that forward client certificates, edgeweir.clientcert). It
-- reads every request header (no limit) and returns them: the cache key
-- is built from the same table, so a header can never be invisible to
-- one and visible to the other.
local function strip_internal_headers()
  local headers = ngx.req.get_headers(0)
  local client = clientcert.STRIP
  for name in pairs(headers) do
    if sub(name, 1, 11) == "x-edgeweir-" or client[name] then
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

-- verified_crawler reports whether the request comes from a verified
-- search engine crawler on a site that lets them skip Under Attack and CC
-- challenges (challenge-v2).
function _M.verified_crawler(site)
  local p = site.protection
  if not (p and p.allow_verified_bots) then return false end
  local ok, verified = pcall(bots.request)
  return ok and verified == true
end

-- run_challenge answers with a challenge (rule_id: the rule that asked for
-- it); failures fail closed (503).
local function run_challenge(site, kind, level, rule_id)
  local ok, err = pcall(challenge.respond, site, kind, level, rule_id)
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
-- the normalized $uri, headers every request header. nil: the key cookies
-- are ambiguous (edgeweir.cachekey.key_cookies), the request is not cached.
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
    local values = cachekey.key_cookies(headers.cookie, key.cookies)
    if not values then
      return nil
    end
    req.cookie = function(name)
      return values[name]
    end
  end
  return req
end

-- unknown answers a request no site serves (Host unknown, an IP literal
-- or empty, or a site's host on a port it is not bound to) by the
-- cluster's handling (edgeweir.unknownhost), and counts it for scan
-- protection. Returns the default site when the request is handed to it;
-- otherwise the request has been answered.
local function unknown(cfg, host, var, is_local)
  if is_local then
    return nil, errorpages.unknown_host(cfg, host)
  end
  unknownhost.count(cfg, var.remote_addr)
  local action = unknownhost.action(cfg, host)
  if action == "close" then
    return nil, ngx.exit(444)
  end
  if action == "site" then
    local site = store.site_current(cfg.unknown.default_site_id)
    if site and store.serves_port(site, var.server_port) then
      return site
    end
  end
  return nil, errorpages.unknown_host(cfg, host)
end

-- access returns true when the request goes on to the cache and origin;
-- every other outcome has answered the request already.
local function access()
  local headers = strip_internal_headers()

  local var = ngx.var
  local is_local = var.edgeweir_local == "1"
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
  end
  -- Other HTTP-01 tokens belong to the origin's own certificates: they go
  -- there, never cached and never challenged (validation servers cannot
  -- solve challenges).
  local acme = token ~= nil
  local site, ver, found = store.lookup_host(host)
  -- A site bound to other listener ports (edge-ports-v1) is unknown here;
  -- the origin's own HTTP-01 tokens still reach it on port 80.
  local unbound = site and not is_local and not store.serves_port(site, var.server_port) and not (acme and var.server_port == "80")
  local handed = false
  if not site or unbound then
    -- From the table version the lookup used: no further shared dict read.
    local cfg = (not site and ver) and store.config(ver) or store.config()
    -- Offline hosts (disabled sites) keep the platform's page.
    if not site and errorpages.offline_reason(cfg, host) then
      return errorpages.unknown_host(cfg, host)
    end
    site = unknown(cfg, host, var, is_local)
    if not site then
      return
    end
    handed = true
    found = "handed"
  end

  local ctx = ngx.ctx
  ctx.edgeweir_site = site
  -- How the site was found (edgeweir.policy: no HTTPS redirect for a host
  -- whose HTTPS handshake would not complete).
  ctx.edgeweir_found = found
  if not is_local then
    -- For the access logs and statistics; rules that read GeoIP look it up
    -- themselves (edgeweir.policy).
    if not site._geo then ctx.edgeweir_geo = geoip.lookup(var.remote_addr, true) or false end
    -- The client's headers, before rules change them.
    if site.log_headers then ctx.edgeweir_log_headers = accesslogs.request_headers(headers, site.log_headers) end
  end
  if handed then
    local u = store.config().unknown
    ngx.ctx.edgeweir_default_certificate = u and u.default_certificate and u.unknown_host == "site" or false
  end
  if site.hide_x_cache then
    var.edgeweir_x_cache_off = "1"
  end
  -- The default site takes requests whose SNI named no site (its
  -- certificate, or the health certificate without SNI): they are not
  -- another site's.
  if var.scheme == "https" and not handed and (not var.ssl_server_name or string.lower(var.ssl_server_name) ~= host) then
    return deny(421, "sni-host-mismatch", "SNI and Host must match")
  end
  -- Sites that require client certificates (client-cert-v1): 403 without
  -- a verified one, plain HTTP after the site's HTTPS redirect; the local
  -- listeners (the agent's prefetches) are the operator's own.
  local client = not is_local and clientcert.decision(site, var.scheme, var.ssl_client_verify, acme)
  if client then
    if client == "http" then
      local r = policy.site_https_redirect(site, host, var.request_uri, found, ngx.ctx.edgeweir_default_certificate)
      if r then return ngx.redirect(r.location, r.status) end
    end
    reasons.set("client_cert")
    return deny(ngx.HTTP_FORBIDDEN, "client-cert-required", "client certificate required")
  end
  -- The site's allow lists (edgeweir.access): such clients skip the site's
  -- bans and CC bans, its block lists, geo, hotlink and user agent checks
  -- and Under Attack and CC challenges.
  local site_allowed = not is_local and site._access ~= nil and accesscontrol.site_allowed(site, var.remote_addr)
  -- Dynamic bans: platform scope, then the site's (not for clients on the
  -- site's allow lists); addresses on a platform allow list and trusted
  -- proxies of the client address setting are never banned.
  if not is_local and bans.match(not site_allowed and site.id or nil, remote_addr) and not _M.platform_allowed(site, var.remote_addr) and not store.trusted_proxy(site, var.remote_addr) then
    reasons.set("ip_banned")
    return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
  end
  -- The PURGE method of sites that turned it on, before maintenance and
  -- the rules (edgeweir.purgemethod).
  if site.purge and ngx.req.get_method() == "PURGE" then
    return purgemethod.handle(site)
  end
  -- Access authentication: the rule, and a signed URL's signature removed
  -- before anything reads the path (edgeweir.auth); checked after the
  -- platform lists (edgeweir.policy).
  if site._auth then
    auth.select(site, acme)
  end
  local original_path = var.uri
  -- Maintenance: 503 and the maintenance page, but for allowed addresses
  -- and paths and HTTP-01 requests for the origin; nothing is cached.
  if site.maintenance and not acme and not _M.maintenance_allowed(site, var.remote_addr, original_path) then
    reasons.set("maintenance")
    return errorpages.maintenance(site)
  end
  ngx.ctx.edgeweir_original_path = original_path
  -- The query string the access log records: the client's, without a
  -- signed URL's signature, before rules rewrite it.
  if site.log_query then ngx.ctx.edgeweir_original_args = var.args or "" end
  var.edgeweir_site = site.id
  -- CC counts every request of the site (edgeweir.cc), clients by their
  -- IPv4 address or IPv6 /64; trusted proxies (the address of requests
  -- whose header named no client) are not counted.
  local cc_n, cc_w, cc_now, cc_addr
  if site._cc and not is_local and not store.trusted_proxy(site, var.remote_addr) then
    cc_addr = ipaddr.client_network(var.remote_addr)
    cc_n, cc_w, cc_now = cc.count(site, cc_addr, original_path)
  end
  -- The reserved prefix is answered here and never reaches the origin.
  if sub(original_path, 1, 11) == "/.edgeweir/" then
    if cc_n and not site_allowed and not _M.platform_allowed(site, var.remote_addr) and cc.check_ip(site, cc_addr, cc_n, cc_w, cc_now) then
      reasons.set("cc")
      return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
    end
    -- Failed answers count towards the site's failure ban, but not for
    -- these clients (nor on the local listeners).
    local uncounted = is_local or site_allowed or _M.platform_allowed(site, var.remote_addr) or store.trusted_proxy(site, var.remote_addr)
    local rok, err = pcall(challenge.reserved, site, uncounted)
    if not rok then
      ngx.log(ngx.ERR, "edgeweir: challenge endpoint failed site=", site.id, ": ", err)
      return deny(503, "challenge-unavailable", "challenge unavailable")
    end
    return
  end
  local ok, result = pcall(policy.access, site, headers, acme, site_allowed)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: policy evaluation failed site=", site.id)
    return deny(503, "policy-unavailable", "policy unavailable")
  end
  -- allow rules, skip actions with challenges, platform allow lists and
  -- the site's allow lists exempt from CC bans and from Under Attack and CC
  -- challenges.
  local pctx = ngx.ctx.edgeweir_policy
  local exempt = site_allowed or (pctx and (pctx.allowed or pctx.platform_allowed or pctx.skip_challenges))
  -- Config rules may turn CC off for the request (it is still counted).
  local cc_on = not (pctx and pctx.cc_enabled == false)
  if cc_n and cc_on and not exempt and cc.check_ip(site, cc_addr, cc_n, cc_w, cc_now) then
    reasons.set("cc")
    return deny(ngx.HTTP_FORBIDDEN, "ip-banned", "banned")
  end
  if result and not (is_local and not result.location) then
    if result.reason then reasons.set(result.reason, result.rule_id) end
    if result.respond then return result.respond() end
    -- A close action: no response, the connection (HTTP/2 and HTTP/3: the
    -- stream) is closed.
    if result.close then return ngx.exit(444) end
    if result.challenge then return run_challenge(site, result.challenge, result.level, result.rule_id) end
    if result.location then return ngx.redirect(result.location, result.status) end
    if result.retry_after then ngx.header["Retry-After"] = tostring(result.retry_after) end
    return deny(result.status, result.code or "policy-denied", result.message or "request denied")
  end
  local under_attack = pctx and pctx.under_attack
  if (site._guard or under_attack == true) and not exempt and not is_local and not acme then
    local cc_level = policy.cc_level(pctx, site._cc and cc_on and cc.level(site, original_path) or 0)
    local level, kind = challenge.required(site, cc_level, under_attack)
    if level > 0 and challenge.pass_level(site) < level and not _M.verified_crawler(site) then
      return run_challenge(site, kind, level)
    end
  end
  -- The client certificate towards the origin (after the rules: they
  -- never overwrite it).
  if site._client and site._client.forward then
    clientcert.forward(clientcert.values())
  end
  headers = ngx.req.get_headers(0)
  -- The variable's default is "": only origin and timeout overrides set it.
  local override = policy.origin_header(pctx)
  if override ~= "" then
    var.edgeweir_origin_override = override
  end

  var.edgeweir_site = site.id
  var.edgeweir_cache_zone = site.cache_zone
  -- The edge compresses: the origin sends (and the cache keeps) identity.
  if compress.enabled(site) then
    var.edgeweir_strip_ae = "1"
  end

  local upgrade = var.http_upgrade
  if upgrade and lower(upgrade) == "websocket" then
    local websocket = site.websocket
    if pctx and pctx.websocket ~= nil then
      websocket = pctx.websocket
    end
    if not websocket then
      return deny(ngx.HTTP_FORBIDDEN, "websocket-disabled", "websocket disabled")
    end
    -- The site's WebSocket origins (edgeweir.access); clients on its allow
    -- lists are checked too, the local listeners are not.
    if not is_local and not accesscontrol.websocket_allowed(site, var.http_origin) then
      reasons.set("websocket_origin")
      return deny(ngx.HTTP_FORBIDDEN, "websocket-origin-denied", "websocket origin denied")
    end
    -- Proxied as is, never cached.
    var.edgeweir_origin_layer = _M.origin_layer(site, "websocket")
    var.edgeweir_upgrade = "websocket"
    var.edgeweir_connection = "upgrade"
    return true
  end
  if site.grpc and _M.is_grpc(var.http_content_type) then
    -- Never cached: _M.access hands it to @edgeweir_grpc.
    var.edgeweir_origin_layer = _M.origin_layer(site, "grpc")
    ngx.ctx.edgeweir_grpc = true
    return true
  end
  -- The site's body limit (a config rule's for this request) by
  -- Content-Length; chunked bodies are bounded by client_max_body_size.
  if _M.body_too_large(pctx and pctx.body_limit, site.body_limit, var.http_content_length) then
    return deny(413, "body-too-large", "request body too large")
  end
  var.edgeweir_origin_layer = _M.origin_layer(site)

  local method = ngx.req.get_method()
  if (method ~= "GET" and method ~= "HEAD") or acme then
    var.edgeweir_range_mode = "pass"
    return true
  end
  -- RFC 9111, section 3.5: responses to requests with Authorization are
  -- shared only when the applying rule allows it (cache_authorized).
  local authorized = var.http_authorization ~= nil
  if pctx and pctx.cache_bypass then
    var.edgeweir_range_mode = "pass"
    return true
  end
  local chain = rules.chain(site, original_path, authorized, pctx and pctx.original)
  if not rules.may_cache(chain, authorized) then
    var.edgeweir_range_mode = "pass"
    return true
  end
  -- Cache rules, purge markers and the key all use nginx's normalized
  -- path, so an encoded variant of a URL can never escape a purge.
  local path = original_path
  local req = key_request(site, var, path, headers)
  if not req then
    var.edgeweir_range_mode = "pass"
    return true
  end
  req.handed = ngx.ctx.edgeweir_found == "handed"
  if site._browser_ttl then
    -- For the browser TTL of the rule that decides the response.
    local ctx = ngx.ctx
    ctx.edgeweir_chain = chain
    ctx.edgeweir_authorized = authorized
  end

  var.edgeweir_cache_bypass = "0"
  var.edgeweir_no_cache = "0"
  var.edgeweir_rules = rule_ids(chain)
  if site.slice then
    var.edgeweir_range_mode = "slice"
  end

  local epoch = purge.epoch(site.id, site.cache_key, host, path, var.args)
  local tmax = purge.tag_max(site.id)
  if tmax then
    -- The site has tag markers: the object's tags may move its key.
    local base = cachekey.build(site, req, 0)
    var.edgeweir_cache_key = cachekey.with_epoch(base, cachetags.key_epoch(site.id, base, epoch, tmax))
  else
    var.edgeweir_cache_key = cachekey.build(site, req, epoch)
  end
  return true
end

function _M.access()
  local var = ngx.var
  -- The probes' health endpoint, for any Host, before CDN-Loop, HTTP-01,
  -- the site lookup, bans, rules and CC: never cached, counted or logged.
  if probehealth.is_request(ngx.req.get_method(), var.uri) then
    -- Not even the live view sees them (edgeweir.stats).
    ngx.ctx.edgeweir_probe = true
    return probehealth.respond()
  end
  -- A connection with the health SNI (or none) serves only that path,
  -- and requests by node IP when the cluster closes them or hands them to
  -- its default site (unknown-host-v1).
  if var.scheme == "https" and probehealth.is_health_sni(var.ssl_server_name) then
    local cfg = store.config()
    local u = cfg.unknown
    if not (u and unknownhost.ip_access(var.host) and u.ip_access ~= "page") then
      if u and unknownhost.ip_access(var.host) then
        unknownhost.count(cfg, var.remote_addr)
      end
      return deny(421, "sni-host-mismatch", "SNI and Host must match")
    end
  end
  if access() then
    local ctx = ngx.ctx
    if ctx.edgeweir_grpc then
      return _M.grpc_enter()
    end
    local site = ctx.edgeweir_site
    if site and site.waf and var.edgeweir_local ~= "1" then
      return waf.enter(site)
    end
  end
end

-- maintenance_allowed reports whether a request of a site in maintenance
-- is served as usual: its client address in the allowed CIDRs or its
-- original path under an allowed prefix.
function _M.maintenance_allowed(site, addr, path)
  local allow = site._maintenance_allow
  if allow and addr and allow(addr) then
    return true
  end
  local prefixes = site.maintenance.allow_prefixes
  if type(prefixes) == "table" then
    for i = 1, #prefixes do
      local p = prefixes[i]
      if sub(path, 1, #p) == p then
        return true
      end
    end
  end
  return false
end

-- body_too_large reports whether a request's Content-Length exceeds its
-- body limit: the config rule's (rule_limit) when one set it, else the
-- site's; 0 or nil means no limit.
function _M.body_too_large(rule_limit, site_limit, content_length)
  local limit = rule_limit
  if limit == nil then
    limit = site_limit
  end
  limit = tonumber(limit)
  local length = tonumber(content_length)
  return limit ~= nil and limit > 0 and length ~= nil and length > limit
end

-- origin_layer returns the edge layer's upstream of the origin layer for a
-- request of site (the value of $edgeweir_origin_layer, nginx.conf): with
-- or without TLS verification, and by the protocol towards the origins.
-- kind is "websocket" for WebSocket upgrades, which nginx proxies over
-- HTTP/1.1 only, "grpc" for the gRPC requests of sites that proxy gRPC,
-- nil for every other request.
function _M.origin_layer(site, kind)
  local layer = site.tls_verify and "edgeweir_origin_verify" or "edgeweir_origin_noverify"
  if kind == "grpc" then
    return layer .. "_grpc"
  end
  if site.origin_http2 and kind ~= "websocket" then
    return layer .. "_h2"
  end
  return layer
end

-- is_grpc reports whether a Content-Type value names gRPC:
-- application/grpc, optionally with a "+" suffix (+proto, +json) or
-- parameters. gRPC-Web (application/grpc-web, -text) is not: it works over
-- HTTP/1.1 and carries its trailers in the body.
function _M.is_grpc(content_type)
  if type(content_type) ~= "string" then
    return false
  end
  local ct = lower(content_type)
  if sub(ct, 1, 16) ~= "application/grpc" then
    return false
  end
  local after = sub(ct, 17, 17)
  return after == "" or after == "+" or after == ";" or after == " " or after == "\t"
end

-- grpc_enter hands a gRPC request to @edgeweir_grpc (nginx.conf) at the
-- end of the access phase, past the CRS: ModSecurity reads a request's
-- whole body before passing it on, which a streaming call never ends. The
-- request context travels like a CRS request's (edgeweir.waf.stash_ctx).
function _M.grpc_enter()
  ngx.var.edgeweir_ctx_ref = waf.stash_ctx(ngx.ctx)
  return ngx.exec("@edgeweir_grpc")
end

-- grpc_access runs in @edgeweir_grpc's access phase: the request context
-- comes back.
function _M.grpc_access()
  waf.restore()
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

-- response_size returns the full entity size of a response when known
-- (Content-Range of a 206, else Content-Length), like the origin layer's.
function _M.response_size(h, status)
  if status == 206 then
    local range = h["Content-Range"]
    local total = type(range) == "string" and range:match("/(%d+)$")
    if total then
      return tonumber(total)
    end
  end
  local length = h["Content-Length"]
  if type(length) == "table" then
    length = length[1]
  end
  return tonumber(length)
end

-- FROM_CACHE are the cache statuses of responses the edge cache served:
-- they get no affinity cookie (a cached object may hold the internal
-- X-Edgeweir-Affinity header of another client's response).
local FROM_CACHE = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }

-- header_filter(waf_location): waf_location in the CRS and gRPC locations,
-- where the request context must come back first (a request ModSecurity
-- blocks never reaches their access phase).
function _M.header_filter(waf_location)
  local h = ngx.header
  local var = ngx.var
  -- The Cache-Tag index learns the tags of every response fetched for the
  -- cache, slices and background updates included (subrequests share the
  -- main request's variables but not its ngx.ctx).
  local cs = var.upstream_cache_status
  if var.edgeweir_local == "1" and (cs == nil or cs == "") then
    h["X-Edgeweir-Edge-Response"] = "1"
  end
  if (cs == "MISS" or cs == "EXPIRED") and var.edgeweir_no_cache == "0" then
    cachetags.record(var.edgeweir_site, var.edgeweir_cache_key, var.upstream_http_cache_tag, store.config().tag_ttl)
  end
  if waf_location then
    waf.restore()
    if var.modsecurity_intervention == "1" then
      local status = ngx.status
      if errorpages.STATUSES[status] and not ngx.is_subrequest then
        errorpages.replace(status, "waf-blocked", ngx.ctx.edgeweir_site, false)
      else
        h["X-Edgeweir-Error"] = "waf-blocked"
        h["Cache-Control"] = "no-store"
      end
    end
  end
  local site = ngx.ctx.edgeweir_site
  -- Set-Cookie lines cached with the response (edgeweir.setcookie): only
  -- on the response fetched for this request, before the affinity cookie.
  if site then
    setcookie.restore(h, var.upstream_http_x_edgeweir_set_cookie, cs, ngx.is_subrequest)
  end
  if site and site.keep_cache_tag then
    -- proxy_hide_header removes Cache-Tag for every other site, cache hits
    -- included.
    h["Cache-Tag"] = var.upstream_http_cache_tag
  end
  if site and site._affinity_ttl and not FROM_CACHE[cs or ""] then
    local value = var.upstream_http_x_edgeweir_affinity
    if value and value ~= "" and affinity.valid_value(value) then
      affinity.append_cookie(h, affinity.cookie(value, site._affinity_ttl, var.scheme == "https"))
    end
  end
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
  -- The browser TTL replaces the origin's Cache-Control (restored above)
  -- on responses the deciding cache rule caches; response rules may still
  -- change it.
  if site and site._browser_ttl and not ngx.is_subrequest then
    local ctx = ngx.ctx
    local chain = ctx.edgeweir_chain
    if chain then
      local status = ngx.status
      local value = rules.browser_cache_control(chain, status, _M.response_size(h, status), ctx.edgeweir_authorized, h["Cache-Control"])
      if value then
        h["Cache-Control"] = value
      end
    end
  end
  if site then
    -- Only responses of the origin layer (fetched or from the cache) get
    -- the site's charset: what the node makes itself (challenge pages and
    -- scripts, PURGE answers, error pages) keeps its own.
    local proxied = (cs ~= nil and cs ~= "") or (var.upstream_status or "") ~= ""
    if site.charset and proxied and not h["X-Edgeweir-Error"] then
      charset.apply(h, site.charset)
    end
    -- Access control's CORS and security headers (edgeweir.access) on
    -- every response of the site, before the response phases: rules win.
    if site._access and not ngx.is_subrequest then
      accesscontrol.response_headers(site, h, ngx.ctx.edgeweir_original_path or var.uri)
    end
    if site._response_rules then
      local ok = pcall(policy.response, site)
      if not ok then ngx.log(ngx.ERR, "edgeweir: response policy failed site=", site.id); ngx.status = 503 end
    end
    -- The gRPC location compresses nothing.
    if not ngx.ctx.edgeweir_grpc then
      compress.header_filter(site)
    end
  end
end

-- body_filter sends the error page header_filter prepared (CRS locations
-- only: the edge layer's location / has no body filter).
function _M.body_filter()
  return errorpages.body_filter()
end

-- error_page answers nginx's own errors (content phase of @edgeweir_error,
-- or of /./edgeweir-error for requests without a URI yet): malformed
-- requests and CRS blocks with status 400, request headers (494) and URIs
-- (414) that are too long, bodies over client_max_body_size (413), plain
-- HTTP on an HTTPS port (497), uncaught Lua errors (500) and the origin
-- layer's failures (502, 504) when the cache had no stale copy to serve.
-- The redirect emptied ngx.ctx: a CRS location's context comes back
-- (edgeweir.waf), else the site of $edgeweir_site, so that the location's
-- log phase (edgeweir.stats) counts the request like the location it came
-- from. Subrequests (slices, background updates) keep nginx's own answer.
function _M.error_page()
  local status = ngx.status
  if ngx.is_subrequest then
    return ngx.exit(status)
  end
  waf.restore()
  local ctx = ngx.ctx
  local var = ngx.var
  local site = ctx.edgeweir_site
  if not site then
    local id = var.edgeweir_site
    site = id and id ~= "" and store.site_current(id) or nil
    ctx.edgeweir_site = site
  end
  if var.edgeweir_local == "1" and (var.upstream_cache_status or "") == "" then
    ngx.header["X-Edgeweir-Edge-Response"] = "1"
  end
  -- This location has no header filter: access control's CORS and security
  -- headers here (edgeweir.access).
  if site and site._access then
    accesscontrol.response_headers(site, ngx.header, var.uri)
  end
  return errorpages.nginx_page(status, site, ctx.edgeweir_waf == true and var.modsecurity_intervention == "1", false)
end

return _M
