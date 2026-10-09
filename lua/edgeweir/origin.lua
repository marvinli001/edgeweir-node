-- edgeweir.origin: origin layer (unix sockets behind the edge cache).
--
-- access():        orders the origins of the request's origin group
--                  (edgeweir.lb), applies the origin rules' overrides
--                  (X-Edgeweir-Origin from the edge layer, see
--                  edgeweir.policy.origin_header: group, Host, SNI, port,
--                  timeouts), resolves their names (edgeweir.dns), signs
--                  S3 requests (edgeweir.sigv4) and sets the variables
--                  used by proxy_pass.
-- balance():       balancer_by_lua: one call per attempt; sets the peer,
--                  retries, timeouts and the keep-alive pool, and rebuilds
--                  the request when a retry goes to an origin with another
--                  Host or S3 signature.
-- header_filter(): hands origin failures back as transport errors when
--                  the edge holds an expired copy it may serve instead
--                  (first: a stale copy wins over any error page), replaces
--                  nginx's own upstream failures and, for sites that
--                  intercept origin errors, origin responses whose status
--                  has a page with error pages (edgeweir.errorpages, sent
--                  by body_filter()), announces session affinity cookies
--                  (edgeweir.affinity) and decides caching for the edge
--                  layer: X-Accel-Expires from the matching cache rule,
--                  stale-while-revalidate and stale-if-error as
--                  Cache-Control extensions (the original header travels in
--                  X-Edgeweir-CC and the edge restores it).
-- auth_access():   a forward authentication subrequest of the edge layer
--                  (X-Edgeweir-Auth: the rule's id; edgeweir.auth): the
--                  rule's service instead of the site's origins, resolved
--                  and checked like them (origin address policy), one try
--                  with the rule's timeout, only the forwarded request
--                  headers; nothing here caches, intercepts or counts it.
-- log():           passive health accounting from $upstream_status.
-- error_page():    nginx's own errors in this layer (uncaught Lua errors,
--                  requests nginx refuses): the stale copy first, as in
--                  header_filter(), else an error page.
--
-- nginx never forwards X-Accel-* headers to clients.
local ngx_balancer = require("ngx.balancer")
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local lb = require("edgeweir.lb")
local dns = require("edgeweir.dns")
local health = require("edgeweir.health")
local sigv4 = require("edgeweir.sigv4")
local upstreamerr = require("edgeweir.upstreamerr")
local compress = require("edgeweir.compress")
local errorpages = require("edgeweir.errorpages")
local affinity = require("edgeweir.affinity")
local challenge = require("edgeweir.challenge")
local policy = require("edgeweir.policy")
local setcookie = require("edgeweir.setcookie")

local _M = {}

-- NO_OVERRIDE stands for a request without origin rule overrides.
local NO_OVERRIDE = {}

local concat = table.concat
local find, gmatch, gsub, sub = string.find, string.gmatch, string.gsub, string.sub
local tonumber = tonumber

-- fail answers with the origin layer's own failure: an error page (never
-- cached by the edge) for the statuses pages apply to, plain text
-- otherwise.
local function fail(status, code, site)
  ngx.ctx.edgeweir_failed = true
  if errorpages.STATUSES[status] then
    return errorpages.origin_fail(status, code, site)
  end
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(code, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- chain_from_header rebuilds the rule chain chosen by the edge layer from
-- the rule ids it sent in X-Edgeweir-Rules.
local function chain_from_header(site, value)
  if not value or value == "" or not site.cache_rules then
    return nil
  end
  local by_id = site._rules_by_id
  if not by_id then
    by_id = {}
    for _, r in ipairs(site.cache_rules) do
      by_id[r.id] = r
    end
    site._rules_by_id = by_id
  end
  local chain
  for id in gmatch(value, "[^,]+") do
    local r = by_id[id]
    if r then
      chain = chain or {}
      chain[#chain + 1] = r
    end
  end
  return chain
end

-- amz_headers returns the client's x-amz-* request header names (sorted).
-- S3 origins must never receive them: SigV4 covers every x-amz-* header
-- and this node signs only its own, so a forwarded one
-- (x-amz-security-token, x-amz-server-side-encryption-customer-key,
-- x-amz-request-payer, ...) would travel unsigned and either break the
-- signature or change what the origin does.
function _M.amz_headers(headers)
  local out = {}
  for name in pairs(headers or {}) do
    if string.lower(sub(name, 1, 6)) == "x-amz-" then
      out[#out + 1] = name
    end
  end
  table.sort(out)
  return out
end

-- effective returns origin o with the overrides of an origin rule (ov from
-- policy.parse_origin_header): the port of every origin, the Host of
-- origins that are not S3 (their signing host keeps its own logic) and the
-- SNI. A copy with the derived fields recomputed; o itself when nothing
-- changes.
function _M.effective(o, ov)
  if not ov or (not ov.port and not ov.sni and (not ov.host or o.s3)) then
    return o
  end
  local c = {}
  for k, v in pairs(o) do
    c[k] = v
  end
  if ov.port then
    c.port = ov.port
  end
  if ov.host and not o.s3 then
    c.host_header = ov.host
  end
  if ov.sni then
    c.sni = ov.sni
  end
  return store.derive_origin(c)
end

local function raw_path(request_uri)
  local q = find(request_uri, "?", 1, true)
  return q and sub(request_uri, 1, q - 1) or request_uri
end

-- apply points the proxy variables at candidate c.
local function apply(c)
  local var = ngx.var
  local o = c.origin
  var.edgeweir_upstream_scheme = o.scheme
  local host = o.host_header
  if not host or host == "" then
    host = o.s3 and o._s3_host or (var.http_host or "")
  end
  var.edgeweir_upstream_host = host
  if o.s3 then
    local s3 = o.s3
    local prefix = (s3.bucket and s3.bucket ~= "") and ("/" .. s3.bucket) or ""
    local signed, err = sigv4.sign_s3({
      method = ngx.req.get_method(),
      host = host,
      path = prefix .. raw_path(var.request_uri),
      region = s3.region,
      access_key = s3.access_key,
      secret_key = s3.secret_key,
    })
    if not signed then
      return nil, err
    end
    -- The client query string is not forwarded to object storage.
    var.edgeweir_upstream_uri = signed.uri
    var.edgeweir_authorization = signed.authorization
    var.edgeweir_amz_date = signed.amz_date
    var.edgeweir_amz_content_sha256 = signed.content_sha256
  else
    var.edgeweir_upstream_uri = var.request_uri
    var.edgeweir_authorization = var.http_authorization or ""
    var.edgeweir_amz_date = var.http_x_amz_date or ""
    var.edgeweir_amz_content_sha256 = var.http_x_amz_content_sha256 or ""
  end
  return true
end

-- AUTH_BODY bounds the body of a forward authentication answer this
-- layer passes on: one byte more than the edge accepts (edgeweir.auth
-- MAX_BODY), so that the edge tells a larger one apart.
_M.AUTH_BODY = 65537

-- Request headers every forward authentication request keeps: the node's
-- own (set by the edge's /./edgeweir-auth location).
local AUTH_NODE_HEADERS = {
  ["x-original-uri"] = true, ["x-original-method"] = true, ["x-original-host"] = true,
  ["x-real-ip"] = true, ["x-forwarded-for"] = true,
}

-- auth_fail answers a forward authentication subrequest that cannot be
-- sent (502): the edge treats it as the service being unavailable.
local function auth_fail(site, rule_id, why)
  ngx.log(ngx.INFO, "edgeweir: access authentication request not sent site=", site.id, " rule=", rule_id, ": ", why)
  ngx.status = ngx.HTTP_BAD_GATEWAY
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.print("authentication service unavailable\n")
  return ngx.exit(ngx.HTTP_OK)
end

function _M.auth_access(site, rule_id)
  local rule
  for _, r in ipairs(site._auth or {}) do
    if r.id == rule_id and r.forward then rule = r; break end
  end
  if not rule then return auth_fail(site, rule_id, "no such rule") end
  local f = rule.forward
  local var = ngx.var
  if f.forbidden then
    return auth_fail(site, rule_id, "address " .. f.address .. " is a special-purpose address outside the origin allow list")
  end
  if f.scheme == "https" and var.edgeweir_trust_store == "missing" then
    return auth_fail(site, rule_id, "no CA bundle to verify the service's certificate")
  end
  local ip, err = dns.resolve(f.address, store.config().allowed)
  if not ip then return auth_fail(site, rule_id, err) end
  local keep = rule._keep
  if not keep then
    keep = {}
    for name in pairs(AUTH_NODE_HEADERS) do keep[name] = true end
    for _, name in ipairs(rule.request_headers or {}) do keep[name] = true end
    rule._keep = keep
  end
  for name in pairs(ngx.req.get_headers(0)) do
    if not keep[name] then ngx.req.clear_header(name) end
  end
  var.edgeweir_upstream_scheme = f.scheme
  var.edgeweir_upstream_host = f.host_header
  var.edgeweir_upstream_uri = f.uri
  var.edgeweir_authorization = keep.authorization and (var.http_authorization or "") or ""
  var.edgeweir_amz_date = ""
  var.edgeweir_amz_content_sha256 = ""
  local sni = f.sni ~= nil and f.sni ~= "" and f.sni or nil
  ngx.ctx.auth = {
    ip = ip, port = f.port, sni = f.scheme == "https" and sni or nil,
    ssl_name = f.scheme == "https" and (sni or f.address) or "",
    timeout = (tonumber(f.timeout_ms) or 5000) / 1000,
  }
end

function _M.access()
  local var = ngx.var
  local site_id = var.http_x_edgeweir_site
  if not site_id or site_id == "" then
    return fail(ngx.HTTP_FORBIDDEN, "missing-site")
  end
  local site = store.site_current(site_id)
  if not site then
    return fail(ngx.HTTP_BAD_GATEWAY, "unknown-site")
  end
  -- Only the edge layer's /./edgeweir-auth location sets it (clients'
  -- X-Edgeweir-* headers never get past the edge).
  local auth_rule = var.http_x_edgeweir_auth
  if auth_rule and auth_rule ~= "" then
    return _M.auth_access(site, auth_rule)
  end
  -- Sites that do not retry after 502, 503 and 504 responses continue in
  -- the location whose next upstream conditions leave them out.
  if site.no_status_retry and var.edgeweir_noretry ~= "1" then
    return ngx.exec("@edgeweir_origin_noretry")
  end
  local ctx = ngx.ctx
  ctx.site = site
  ctx.chain = chain_from_header(site, var.http_x_edgeweir_rules)
  -- Only the edge layer sets it (proxy_set_header; clients' X-Edgeweir-*
  -- headers never get past the edge).
  local ov = policy.parse_origin_header(var.http_x_edgeweir_origin)
  ctx.override = ov
  -- The edge forwards the client's Authorization unchanged.
  ctx.authorized = var.http_authorization ~= nil
  ctx.upgrade = var.http_upgrade ~= nil and var.http_upgrade ~= ""

  local now = ngx.now()
  -- Session affinity: a valid cookie pins the origin that served the
  -- client (no keys yet: no pin, no cookie).
  local pin
  if site._affinity_ttl then
    local keys = challenge.keys()
    if keys and keys.current then
      local exp
      pin, exp = affinity.verify(keys, site.id, var["cookie_" .. affinity.COOKIE], ngx.time())
      ctx.affinity = { key = keys.current, pin = pin, exp = exp }
    end
  end
  local method = ngx.req.get_method()
  local allowed = store.config().allowed
  local cands, scheme, s3_refused = {}, nil, false
  for _, listed in ipairs(lb.order(site, var.request_uri, now, pin, ov and ov.group)) do
    local o = _M.effective(listed, ov)
    local usable = true
    if o.forbidden then
      -- Refused by the agent already (special-purpose IP literal).
      usable = false
      health.failure(site.id, o.id, "address " .. o.address .. " is a special-purpose address outside the origin allow list",
        site.health.max_fails, site.health.recovery_seconds, now, "address_forbidden", { address = o.address })
    elseif o.s3 and method ~= "GET" and method ~= "HEAD" then
      usable, s3_refused = false, true
    elseif o.s3 and not o.s3.secret_key then
      usable = false
      health.failure(site.id, o.id, "no credential for S3 signing", site.health.max_fails,
        site.health.recovery_seconds, now)
    elseif o.scheme == "https" and site.tls_verify and var.edgeweir_trust_store == "missing" then
      -- No CA bundle on this node: origins that must be verified fail closed.
      usable = false
      health.failure(site.id, o.id, "no CA bundle to verify the origin certificate",
        site.health.max_fails, site.health.recovery_seconds, now)
    elseif scheme and o.scheme ~= scheme then
      -- A retry cannot switch between HTTP and HTTPS; the next request will.
      usable = false
    end
    if usable then
      local ip, err, code, params = dns.resolve(o.address, allowed)
      if ip then
        scheme = scheme or o.scheme
        cands[#cands + 1] = { origin = o, ip = ip }
      else
        health.failure(site.id, o.id, err, site.health.max_fails, site.health.recovery_seconds, now, code, params)
      end
    end
  end
  -- A request tries at most the site's number of origins (OriginPool.tries).
  for i = #cands, (tonumber(site.tries) or 3) + 1, -1 do
    cands[i] = nil
  end
  if #cands == 0 then
    if s3_refused then
      ngx.header["Allow"] = "GET, HEAD"
      return fail(ngx.HTTP_NOT_ALLOWED, "method-not-allowed", site)
    end
    return fail(ngx.HTTP_BAD_GATEWAY, "no-origin", site)
  end
  for i = 1, #cands do
    if cands[i].origin.s3 then
      for _, name in ipairs(_M.amz_headers(ngx.req.get_headers(0))) do
        ngx.req.clear_header(name)
      end
      break
    end
  end
  ctx.cands = cands
  ctx.tried = {}
  local ok, err = apply(cands[1])
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: cannot sign origin request: ", err)
    return fail(ngx.HTTP_BAD_GATEWAY, "origin-signing", site)
  end
end

local function same_request(a, b)
  return a.origin.host_header == b.origin.host_header and a.origin.s3 == nil and b.origin.s3 == nil
end

function _M.balance()
  local ctx = ngx.ctx
  local a = ctx.auth
  if a then
    -- One try: a failure is the service being unavailable.
    if a.tried then return ngx.exit(ngx.ERROR) end
    a.tried = true
    ngx.var.edgeweir_ssl_name = a.ssl_name
    local ok, err = ngx_balancer.set_current_peer(a.ip, a.port, a.sni)
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: set_current_peer ", a.ip, ":", a.port, ": ", err)
      return ngx.exit(ngx.ERROR)
    end
    ngx_balancer.set_timeouts(a.timeout, a.timeout, a.timeout)
    return
  end
  local n = (ctx.try or 0) + 1
  ctx.try = n
  local c = ctx.cands and ctx.cands[n]
  if not c then
    return ngx.exit(ngx.ERROR)
  end
  local o = c.origin
  if n > 1 and not same_request(ctx.cands[n - 1], c) then
    local ok, err = apply(c)
    if ok then
      ok, err = ngx_balancer.recreate_request()
    end
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: cannot prepare retry to ", o.address, ": ", err)
      return ngx.exit(ngx.ERROR)
    end
  end
  -- The name nginx sends as SNI and verifies the certificate against
  -- (proxy_ssl_name) is set for every attempt: a retry may go to an origin
  -- with another SNI even when the request itself is unchanged. It equals
  -- the SNI passed to set_current_peer, which also keys the keep-alive
  -- pool.
  local sni = o.scheme == "https" and o.sni_name or nil
  ngx.var.edgeweir_ssl_name = sni or ""
  local ok, err = ngx_balancer.set_current_peer(c.ip, o.port, sni)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: set_current_peer ", c.ip, ":", o.port, ": ", err)
    return ngx.exit(ngx.ERROR)
  end
  if n == 1 and #ctx.cands > 1 then
    ngx_balancer.set_more_tries(#ctx.cands - 1)
  end
  local conn = ctx.site.conn
  ngx_balancer.set_timeouts(_M.timeouts(conn, ctx.override or NO_OVERRIDE, ctx.upgrade and (ctx.site._ws_idle_ms or true)))
  -- Unverified TLS connections are never pooled: a site that verifies must
  -- not reuse a connection another site opened without verification.
  if conn.keepalive and not ctx.upgrade and (o.scheme ~= "https" or ctx.site.tls_verify) then
    ngx_balancer.enable_keepalive(conn.keepalive_idle, conn.keepalive_requests)
  end
  ctx.tried[n] = c
end

-- response_size returns the full entity size of the response when known.
local function response_size(h, status)
  if status == 206 then
    local range = h["Content-Range"]
    local total = type(range) == "string" and range:match("/(%d+)$")
    if total then
      return tonumber(total)
    end
  end
  return tonumber(h["Content-Length"])
end

local function flatten(v)
  if type(v) == "table" then
    return concat(v, ", ")
  end
  return v
end

-- strip_directives removes the given Cache-Control directives.
local function strip_directives(cc, names)
  local kept = {}
  for part in gmatch(cc or "", "[^,]+") do
    local d = gsub(gsub(part, "^%s+", ""), "%s+$", "")
    local name = d:match("^([^=]+)")
    if d ~= "" and not (name and names[name:lower()]) then
      kept[#kept + 1] = d
    end
  end
  return kept
end

local STALE = { ["stale-while-revalidate"] = true, ["stale-if-error"] = true }
local FRESHNESS = {
  ["stale-while-revalidate"] = true, ["stale-if-error"] = true, ["max-age"] = true,
  ["s-maxage"] = true, ["no-cache"] = true, ["no-store"] = true, ["private"] = true,
  ["public"] = true, ["must-revalidate"] = true, ["proxy-revalidate"] = true,
}

local function stale_capable(chain, authorized)
  if not chain then
    return false
  end
  for i = 1, #chain do
    local r = chain[i]
    if rules.action(r, authorized) == "cache" and (r.sie > 0 or r.mode == "respect") then
      return true
    end
  end
  return false
end

-- WEBSOCKET_IDLE_MS is how long an upgraded connection (WebSocket) may be
-- idle by default: its read and send timeouts are its idle timeouts, and
-- the site's (for responses, 60 s by default) would close quiet ones. A
-- site's access control sets its own (WebSocketAccess.idle_timeout_seconds,
-- 60 s to 86400 s, edgeweir.access: site._ws_idle_ms); the edge's local hop
-- allows the longest (proxy_read_timeout 86400s).
_M.WEBSOCKET_IDLE_MS = 3600000

-- timeouts returns the connect, send and read timeouts in seconds of an
-- attempt: the site's connection settings, config rules' overrides (ov)
-- first; upgraded connections idle up to upgrade milliseconds (true:
-- WEBSOCKET_IDLE_MS) unless a rule sets the timeout.
function _M.timeouts(conn, ov, upgrade)
  local send, read = conn.send_timeout_ms, conn.read_timeout_ms
  if upgrade then
    local idle = type(upgrade) == "number" and upgrade or _M.WEBSOCKET_IDLE_MS
    send, read = idle, idle
  end
  return (ov.connect or conn.connect_timeout_ms) / 1000, (ov.send or send) / 1000, (ov.read or read) / 1000
end

-- defer_to_stale reports whether a response of the origin layer must be
-- dropped (the connection closed without a response) so that the edge
-- serves its expired copy under stale-if-error: a 5xx, also one this layer
-- produced itself (no usable origin, signing failures), while the edge
-- holds an EXPIRED copy that a cache rule of the request may serve stale.
-- cache_status is the edge's X-Edgeweir-Cache-Status.
function _M.defer_to_stale(status, cache_status, chain, authorized)
  return status >= 500 and cache_status == "EXPIRED" and stale_capable(chain, authorized)
end

-- decide returns what the origin layer adds to a response for the edge
-- cache: { accel_expires = seconds or nil, cache_control = string or nil,
-- stash = original Cache-Control ("-" when absent) or nil, set_cookie =
-- true when the deciding rule caches responses with Set-Cookie }.
-- cc and expires are the origin's Cache-Control and Expires values;
-- authorized tells whether the request carried Authorization.
function _M.decide(chain, status, size, cc, expires, authorized)
  local out = {}
  local rule = rules.decide(chain, status, size, authorized)
  if not rule or rules.action(rule, authorized) ~= "cache" then
    out.accel_expires = 0
    return out
  end
  local ttl
  if rule.mode == "override" then
    ttl = rule.ttl
  elseif cc == nil and expires == nil then
    ttl = (rule._has_status or rules.default_cacheable(status)) and rule.ttl or 0
  end
  out.accel_expires = ttl
  out.set_cookie = rule.set_cookie == true
  if (rule.swr > 0 or rule.sie > 0) and ttl ~= 0 then
    local directives
    if rule.mode == "override" then
      directives = strip_directives(cc, FRESHNESS)
      directives[#directives + 1] = "max-age=" .. ttl
    else
      directives = strip_directives(cc, STALE)
    end
    if rule.swr > 0 then
      directives[#directives + 1] = "stale-while-revalidate=" .. rule.swr
    end
    if rule.sie > 0 then
      directives[#directives + 1] = "stale-if-error=" .. rule.sie
    end
    out.stash = cc or "-"
    out.cache_control = concat(directives, ", ")
  end
  return out
end

-- page_code returns the X-Edgeweir-Error code when the response must be
-- replaced with an error page: nginx's own failure of the last attempt
-- (no response header), or an origin error the site intercepts.
function _M.page_code(site, status, upstream_header_time)
  if errorpages.generated(upstream_header_time) then
    -- nginx's own upstream failures; its other errors (an uncaught Lua
    -- error's 500) go to error_page and never reach the header filter.
    return (status == 502 or status == 503 or status == 504) and errorpages.origin_code(status) or nil
  end
  -- Intercepted: any 4xx or 5xx with a page of its status or class.
  if site._intercept and status >= 400 and status <= 599 and errorpages.page_for(site, status) then
    return "origin-error"
  end
  return nil
end

function _M.header_filter()
  local ctx = ngx.ctx
  local h = ngx.header
  -- Only this layer may set the stash header the edge restores and the
  -- carrier of cached Set-Cookie lines.
  h["X-Edgeweir-CC"] = nil
  h[setcookie.HEADER] = nil
  local site = ctx.site
  if not site then
    return
  end
  local status = ngx.status
  local chain = ctx.chain
  local var = ngx.var
  -- Stale first, before anything else, also for this layer's own failures
  -- (fail(): every origin dropped before an attempt, e.g. a name that no
  -- longer resolves): close without a response, so that the edge sees a
  -- transport error and serves its stale copy if stale-if-error allows it.
  if _M.defer_to_stale(status, var.http_x_edgeweir_cache_status, chain, ctx.authorized) then
    return ngx.exit(ngx.ERROR)
  end
  if ctx.edgeweir_failed then
    return -- fail() answered with its page or text already
  end
  if site._affinity_ttl then
    -- Only this layer announces affinity cookies.
    h[affinity.HEADER] = nil
  end
  -- Sites the edge compresses asked for identity: the cached object does
  -- not vary by Accept-Encoding.
  compress.origin_header_filter(site)
  local code = _M.page_code(site, status, var.upstream_header_time)
  if code then
    return errorpages.replace(status, code, site, true)
  end
  local a = ctx.affinity
  local tried = ctx.tried
  local chosen = a and tried and tried[#tried]
  if chosen then
    local now = ngx.time()
    if affinity.renew(a.pin, a.exp, chosen.origin.id, site._affinity_ttl, now) then
      h[affinity.HEADER] = affinity.sign(a.key, site.id, chosen.origin.id, now + site._affinity_ttl)
    end
  end
  if not chain then
    return -- the edge does not cache this request
  end
  local d = _M.decide(chain, status, response_size(h, status), flatten(h["Cache-Control"]), h["Expires"], ctx.authorized)
  if d.accel_expires ~= nil then
    h["X-Accel-Expires"] = d.accel_expires
  end
  if d.cache_control then
    h["X-Edgeweir-CC"] = d.stash
    h["Cache-Control"] = d.cache_control
  end
  -- The rule caches responses with Set-Cookie: the lines travel in the
  -- carrier, which the edge never sends on (proxy_hide_header) and turns
  -- back into Set-Cookie only for the response fetched for the request.
  if d.set_cookie and d.accel_expires ~= 0 then
    setcookie.carry(h)
  end
end

-- body_filter sends the error page header_filter prepared, and keeps at
-- most AUTH_BODY bytes of a forward authentication answer.
function _M.body_filter()
  local a = ngx.ctx.auth
  if a then
    local chunk = ngx.arg[1]
    if chunk and chunk ~= "" then
      local room = _M.AUTH_BODY - (a.seen or 0)
      a.seen = (a.seen or 0) + #chunk
      if room <= 0 then
        ngx.arg[1] = ""
      elseif #chunk > room then
        ngx.arg[1] = sub(chunk, 1, room)
      end
    end
    return
  end
  return errorpages.body_filter()
end

-- error_page answers nginx's own errors in this layer (content phase of
-- @edgeweir_error, or of /./edgeweir-error for requests without a URI
-- yet): uncaught Lua errors (500) and requests nginx refuses (400, 413,
-- 414, 494; the edge passes on only what it accepted, so these are rare).
-- nginx's 502 and 504 stay with header_filter(). Like there, a 5xx closes
-- the connection when the edge may serve its expired copy instead; the
-- redirect emptied ngx.ctx, so the site and the rules come from the edge
-- layer's request headers again.
function _M.error_page()
  local status = ngx.status
  local var = ngx.var
  local id = var.http_x_edgeweir_site
  local site = id and id ~= "" and store.site_current(id) or nil
  if _M.yields_to_stale(site, status, var.http_x_edgeweir_rules, var.http_x_edgeweir_cache_status,
      var.http_authorization ~= nil) then
    return ngx.exit(ngx.ERROR)
  end
  return errorpages.nginx_page(status, site, false, true)
end

-- yields_to_stale reports whether nginx's own error status of a request of
-- site (nil: none) yields to the edge's expired copy (defer_to_stale), the
-- rule chain rebuilt from rules_value, the edge layer's X-Edgeweir-Rules.
function _M.yields_to_stale(site, status, rules_value, cache_status, authorized)
  return site ~= nil and _M.defer_to_stale(status, cache_status, chain_from_header(site, rules_value), authorized)
end

-- classify returns the error code, its parameters and a text for a failed
-- attempt, or nil when the attempt counts as a success. status is the
-- attempt's $upstream_status, answered whether the origin sent a response
-- header, tls whether the TLS handshake (or certificate check) failed.
function _M.classify(status, answered, tls)
  if status ~= "502" and status ~= "503" and status ~= "504" then
    return nil
  end
  if answered then
    return "upstream_status", { status = status }, "HTTP " .. status
  end
  if status == "504" then
    return "timeout", nil, "timeout"
  end
  if tls then
    return "tls_failed", nil, "TLS handshake or certificate verification failed"
  end
  if status == "502" then
    return "connect_failed", nil, "connection failed"
  end
  return "", nil, "HTTP " .. status
end

local function split(v)
  local out = {}
  for item in gmatch(v or "", "[^,:%s]+") do
    out[#out + 1] = item
  end
  return out
end

function _M.log()
  local ctx = ngx.ctx
  local tried = ctx.tried
  if not tried or #tried == 0 then
    return
  end
  local site = ctx.site
  local var = ngx.var
  local statuses = split(var.upstream_status)
  local header_times = split(var.upstream_header_time)
  local now = ngx.now()
  for i = 1, #statuses do
    local c = tried[i]
    if not c then
      break
    end
    local o, st = c.origin, statuses[i]
    local answered = header_times[i] ~= nil and header_times[i] ~= "-"
    local tls = false
    if st == "502" and not answered and o.scheme == "https" then
      tls = upstreamerr.tls_failed(var.connection, upstreamerr.hostport(c.ip, o.port))
    end
    local code, params, text = _M.classify(st, answered, tls)
    if code then
      health.failure(site.id, o.id, text, site.health.max_fails, site.health.recovery_seconds, now, code, params)
      dns.invalidate(o.address)
    elseif st ~= "-" then
      health.success(site.id, o.id)
    end
  end
end

return _M
