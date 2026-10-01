-- edgeweir.origin: origin layer (unix sockets behind the edge cache).
--
-- access():        orders the site's origins (edgeweir.lb), resolves their
--                  names (edgeweir.dns), signs S3 requests (edgeweir.sigv4)
--                  and sets the variables used by proxy_pass.
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
-- log():           passive health accounting from $upstream_status.
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

local _M = {}

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
  local ctx = ngx.ctx
  ctx.site = site
  ctx.chain = chain_from_header(site, var.http_x_edgeweir_rules)
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
  for _, o in ipairs(lb.order(site, var.request_uri, now, pin)) do
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
  ngx_balancer.set_timeouts(conn.connect_timeout_ms / 1000, conn.send_timeout_ms / 1000,
    conn.read_timeout_ms / 1000)
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

-- decide returns what the origin layer adds to a response for the edge
-- cache: { accel_expires = seconds or nil, cache_control = string or nil,
-- stash = original Cache-Control ("-" when absent) or nil }.
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
  if not errorpages.STATUSES[status] then
    return nil
  end
  if errorpages.generated(upstream_header_time) then
    return errorpages.origin_code(status)
  end
  if site._intercept and site._error_pages[status] then
    return "origin-error"
  end
  return nil
end

function _M.header_filter()
  local ctx = ngx.ctx
  local h = ngx.header
  -- Only this layer may set the stash header the edge restores.
  h["X-Edgeweir-CC"] = nil
  local site = ctx.site
  if not site or ctx.edgeweir_failed then
    return
  end
  if site._affinity_ttl then
    -- Only this layer announces affinity cookies.
    h[affinity.HEADER] = nil
  end
  -- Sites the edge compresses asked for identity: the cached object does
  -- not vary by Accept-Encoding.
  compress.origin_header_filter(site)
  local status = ngx.status
  local chain = ctx.chain
  local var = ngx.var
  if status >= 500 and var.http_x_edgeweir_cache_status == "EXPIRED" and stale_capable(chain, ctx.authorized) then
    -- Close without a response: the edge sees a transport error and serves
    -- its stale copy if stale-if-error allows it.
    return ngx.exit(ngx.ERROR)
  end
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
end

-- body_filter sends the error page header_filter prepared.
function _M.body_filter()
  return errorpages.body_filter()
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
