-- edgeweir.origin: origin layer (unix sockets behind the edge cache).
--
-- access():        orders the site's origins (edgeweir.lb), resolves their
--                  names (edgeweir.dns), signs S3 requests (edgeweir.sigv4)
--                  and sets the variables used by proxy_pass.
-- balance():       balancer_by_lua: one call per attempt; sets the peer,
--                  retries, timeouts and the keep-alive pool, and rebuilds
--                  the request when a retry goes to an origin with another
--                  Host or S3 signature.
-- header_filter(): decides caching for the edge layer: X-Accel-Expires from
--                  the matching cache rule, stale-while-revalidate and
--                  stale-if-error as Cache-Control extensions (the original
--                  header travels in X-Edgeweir-CC and the edge restores it),
--                  and hands origin failures back as transport errors when
--                  the edge holds an expired copy it may serve instead.
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

local _M = {}

local concat = table.concat
local find, gmatch, gsub, sub = string.find, string.gmatch, string.gsub, string.sub
local tonumber = tonumber

local function fail(status, code)
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
  ctx.upgrade = var.http_upgrade ~= nil and var.http_upgrade ~= ""

  local now = ngx.now()
  local method = ngx.req.get_method()
  local allowed = store.config().allowed
  local cands, scheme, s3_refused = {}, nil, false
  for _, o in ipairs(lb.order(site, var.request_uri, now)) do
    local usable = true
    if o.forbidden then
      -- Refused by the agent already (special-purpose IP literal).
      usable = false
      health.failure(site.id, o.id, "address " .. o.address .. " is a special-purpose address outside the origin allow list",
        site.health.max_fails, site.health.recovery_seconds, now)
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
      local ip, err = dns.resolve(o.address, allowed)
      if ip then
        scheme = scheme or o.scheme
        cands[#cands + 1] = { origin = o, ip = ip }
      else
        health.failure(site.id, o.id, err, site.health.max_fails, site.health.recovery_seconds, now)
      end
    end
  end
  if #cands == 0 then
    if s3_refused then
      ngx.header["Allow"] = "GET, HEAD"
      return fail(ngx.HTTP_NOT_ALLOWED, "method-not-allowed")
    end
    return fail(ngx.HTTP_BAD_GATEWAY, "no-origin")
  end
  ctx.cands = cands
  ctx.tried = {}
  local ok, err = apply(cands[1])
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: cannot sign origin request: ", err)
    return fail(ngx.HTTP_BAD_GATEWAY, "origin-signing")
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

local function stale_capable(chain)
  if not chain then
    return false
  end
  for i = 1, #chain do
    local r = chain[i]
    if r.action == "cache" and (r.sie > 0 or r.mode == "respect") then
      return true
    end
  end
  return false
end

-- decide returns what the origin layer adds to a response for the edge
-- cache: { accel_expires = seconds or nil, cache_control = string or nil,
-- stash = original Cache-Control ("-" when absent) or nil }.
-- cc and expires are the origin's Cache-Control and Expires values.
function _M.decide(chain, status, size, cc, expires)
  local out = {}
  local rule = rules.decide(chain, status, size)
  if not rule or rule.action ~= "cache" then
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

function _M.header_filter()
  local ctx = ngx.ctx
  local h = ngx.header
  -- Only this layer may set the stash header the edge restores.
  h["X-Edgeweir-CC"] = nil
  local site = ctx.site
  if not site then
    return
  end
  local status = ngx.status
  local chain = ctx.chain
  if status >= 500 and ngx.var.http_x_edgeweir_cache_status == "EXPIRED" and stale_capable(chain) then
    -- Close without a response: the edge sees a transport error and serves
    -- its stale copy if stale-if-error allows it.
    return ngx.exit(ngx.ERROR)
  end
  if not chain then
    return -- the edge does not cache this request
  end
  local d = _M.decide(chain, status, response_size(h, status), flatten(h["Cache-Control"]), h["Expires"])
  if d.accel_expires ~= nil then
    h["X-Accel-Expires"] = d.accel_expires
  end
  if d.cache_control then
    h["X-Edgeweir-CC"] = d.stash
    h["Cache-Control"] = d.cache_control
  end
end

local FAILURE = {
  ["502"] = "connection failed or HTTP 502",
  ["503"] = "HTTP 503",
  ["504"] = "timeout or HTTP 504",
}

function _M.log()
  local ctx = ngx.ctx
  local tried = ctx.tried
  if not tried or #tried == 0 then
    return
  end
  local site = ctx.site
  local statuses = ngx.var.upstream_status or ""
  local i, now = 0, ngx.now()
  for st in gmatch(statuses, "[^,:%s]+") do
    i = i + 1
    local c = tried[i]
    if not c then
      break
    end
    local o = c.origin
    local reason = FAILURE[st]
    if reason then
      health.failure(site.id, o.id, reason, site.health.max_fails, site.health.recovery_seconds, now)
      dns.invalidate(o.address)
    elseif st ~= "-" then
      health.success(site.id, o.id)
    end
  end
end

return _M
