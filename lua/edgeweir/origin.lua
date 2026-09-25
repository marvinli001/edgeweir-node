-- edgeweir.origin: origin layer (unix socket behind the edge cache).
--
-- access(): picks an origin for the site named by X-Edgeweir-Site and sets
-- the proxy_pass target, Host header and TLS SNI.
-- header_filter(): turns the rule TTL into X-Accel-Expires so the edge
-- layer's proxy_cache honours hot-updated TTLs without an nginx reload.
-- nginx never forwards X-Accel-* headers to clients.
local store = require("edgeweir.store")

local _M = {}

-- Status codes that a rule TTL may make cacheable. Error responses are
-- never cached by rule TTL (only if the origin explicitly asks for it).
local CACHEABLE = { [200] = true, [203] = true, [206] = true, [300] = true, [301] = true, [308] = true }

local function fail(status, code)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(code, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- pick selects an origin: weighted random over primaries, backups only
-- when there is no primary.
-- TODO(phase1): passive health checks, round_robin and consistent_hash
-- (these policies currently fall back to weighted random).
function _M.pick(site)
  local list, total = site._primaries, site._pw
  if not list or #list == 0 then
    list, total = site._backups, site._bw
  end
  local n = list and #list or 0
  if n == 0 then
    return nil
  end
  if n == 1 then
    return list[1]
  end
  local r = math.random() * total
  for i = 1, n do
    r = r - list[i].weight
    if r < 0 then
      return list[i]
    end
  end
  return list[n]
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
  local o = _M.pick(site)
  if not o then
    return fail(ngx.HTTP_BAD_GATEWAY, "no-origin")
  end

  var.edgeweir_upstream = o.url
  local host = o.host_header
  if not host or host == "" then
    host = var.http_host or ""
  end
  var.edgeweir_upstream_host = host
  var.edgeweir_upstream_sni = o.sni_name

  local ctx = ngx.ctx
  ctx.ew_ttl = tonumber(var.http_x_edgeweir_ttl) or 0
  ctx.ew_mode = var.http_x_edgeweir_cache_mode
end

-- accel_expires returns the X-Accel-Expires value for a response, or nil.
function _M.accel_expires(ttl, mode, status, cache_control, expires)
  if not ttl or ttl <= 0 or not CACHEABLE[status] then
    return nil
  end
  if mode == "override" then
    return ttl
  end
  if mode == "respect" and cache_control == nil and expires == nil then
    return ttl
  end
  return nil
end

function _M.header_filter()
  local ctx = ngx.ctx
  local h = ngx.header
  local v = _M.accel_expires(ctx.ew_ttl, ctx.ew_mode, ngx.status, h["Cache-Control"], h["Expires"])
  if v then
    h["X-Accel-Expires"] = v
  end
end

return _M
