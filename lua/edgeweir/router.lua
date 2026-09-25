-- edgeweir.router: edge layer (public listeners), access phase.
--
-- Resolves the site by Host, answers 404 for unknown hosts, evaluates the
-- cache rules and prepares the variables used by proxy_cache in nginx.conf.
-- The TTL and origin cache-control mode travel to the origin layer in
-- internal X-Edgeweir-* request headers set by proxy_set_header.
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")

local _M = {}

local sub = string.sub

local function unknown_host()
  ngx.status = ngx.HTTP_NOT_FOUND
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = "unknown-host"
  ngx.print("unknown host\n")
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

function _M.access()
  strip_internal_headers()

  local var = ngx.var
  local host = var.host
  local site = store.lookup_host(host)
  if not site then
    return unknown_host()
  end

  var.edgeweir_site = site.id
  var.edgeweir_cache_zone = site.cache_zone

  local method = ngx.req.get_method()
  if method == "GET" or method == "HEAD" then
    local rule = rules.match(site, var.uri)
    if rule and rule.action == "cache" and (rule.ttl > 0 or rule.mode == "respect") then
      var.edgeweir_cache_bypass = "0"
      var.edgeweir_no_cache = "0"
      var.edgeweir_ttl = tostring(rule.ttl)
      var.edgeweir_cache_mode = rule.mode
    end
  end

  -- Bumping cache_generation invalidates every object of the site at once.
  var.edgeweir_cache_key = site.id .. ":" .. site.cache_generation .. ":"
    .. var.scheme .. "://" .. host .. var.request_uri
end

return _M
