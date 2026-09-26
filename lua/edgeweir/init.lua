-- edgeweir.init: nginx init hooks.
--
-- init() runs in the master at configuration load (also during `nginx -t`,
-- so Lua syntax errors fail the configuration test instead of the reload).
-- init_worker() runs once per worker process.
local _M = {}

-- init(opts): opts.resolvers are the nameservers of nginx's `resolver`
-- directive, opts.ipv6 whether AAAA records are used.
_M.conf_id = ""

function _M.init(opts)
  opts = opts or {}
  -- Id of the nginx.conf being loaded (reported by GET /v1/status; the
  -- agent checks it after a reload).
  _M.conf_id = type(opts.conf_id) == "string" and opts.conf_id or ""
  -- Load every module eagerly: workers inherit them after fork.
  require("edgeweir.geoip").socket = opts.geoip_socket or ""
  require("edgeweir.ipaddr")
  require("edgeweir.store")
  require("edgeweir.rules")
  require("edgeweir.cachekey")
  require("edgeweir.purge")
  require("edgeweir.health")
  require("edgeweir.lb")
  require("edgeweir.sigv4")
  require("edgeweir.dns").configure(opts.resolvers, opts.ipv6)
  require("edgeweir.upstreamerr")
  -- Capture only errors (lua_capture_error_log): enough to tell TLS
  -- failures of origin attempts apart (edgeweir.upstreamerr).
  local ok, errlog = pcall(require, "ngx.errlog")
  if ok then
    pcall(errlog.set_filter_level, ngx.ERR)
  end
  require("edgeweir.router")
  require("edgeweir.origin")
  require("edgeweir.stats")
  require("edgeweir.control")
end

function _M.init_worker()
  -- Weighted origin selection uses math.random: seed per worker so that
  -- workers do not all pick the same sequence.
  math.randomseed(ngx.now() * 1000 + ngx.worker.pid())
end

return _M
