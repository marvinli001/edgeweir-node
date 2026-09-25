-- edgeweir.init: nginx init hooks.
--
-- init() runs in the master at configuration load (also during `nginx -t`,
-- so Lua syntax errors fail the configuration test instead of the reload).
-- init_worker() runs once per worker process.
local _M = {}

-- init(opts): opts.resolvers are the nameservers of nginx's `resolver`
-- directive, opts.ipv6 whether AAAA records are used.
function _M.init(opts)
  opts = opts or {}
  -- Load every module eagerly: workers inherit them after fork.
  require("edgeweir.store")
  require("edgeweir.rules")
  require("edgeweir.cachekey")
  require("edgeweir.purge")
  require("edgeweir.health")
  require("edgeweir.lb")
  require("edgeweir.sigv4")
  require("edgeweir.dns").configure(opts.resolvers, opts.ipv6)
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
