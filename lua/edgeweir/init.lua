-- edgeweir.init: nginx init hooks.
--
-- init() runs in the master at configuration load (also during `nginx -t`,
-- so Lua syntax errors fail the configuration test instead of the reload).
-- init_worker() runs once per worker process.
local _M = {}

function _M.init()
  -- Load every module eagerly: workers inherit them after fork.
  require("edgeweir.store")
  require("edgeweir.rules")
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
