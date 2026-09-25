-- edgeweir.control: JSON control API for the agent.
--
-- Served only on a unix socket (see nginx.conf); never exposed over TCP.
--
--   GET  /v1/health           liveness
--   GET  /v1/status           {version, revision, content_hash, site_count, purge, conf_id, ...}
--   PUT  /v1/sites            replace the whole site table atomically
--   POST /v1/stats/drain      return and delete completed per-minute counters
--   PUT  /v1/purge            replace the purge marker set {id, markers}
--   POST /v1/purge            merge purge markers {id, markers}
--   GET  /v1/origins/health   origins with recorded failures
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local stats = require("edgeweir.stats")
local purge = require("edgeweir.purge")
local health = require("edgeweir.health")

local _M = {}

if cjson.encode_number_precision then
  pcall(cjson.encode_number_precision, 16)
end

local function reply(status, body)
  ngx.status = status
  ngx.header["Content-Type"] = "application/json"
  ngx.header["Cache-Control"] = "no-store"
  ngx.print(cjson.encode(body))
  return ngx.exit(ngx.HTTP_OK)
end

local function read_body()
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if data then
    return data
  end
  local path = ngx.req.get_body_file()
  if not path then
    return nil, "empty body"
  end
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  data = f:read("*a")
  f:close()
  return data
end

function _M.handle()
  local method = ngx.req.get_method()
  local uri = ngx.var.uri

  if uri == "/v1/health" then
    return reply(200, { status = "ok" })
  end

  if uri == "/v1/status" then
    if method ~= "GET" then
      return reply(405, { error = "method not allowed" })
    end
    local st = store.status()
    st.purge = purge.status()
    st.nginx_version = ngx.config.nginx_version
    st.ngx_lua_version = ngx.config.ngx_lua_version
    st.worker_pid = ngx.worker.pid()
    st.conf_id = require("edgeweir.init").conf_id
    return reply(200, st)
  end

  if uri == "/v1/sites" then
    if method ~= "PUT" then
      return reply(405, { error = "method not allowed" })
    end
    local body, err = read_body()
    if not body then
      return reply(400, { error = "read body: " .. tostring(err) })
    end
    local doc, derr = cjson.decode(body)
    if type(doc) ~= "table" then
      return reply(400, { error = "invalid JSON: " .. tostring(derr) })
    end
    local res, perr, code = store.replace(doc)
    if not res then
      ngx.log(ngx.ERR, "edgeweir: site table update rejected: ", perr)
      return reply(code or 500, { error = perr })
    end
    ngx.log(ngx.NOTICE, "edgeweir: site table version ", res.version, " installed: revision ",
      res.revision, ", ", res.site_count, " sites")
    return reply(200, res)
  end

  if uri == "/v1/stats/drain" then
    if method ~= "POST" then
      return reply(405, { error = "method not allowed" })
    end
    return reply(200, { stats = stats.drain() })
  end

  if uri == "/v1/purge" then
    if method == "GET" then
      return reply(200, purge.status())
    end
    if method ~= "PUT" and method ~= "POST" then
      return reply(405, { error = "method not allowed" })
    end
    local body, err = read_body()
    if not body then
      return reply(400, { error = "read body: " .. tostring(err) })
    end
    local doc, derr = cjson.decode(body)
    if type(doc) ~= "table" then
      return reply(400, { error = "invalid JSON: " .. tostring(derr) })
    end
    local res, perr, code
    if method == "PUT" then
      res, perr, code = purge.replace(doc)
    else
      res, perr, code = purge.add(doc)
    end
    if not res then
      ngx.log(ngx.ERR, "edgeweir: purge markers rejected: ", perr)
      return reply(code or 500, { error = perr })
    end
    ngx.log(ngx.NOTICE, "edgeweir: purge markers ", method == "PUT" and "replaced" or "added",
      ": ", res.entries, " entries")
    return reply(200, res)
  end

  if uri == "/v1/origins/health" then
    if method ~= "GET" then
      return reply(405, { error = "method not allowed" })
    end
    local list = health.report()
    if cjson.array_mt then
      setmetatable(list, cjson.array_mt)
    end
    return reply(200, { origins = list })
  end

  return reply(404, { error = "not found" })
end

return _M
