-- edgeweir.control: JSON control API for the agent.
--
-- Served only on a unix socket (see nginx.conf); never exposed over TCP.
--
--   GET  /v1/health           liveness
--   GET  /v1/status           {version, revision, content_hash, site_count, purge, conf_id,
--                             connections_active, ...}
--   PUT  /v1/sites            replace the whole site table atomically
--   POST /v1/stats/drain      return and delete completed per-minute counters
--                             ({"all": true}: the current minute too)
--   PUT  /v1/purge            replace the purge marker set {id, markers}
--   POST /v1/purge            merge purge markers {id, markers}
--   GET  /v1/origins/health   origins with recorded failures (passive check)
--   PUT  /v1/origins/active   replace the origins the agent's active check
--                             marks down {ttl, down: [{site_id, origin_id}]}
--   GET  /v1/bans             ban status (?list=1 adds up to 1000 bans)
--   PUT  /v1/bans             replace the console bans {sequence, bans}
--   POST /v1/bans             apply a delta {base, sequence, upsert, remove}
--   POST /v1/bans/auto/drain  return and delete up to 1000 queued own bans
--   POST /v1/bans/release     delete own bans the console lifted {bans}
--   GET  /v1/challenge        challenge keys and captcha pool status
--   PUT  /v1/challenge/keys   replace the challenge keys {id, current, keys}
--   PUT  /v1/challenge/captchas  replace the captcha pool {id, images}
--   GET  /v1/security         CC levels of the sites with CC
--   POST /v1/security/drain   return and delete up to 1000 CC events
--   GET  /v1/l4, PUT /v1/l4, POST /v1/l4/stats/drain
--                             layer-4 applications: forwarded to the
--                             stream subsystem (edgeweir.l4control), whose
--                             shared dicts this one cannot reach; 404 when
--                             nginx.conf has no layer-4 applications, 503
--                             when the stream side does not answer
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local stats = require("edgeweir.stats")
local purge = require("edgeweir.purge")
local health = require("edgeweir.health")
local bans = require("edgeweir.bans")
local challenge = require("edgeweir.challenge")
local cc = require("edgeweir.cc")

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

-- l4 forwards a /v1/l4 request to the stream subsystem's control relay
-- (framing in edgeweir.l4control) and answers with its response.
local function l4(method, uri)
  local socket = require("edgeweir.init").l4_socket
  if socket == "" then
    return reply(404, { error = "no layer-4 applications in this configuration" })
  end
  local body = ""
  if method == "PUT" or method == "POST" then
    local err
    body, err = read_body()
    if not body then
      if method == "PUT" then
        return reply(400, { error = "read body: " .. tostring(err) })
      end
      body = ""
    end
  end
  local sock = ngx.socket.tcp()
  sock:settimeouts(2000, 30000, 30000)
  local ok, err = sock:connect(socket)
  if not ok then
    return reply(503, { error = "layer-4 control relay " .. socket .. ": " .. tostring(err) })
  end
  ok, err = sock:send(method .. " " .. uri .. " " .. #body .. "\n" .. body)
  local line = ok and sock:receive("*l")
  local status, len = (line or ""):match("^(%d+) (%d+)$")
  local resp = status and sock:receive(tonumber(len))
  sock:close()
  if not resp then
    return reply(503, { error = "layer-4 control relay " .. socket .. ": no answer (" .. tostring(err) .. ")" })
  end
  ngx.status = tonumber(status)
  ngx.header["Content-Type"] = "application/json"
  ngx.header["Cache-Control"] = "no-store"
  ngx.print(resp)
  return ngx.exit(ngx.HTTP_OK)
end

function _M.handle()
  local method = ngx.req.get_method()
  local uri = ngx.var.uri

  if uri == "/v1/l4" or uri:sub(1, 7) == "/v1/l4/" then
    return l4(method, uri)
  end

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
    -- Connections nginx holds ($connections_active of the stub_status
    -- module) without this request; nil when the module is missing.
    local active = tonumber(ngx.var.connections_active)
    st.connections_active = active and math.max(active - 1, 0) or nil
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

  if uri == "/v1/logs/drain" then
    if method ~= "POST" then return reply(405, { error = "method not allowed" }) end
    return reply(200, { logs = require("edgeweir.accesslogs").drain() })
  end

  if uri == "/v1/stats/drain" then
    if method ~= "POST" then
      return reply(405, { error = "method not allowed" })
    end
    -- {"all": true} takes the current minute too (before nginx stops).
    local doc = cjson.decode(read_body() or "")
    local all = type(doc) == "table" and doc.all == true
    return reply(200, { stats = stats.drain(all and ngx.time() + 60 or nil) })
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

  if uri == "/v1/bans" then
    if method == "GET" then
      local args = ngx.req.get_uri_args(1)
      return reply(200, bans.status(args.list == "1"))
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
      res, perr, code = bans.replace(doc)
    else
      res, perr, code = bans.add(doc)
    end
    if not res then
      if code ~= 409 then
        ngx.log(ngx.ERR, "edgeweir: ban update rejected: ", perr)
      end
      return reply(code or 500, { error = perr })
    end
    ngx.log(ngx.NOTICE, "edgeweir: bans ", method == "PUT" and "replaced" or "updated", ": sequence ",
      res.sequence, ", ", res.entries, " held, ", res.unapplied, " unapplied")
    return reply(200, res)
  end

  if uri == "/v1/bans/release" then
    if method ~= "POST" then
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
    local n, rerr, code = bans.release(doc.bans)
    if not n then
      return reply(code or 500, { error = rerr })
    end
    if n > 0 then
      ngx.log(ngx.NOTICE, "edgeweir: own bans lifted by the console: ", n)
    end
    return reply(200, { released = n })
  end

  if uri == "/v1/bans/auto/drain" then
    if method ~= "POST" then
      return reply(405, { error = "method not allowed" })
    end
    return reply(200, { bans = bans.drain(1000) })
  end

  if uri == "/v1/challenge" then
    if method ~= "GET" then return reply(405, { error = "method not allowed" }) end
    return reply(200, challenge.status())
  end

  if uri == "/v1/challenge/keys" or uri == "/v1/challenge/captchas" then
    if method ~= "PUT" then return reply(405, { error = "method not allowed" }) end
    local body, err = read_body()
    if not body then
      return reply(400, { error = "read body: " .. tostring(err) })
    end
    local doc, derr = cjson.decode(body)
    if type(doc) ~= "table" then
      return reply(400, { error = "invalid JSON: " .. tostring(derr) })
    end
    local res, perr, code
    if uri == "/v1/challenge/keys" then
      res, perr, code = challenge.replace_keys(doc)
    else
      res, perr, code = challenge.replace_captchas(doc)
    end
    if not res then
      ngx.log(ngx.ERR, "edgeweir: challenge update rejected: ", perr)
      return reply(code or 500, { error = perr })
    end
    if uri == "/v1/challenge/keys" then
      ngx.log(ngx.NOTICE, "edgeweir: challenge keys installed: ", #res.keys, " keys, current ", res.current)
    end
    return reply(200, res)
  end

  if uri == "/v1/security" then
    if method ~= "GET" then return reply(405, { error = "method not allowed" }) end
    return reply(200, cc.status())
  end

  if uri == "/v1/security/drain" then
    if method ~= "POST" then return reply(405, { error = "method not allowed" }) end
    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print('{"events":', cc.drain(1000), "}")
    return ngx.exit(ngx.HTTP_OK)
  end

  if uri == "/v1/origins/active" then
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
    local res, perr, code = health.replace_active(doc)
    if not res then
      if code ~= 409 then
        ngx.log(ngx.ERR, "edgeweir: active health marks rejected: ", perr)
      end
      return reply(code or 500, { error = perr })
    end
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
