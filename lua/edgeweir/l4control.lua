-- edgeweir.l4control: the stream subsystem's end of the control API.
--
-- The stream subsystem has its own shared dicts, which the http control
-- API (edgeweir.control) cannot reach. It forwards /v1/l4 requests over
-- the unix socket of this server (nginx.conf: listen unix:.../l4.sock,
-- reachable only locally like control.sock) in a minimal framing:
--
--   request   "<METHOD> <path> <body length>\n" and the body
--   response  "<status> <body length>\n" and a JSON body
--
--   GET  /v1/l4              table status {version, revision, content_hash,
--                            apps, pushed_at, down: [{app_id, origin_id,
--                            down_until}]}
--   PUT  /v1/l4              replace the layer-4 table (400 invalid, 409
--                            another update in progress, 507 no memory)
--   POST /v1/l4/stats/drain  return and delete the completed minutes
--                            {stats: [{minute, app_id, connections,
--                            refused, peak_concurrent, bytes_received,
--                            bytes_sent}]}
local cjson = require("cjson.safe")
local l4 = require("edgeweir.l4")

local _M = {}

_M.MAX_BODY = 256 * 1024 * 1024

if cjson.encode_number_precision then
  pcall(cjson.encode_number_precision, 16)
end

-- dispatch answers one request (pure apart from the dicts): status, body.
function _M.dispatch(method, path, body)
  if path == "/v1/l4" then
    if method == "GET" then
      return 200, l4.status()
    end
    if method ~= "PUT" then
      return 405, { error = "method not allowed" }
    end
    local res, err, code = l4.replace(body)
    if not res then
      ngx.log(ngx.ERR, "edgeweir: layer-4 table update rejected: ", err)
      return code or 500, { error = err }
    end
    ngx.log(ngx.NOTICE, "edgeweir: layer-4 table version ", res.version, " installed: revision ",
      res.revision, ", ", res.apps, " applications")
    return 200, res
  end
  if path == "/v1/l4/stats/drain" then
    if method ~= "POST" then
      return 405, { error = "method not allowed" }
    end
    return 200, { stats = l4.drain() }
  end
  return 404, { error = "not found" }
end

function _M.handle()
  local sock, err = ngx.req.socket(true)
  if not sock then
    ngx.log(ngx.ERR, "edgeweir: layer-4 control: ", err)
    return
  end
  sock:settimeouts(5000, 30000, 30000)
  local line = sock:receive("*l")
  local method, path, len = (line or ""):match("^(%u+) (/%S*) (%d+)$")
  len = tonumber(len)
  local status, res, body
  if not method or len > _M.MAX_BODY then
    status, res = 400, { error = "bad request" }
  else
    body = ""
    if len > 0 then
      body, err = sock:receive(len)
    end
    if not body then
      status, res = 400, { error = "read body: " .. tostring(err) }
    else
      status, res = _M.dispatch(method, path, body)
    end
  end
  local out = cjson.encode(res) or "{}"
  sock:send(status .. " " .. #out .. "\n" .. out)
end

return _M
