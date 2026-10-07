-- edgeweir.purgemethod: the PURGE method (Site.purge, feature
-- site-content-v1).
--
-- A PURGE request for a site with the method on is answered at the edge:
-- at most RATE requests per second per site and client address on this
-- node (429 purge-rate-limited), then the request's URL and X-Purge-Key go
-- to the agent over its unix socket (agent_socket). The agent checks the
-- key, allows a site RATE accepted requests per second (so clients without
-- the key cannot use up the site's budget, only their own) and
-- asks the console to purge the URL on every node of the cluster; the
-- answer is 202 {"task_id": ...}, or 403 (purge-key-invalid,
-- purge-disabled), 400 (purge-url-invalid), 429 (purge-rate-limited, with
-- Retry-After) or 503 (purge-unavailable). Answers are JSON and never
-- cached. The key never enters the data plane's shared memory.
local cjson = require("cjson.safe")

local _M = { socket = "" }

-- RATE is how many PURGE requests per second a site takes from one client
-- address on this node (the agent applies the same number to the site's
-- accepted requests).
_M.RATE = 20
-- TIMEOUT bounds the agent's answer (it waits for the console).
_M.TIMEOUT = 35000

local function answer(status, body, code, retry_after)
  ngx.status = status
  local h = ngx.header
  h["Content-Type"] = "application/json"
  h["Cache-Control"] = "no-store"
  if code then
    h["X-Edgeweir-Error"] = code
  end
  if retry_after then
    h["Retry-After"] = tostring(retry_after)
  end
  ngx.print(cjson.encode(body), "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- limited reports whether the site took RATE PURGE requests from addr this
-- second.
function _M.limited(site_id, addr, now)
  local dict = ngx.shared.edgeweir_meta
  local key = "purge:" .. site_id .. ":" .. tostring(addr) .. ":" .. tostring(now)
  local n = dict:incr(key, 1, 0, 2)
  return n == nil or n > _M.RATE
end

-- ask sends the request to the agent and returns its status and decoded
-- answer, or nil.
function _M.ask(site_id, url, key)
  if _M.socket == "" then
    return nil
  end
  local body = cjson.encode({ site_id = site_id, url = url, key = key or "" })
  local sock = ngx.socket.tcp()
  sock:settimeout(_M.TIMEOUT)
  local ok = sock:connect("unix:" .. _M.socket)
  if not ok then
    sock:close()
    return nil
  end
  ok = sock:send("POST /v1/purge HTTP/1.0\r\nHost: agent\r\nContent-Type: application/json\r\nContent-Length: "
    .. #body .. "\r\nConnection: close\r\n\r\n" .. body)
  if not ok then
    sock:close()
    return nil
  end
  local status_line = sock:receive("*l")
  local status = status_line and tonumber(status_line:match("^HTTP/1%.[01] (%d%d%d)"))
  if not status then
    sock:close()
    return nil
  end
  for _ = 1, 32 do
    local line = sock:receive("*l")
    if not line then
      sock:close()
      return nil
    end
    if line == "" then
      break
    end
  end
  local data = sock:receive("*a")
  sock:close()
  local decoded = data and cjson.decode(data)
  return status, type(decoded) == "table" and decoded or {}
end

-- handle answers a PURGE request of site.
function _M.handle(site)
  local var = ngx.var
  if _M.limited(site.id, var.remote_addr, ngx.time()) then
    return answer(429, { error = "purge_rate_limited" }, "purge-rate-limited", 1)
  end
  local url = var.scheme .. "://" .. var.host .. var.request_uri
  if #url > 2048 then
    return answer(400, { error = "purge_url_invalid" }, "purge-url-invalid")
  end
  local status, reply = _M.ask(site.id, url, var.http_x_purge_key)
  if not status then
    ngx.log(ngx.ERR, "edgeweir: PURGE: the agent did not answer site=", site.id)
    return answer(503, { error = "purge_unavailable" }, "purge-unavailable")
  end
  if status == 202 and type(reply.task_id) == "string" then
    return answer(202, { task_id = reply.task_id })
  end
  local code = type(reply.error) == "string" and reply.error or "purge-unavailable"
  if status ~= 400 and status ~= 403 and status ~= 429 then
    status, code = 503, "purge-unavailable"
  end
  return answer(status, { error = (code:gsub("-", "_")) }, code, status == 429 and (tonumber(reply.retry_after) or 60) or nil)
end

return _M
