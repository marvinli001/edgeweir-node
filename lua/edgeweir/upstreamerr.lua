-- edgeweir.upstreamerr: tells TLS failures of origin attempts apart.
--
-- An attempt that fails before the origin sends a response header is a 502
-- in $upstream_status whether the TCP connection or the TLS handshake
-- (including certificate verification) failed; nginx's variables look the
-- same for both. nginx does log the phase ("while SSL handshaking to
-- upstream"), so the origin layer captures error log lines
-- (lua_capture_error_log, error level only, per worker) and matches them
-- to its attempts by the downstream connection number and the upstream
-- address. Anything unmatched counts as a connection failure.
local ok_errlog, errlog = pcall(require, "ngx.errlog")

local _M = {}

local find, match = string.find, string.match

local MAX = 1000
local seen, count = {}, 0

-- parse returns the downstream connection number, the upstream
-- "host:port" and the phase ("tls" or "connect") of an nginx error log line
-- about a failed upstream attempt, or nil.
function _M.parse(msg)
  if type(msg) ~= "string" then
    return nil
  end
  local conn = match(msg, " %*(%d+) ")
  local hostport = match(msg, 'upstream: "%a+://([^/"]+)')
  if not conn or not hostport then
    return nil
  end
  if find(msg, "while SSL handshaking to upstream", 1, true) then
    return conn, hostport, "tls"
  end
  if find(msg, "while connecting to upstream", 1, true) then
    return conn, hostport, "connect"
  end
  return nil
end

-- record remembers the phase of a parsed failure (bounded).
function _M.record(conn, hostport, phase)
  if count >= MAX then
    seen, count = {}, 0
  end
  local k = conn .. "|" .. hostport
  if not seen[k] then
    count = count + 1
  end
  seen[k] = phase
end

local function drain()
  if not ok_errlog then
    return
  end
  local ok, logs = pcall(errlog.get_logs, 200)
  if not ok or type(logs) ~= "table" then
    return
  end
  for i = 1, #logs, 3 do
    local conn, hostport, phase = _M.parse(logs[i + 2])
    if conn then
      _M.record(conn, hostport, phase)
    end
  end
end

-- hostport formats an address the way nginx logs it.
function _M.hostport(ip, port)
  if find(ip, ":", 1, true) then
    return "[" .. ip .. "]:" .. port
  end
  return ip .. ":" .. port
end

-- tls_failed reports (and forgets) whether the attempt of downstream
-- connection conn to hostport failed in the TLS handshake.
function _M.tls_failed(conn, hostport)
  drain()
  local k = tostring(conn) .. "|" .. hostport
  local phase = seen[k]
  if phase then
    seen[k] = nil
    count = count - 1
  end
  return phase == "tls"
end

return _M
