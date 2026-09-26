local cjson = require("cjson.safe")
local cache = assert(require("resty.lrucache").new(10000))
local _M = { socket = "" }
function _M.lookup(ip)
  local hit = cache:get(ip)
  if hit then return hit end
  if _M.socket == "" then return nil end
  local sock = ngx.socket.tcp()
  sock:settimeout(200)
  local ok = sock:connect("unix:" .. _M.socket)
  if not ok then sock:close(); return nil end
  ok = sock:send("GET /lookup?ip=" .. ngx.escape_uri(ip) .. " HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  if not ok then sock:close(); return nil end
  local status = sock:receive("*l")
  if not status or not status:match("^HTTP/1%.[01] 200 ") then sock:close(); return nil end
  for _ = 1, 32 do
    local line = sock:receive("*l")
    if not line then sock:close(); return nil end
    if line == "" then break end
  end
  local line = sock:receive("*l"); sock:close()
  if not line or #line > 2048 then return nil end
  local record = cjson.decode(line)
  if type(record) ~= "table" then return nil end
  cache:set(ip, record, 300)
  return record
end
return _M
