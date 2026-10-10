-- edgeweir.geoip: the agent's GeoIP lookups over its unix socket
-- (GET /lookup?ip=), cached per worker (10000 records, 300 s).
--
-- Hard lookups (rules and access control that read GeoIP) wait up to 200
-- ms and are tried every time. Soft lookups (ADR-0041: one per request of
-- a site, for its access log and statistics, once the bans, the client
-- certificate and maintenance let it through) wait up to 50 ms; after a
-- failure this worker skips them for 5 s, and a worker asks the agent for
-- at most SOFT_BUDGET addresses a second that miss the cache (a token
-- bucket; the requests over it count as of unknown country, without
-- backoff). So an agent that does not answer, or a flood of new client
-- addresses, slows down no request for long. peek() reads the cache only:
-- the log phase cannot use sockets, and requests refused before the soft
-- lookup use it too.
local cjson = require("cjson.safe")
local cache = assert(require("resty.lrucache").new(10000))
local _M = { socket = "" }

_M.HARD_TIMEOUT = 200
_M.SOFT_TIMEOUT = 50
_M.SOFT_BACKOFF = 5
_M.SOFT_BUDGET = 200

-- No soft lookups before this time (ngx.now()) in this worker.
local soft_until = 0
-- The soft lookups' token bucket: the tokens left at soft_at.
local soft_tokens, soft_at = _M.SOFT_BUDGET, 0

-- soft_take takes a token for a soft lookup at now: the bucket refills at
-- SOFT_BUDGET tokens a second and holds at most SOFT_BUDGET.
local function soft_take(now)
  local elapsed = now - soft_at
  if elapsed < 0 then elapsed = 0 end
  local tokens = soft_tokens + elapsed * _M.SOFT_BUDGET
  if tokens > _M.SOFT_BUDGET then tokens = _M.SOFT_BUDGET end
  soft_at = now
  if tokens < 1 then
    soft_tokens = tokens
    return false
  end
  soft_tokens = tokens - 1
  return true
end

local function fetch(ip, timeout)
  local sock = ngx.socket.tcp()
  sock:settimeout(timeout)
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

-- lookup returns the record of ip ({country, subdivision, asnum, as_name})
-- or nil when GeoIP is unavailable; soft: a soft lookup (see above).
function _M.lookup(ip, soft)
  local hit = cache:get(ip)
  if hit then return hit end
  if _M.socket == "" or type(ip) ~= "string" then return nil end
  if not soft then return fetch(ip, _M.HARD_TIMEOUT) end
  local now = ngx.now()
  if now < soft_until or not soft_take(now) then return nil end
  local record = fetch(ip, _M.SOFT_TIMEOUT)
  if not record then soft_until = ngx.now() + _M.SOFT_BACKOFF end
  return record
end

-- peek returns the cached record of ip, never asking the agent.
function _M.peek(ip)
  if type(ip) ~= "string" then return nil end
  return (cache:get(ip))
end

-- reset forgets the cache, the soft backoff and the spent budget (tests).
function _M.reset()
  cache:flush_all()
  soft_until = 0
  soft_tokens, soft_at = _M.SOFT_BUDGET, 0
end

return _M
