-- edgeweir.health: passive health checks of origins.
--
-- Real traffic is the probe: every attempt that fails (connect error,
-- timeout, 502/503/504, or an unresolvable host name) counts as a failure,
-- any other response resets the counter. After max_fails consecutive
-- failures the origin is down for recovery seconds; afterwards traffic tries
-- it again and a single further failure marks it down again.
--
-- An origin counts as unhealthy from its max_fails-th consecutive failure
-- until a request succeeds again (the recovery time only decides when
-- traffic may try it again).
--
-- State lives in lua_shared_dict "edgeweir_health" (shared by all workers,
-- entries expire after a day without failures), keyed by site and origin
-- (<key> = "<site id>|<origin id>"; ids never contain "|"):
--
--   f|<key>  consecutive failures     d|<key>  down until (epoch s)
--   t|<key>  last failure (epoch s)   e|<key>  last error (text)
--   m|<key>  max_fails of its site    c|<key>  last error code
--   q|<key>  JSON parameters of the last error code
--
-- Error codes (the console localizes them, last_error is the fallback):
-- connect_failed, timeout, upstream_status {status}, dns_failed {host},
-- address_forbidden {address}, tls_failed; empty for anything else.
local cjson = require("cjson.safe")

local _M = {}

local find, sub = string.find, string.sub
local dict = ngx.shared.edgeweir_health
local TTL = 86400
local FIELDS = { "f|", "d|", "t|", "e|", "m|", "c|", "q|" }

local function key(site_id, origin_id)
  return site_id .. "|" .. origin_id
end

function _M.is_down(site_id, origin_id, now)
  local until_ = dict:get("d|" .. key(site_id, origin_id))
  return until_ ~= nil and until_ > (now or ngx.now())
end

-- failure records a failed attempt; returns true when the origin is down.
-- code and params (string values) describe the error for the console.
function _M.failure(site_id, origin_id, err, max_fails, recovery, now, code, params)
  now = now or ngx.now()
  local k = key(site_id, origin_id)
  local n = dict:incr("f|" .. k, 1, 0, TTL) or 1
  dict:set("t|" .. k, now, TTL)
  dict:set("e|" .. k, sub(err or "", 1, 200), TTL)
  dict:set("m|" .. k, max_fails or 3, TTL)
  dict:set("c|" .. k, code or "", TTL)
  if type(params) == "table" and next(params) ~= nil then
    dict:set("q|" .. k, cjson.encode(params), TTL)
  else
    dict:delete("q|" .. k)
  end
  if n >= (max_fails or 3) then
    dict:set("d|" .. k, now + (recovery or 30), TTL)
    return true
  end
  return false
end

-- success resets the failure counter of an origin.
function _M.success(site_id, origin_id)
  local k = key(site_id, origin_id)
  if dict:get("f|" .. k) then
    for i = 1, #FIELDS do
      dict:delete(FIELDS[i] .. k)
    end
  end
end

-- report lists every origin with recorded failures.
function _M.report(now)
  now = now or ngx.now()
  local out = {}
  local keys = dict:get_keys(0)
  for i = 1, #keys do
    local k = keys[i]
    local bar = sub(k, 1, 2) == "f|" and find(k, "|", 3, true)
    if bar then
      local id = sub(k, 3)
      local until_ = dict:get("d|" .. id)
      local failures = dict:get(k) or 0
      out[#out + 1] = {
        site_id = sub(k, 3, bar - 1),
        origin_id = sub(k, bar + 1),
        healthy = failures < (dict:get("m|" .. id) or 3),
        failures = failures,
        last_failure_at = dict:get("t|" .. id) or 0,
        down_until = (until_ and until_ > now) and until_ or 0,
        last_error = dict:get("e|" .. id) or "",
        last_error_code = dict:get("c|" .. id) or "",
      }
      local q = dict:get("q|" .. id)
      local params = q and cjson.decode(q)
      if type(params) == "table" then
        out[#out].last_error_params = params
      end
    end
  end
  return out
end

return _M
