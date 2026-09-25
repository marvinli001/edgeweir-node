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
--   t|<key>  last failure (epoch s)   e|<key>  last error
--   m|<key>  max_fails of its site
local _M = {}

local find, sub = string.find, string.sub
local dict = ngx.shared.edgeweir_health
local TTL = 86400
local FIELDS = { "f|", "d|", "t|", "e|", "m|" }

local function key(site_id, origin_id)
  return site_id .. "|" .. origin_id
end

function _M.is_down(site_id, origin_id, now)
  local until_ = dict:get("d|" .. key(site_id, origin_id))
  return until_ ~= nil and until_ > (now or ngx.now())
end

-- failure records a failed attempt; returns true when the origin is down.
function _M.failure(site_id, origin_id, err, max_fails, recovery, now)
  now = now or ngx.now()
  local k = key(site_id, origin_id)
  local n = dict:incr("f|" .. k, 1, 0, TTL) or 1
  dict:set("t|" .. k, now, TTL)
  dict:set("e|" .. k, sub(err or "", 1, 200), TTL)
  dict:set("m|" .. k, max_fails or 3, TTL)
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
      }
    end
  end
  return out
end

return _M
