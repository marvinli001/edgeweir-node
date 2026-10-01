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
--
-- Active health checks run in the agent (OriginPool.active_health_check),
-- which pushes the full set of origins its probes mark down with
-- PUT /v1/origins/active {ttl, down: [{site_id, origin_id}]} on every
-- change and at least every 30 seconds:
--
--   a|<key>  marked down by the active check (expires after ttl, so the
--            marks of an agent that stopped pushing do not outlive it)
--   a#keys   JSON list of the a| keys of the last push (a later push
--            deletes the ones that left)
--   a#lock   held while a push is written
--
-- An origin that either check marks down takes no traffic; active marks
-- only count for sites whose pool has active checks (is_down's active
-- argument, the site table's active_health flag). GET /v1/origins/health
-- reports the passive state only.
local cjson = require("cjson.safe")

local _M = {}

local find, sub = string.find, string.sub
local dict = ngx.shared.edgeweir_health
local TTL = 86400
local FIELDS = { "f|", "d|", "t|", "e|", "m|", "c|", "q|" }

-- MAX_ACTIVE bounds the marks of one push; MAX_ACTIVE_TTL their lifetime.
_M.MAX_ACTIVE = 10000
_M.MAX_ACTIVE_TTL = 86400

local function key(site_id, origin_id)
  return site_id .. "|" .. origin_id
end

-- is_down reports whether an origin takes no traffic: marked down by the
-- passive check until its recovery time, or (active: the site's pool has
-- active checks) by the agent's active check.
function _M.is_down(site_id, origin_id, now, active)
  local k = key(site_id, origin_id)
  local until_ = dict:get("d|" .. k)
  if until_ ~= nil and until_ > (now or ngx.now()) then
    return true
  end
  return active == true and dict:get("a|" .. k) ~= nil
end

local function valid_id(s)
  return type(s) == "string" and #s > 0 and #s <= 128 and not find(s, "[^A-Za-z0-9_-]")
end

-- replace_active installs the set of origins the active check marks down:
-- doc = {ttl (seconds), down = [{site_id, origin_id}]}. Returns {down = n}
-- or nil, error, HTTP status.
function _M.replace_active(doc)
  if type(doc) ~= "table" then
    return nil, "document must be an object", 400
  end
  local ttl = tonumber(doc.ttl)
  if not ttl or ttl < 1 or ttl > _M.MAX_ACTIVE_TTL or ttl ~= math.floor(ttl) then
    return nil, "ttl must be 1-" .. _M.MAX_ACTIVE_TTL .. " seconds", 400
  end
  local down = doc.down
  if down == nil or down == cjson.null then
    down = {}
  end
  if type(down) ~= "table" or #down > _M.MAX_ACTIVE then
    return nil, "down must be an array of at most " .. _M.MAX_ACTIVE .. " origins", 400
  end
  local keys, seen = {}, {}
  for i = 1, #down do
    local d = down[i]
    if type(d) ~= "table" or not valid_id(d.site_id) or not valid_id(d.origin_id) then
      return nil, "invalid origin #" .. i, 400
    end
    local k = "a|" .. key(d.site_id, d.origin_id)
    if not seen[k] then
      seen[k] = true
      keys[#keys + 1] = k
    end
  end
  local ok, err = dict:add("a#lock", true, 30)
  if not ok then
    if err == "exists" then
      return nil, "another update is in progress", 409
    end
    return nil, "lock: " .. tostring(err), 500
  end
  for i = 1, #keys do
    local sok, serr = dict:safe_set(keys[i], true, ttl)
    if not sok then
      dict:delete("a#lock")
      return nil, "shared dict edgeweir_health: " .. tostring(serr), serr == "no memory" and 507 or 500
    end
  end
  local previous = cjson.decode(dict:get("a#keys") or "")
  if type(previous) == "table" then
    for i = 1, #previous do
      if not seen[previous[i]] then
        dict:delete(previous[i])
      end
    end
  end
  if cjson.empty_array_mt and #keys == 0 then
    setmetatable(keys, cjson.empty_array_mt)
  end
  local sok, serr = dict:safe_set("a#keys", cjson.encode(keys), ttl)
  dict:delete("a#lock")
  if not sok then
    return nil, "shared dict edgeweir_health: " .. tostring(serr), serr == "no memory" and 507 or 500
  end
  return { down = #keys }
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
