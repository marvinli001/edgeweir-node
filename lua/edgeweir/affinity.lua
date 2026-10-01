-- edgeweir.affinity: cookie-based session affinity (OriginPool.session_affinity).
--
-- The cookie __ew_affinity pins a client to the origin that served it:
--
--   <origin id>.<exp>.<kid>.<sig>
--   sig = base64url (no padding) of HMAC-SHA256(secret of key kid,
--         "affinity|" .. site id .. "|" .. origin id .. "|" .. exp)
--
-- exp is in Unix seconds. The cluster's challenge keys sign it
-- (edgeweir.challenge: the current key signs, next, current and previous
-- verify), so every node of the cluster honors it. Without keys there is
-- no pin and no cookie.
--
-- Origin layer: a valid pin whose origin is still in the pool and eligible
-- in the tier that takes traffic goes first (edgeweir.lb; origins that are
-- forbidden or unusable are skipped like any other); retries may leave it.
-- The origin layer then announces the cookie to issue in the internal
-- response header X-Edgeweir-Affinity when there was no valid pin, the
-- pinned origin did not answer the last attempt, or less than half of the
-- lifetime is left. The edge layer turns it into Set-Cookie on responses
-- that did not come from its cache and never forwards the header itself.
local b64 = require("ngx.base64")
local challenge = require("edgeweir.challenge")

local _M = {}

_M.COOKIE = "__ew_affinity"
_M.HEADER = "X-Edgeweir-Affinity"

local tonumber, type = tonumber, type

local function message(site_id, origin_id, exp)
  return "affinity|" .. site_id .. "|" .. origin_id .. "|" .. exp
end

-- sign returns the cookie value pinning site_id to origin_id until exp
-- with key ({id, secret}).
function _M.sign(key, site_id, origin_id, exp)
  exp = string.format("%.0f", exp)
  return origin_id .. "." .. exp .. "." .. key.id .. "." ..
    b64.encode_base64url(challenge.mac(key, message(site_id, origin_id, exp)))
end

-- verify returns the origin id and expiry of a valid cookie value of
-- site_id, or nil and a reason. keys = edgeweir.challenge.keys().
function _M.verify(keys, site_id, value, now)
  if type(value) ~= "string" or #value > 512 then
    return nil, "malformed"
  end
  local origin, exp, kid, sig = value:match("^([A-Za-z0-9_-]+)%.(%d+)%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  if not origin or #exp > 12 then
    return nil, "malformed"
  end
  local key = keys and keys.by_id[kid]
  if not key then
    return nil, "unknown key"
  end
  if not challenge.equal(b64.encode_base64url(challenge.mac(key, message(site_id, origin, exp))), sig) then
    return nil, "bad signature"
  end
  local e = tonumber(exp)
  if not e or e <= now then
    return nil, "expired"
  end
  return origin, e
end

-- cookie returns the Set-Cookie value for an announced cookie value.
function _M.cookie(value, ttl, https)
  return _M.COOKIE .. "=" .. value .. "; Path=/; Max-Age=" .. ttl .. "; HttpOnly; SameSite=Lax" .. (https and "; Secure" or "")
end

-- valid_value reports whether value can only be a cookie value this module
-- produced (no separators that would break the Set-Cookie header).
function _M.valid_value(value)
  return type(value) == "string" and #value <= 512 and value:match("^[A-Za-z0-9_.-]+$") ~= nil
end

-- renew reports whether the origin layer must announce a new cookie:
-- pin/exp are the request's valid pin (nil without one), chosen the origin
-- of the last attempt.
function _M.renew(pin, exp, chosen, ttl, now)
  return pin == nil or pin ~= chosen or (exp - now) < ttl / 2
end

-- append_cookie adds a Set-Cookie header to the response headers h,
-- keeping the origin's.
function _M.append_cookie(h, value)
  local current = h["Set-Cookie"]
  if current == nil then
    h["Set-Cookie"] = value
  elseif type(current) == "table" then
    current[#current + 1] = value
    h["Set-Cookie"] = current
  else
    h["Set-Cookie"] = { current, value }
  end
end

return _M
