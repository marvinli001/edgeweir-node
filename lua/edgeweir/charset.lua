-- edgeweir.charset: the charset parameter of text responses (Site.charset,
-- feature site-content-v1).
--
-- For responses from the origin or the cache whose Content-Type is
-- text/*, application/javascript, application/json or application/xml,
-- the edge adds "; charset=<name>" when there is none, replaces an
-- existing one when force is set, and writes the name in upper case when
-- uppercase is set. Only the header changes; the body is never converted.
local _M = {}

local find, lower, match, upper, gsub = string.find, string.lower, string.match, string.upper, string.gsub

local TYPES = { ["application/javascript"] = true, ["application/json"] = true, ["application/xml"] = true }

-- applies reports whether a Content-Type value names one of the types.
function _M.applies(content_type)
  if type(content_type) ~= "string" then
    return false
  end
  local mime = lower(match(content_type, "^%s*([^;%s]+)") or "")
  return mime:sub(1, 5) == "text/" or TYPES[mime] == true
end

-- value returns the Content-Type value with the setting applied, or nil
-- when it stays as it is.
function _M.value(content_type, setting)
  if not setting or not _M.applies(content_type) then
    return nil
  end
  local name = setting.uppercase and upper(setting.name) or setting.name
  local s = find(lower(content_type), ";%s*charset%s*=")
  if not s then
    return (gsub(content_type, "%s*$", "")) .. "; charset=" .. name
  end
  if not setting.force then
    return nil
  end
  -- Replace the charset parameter's value (quoted or a token).
  local before = content_type:sub(1, s - 1)
  local rest = content_type:sub(s)
  local prefix = match(rest, "^;%s*[Cc][Hh][Aa][Rr][Ss][Ee][Tt]%s*=%s*")
  local value = rest:sub(#prefix + 1)
  -- The old value: quoted, or a token up to the next parameter.
  local old = match(value, '^"[^"]*"') or match(value, "^[^;%s]*")
  return before .. prefix .. name .. value:sub(#old + 1)
end

-- apply rewrites the response's Content-Type (edge layer header filter).
function _M.apply(h, setting)
  local ct = h["Content-Type"]
  if type(ct) == "table" then
    ct = ct[1]
  end
  local v = _M.value(ct, setting)
  if v then
    h["Content-Type"] = v
  end
end

return _M
