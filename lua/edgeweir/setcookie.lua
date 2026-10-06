-- edgeweir.setcookie: responses cached with their Set-Cookie lines
-- (CacheRule.cache_set_cookie, feature site-content-v1).
--
-- nginx's cache never stores a response with Set-Cookie. For a response a
-- rule caches with its cookies, the origin layer moves every Set-Cookie
-- line into the carrier header X-Edgeweir-Set-Cookie (carry): each line
-- with "%" written as "%25" and "," as "%2C", the lines joined with ",",
-- so the carrier is one header line. The edge layer hides the carrier
-- from clients in every caching location (proxy_hide_header, cache hits
-- included) and restores the lines (restore) only on a response fetched
-- from the origin for this request: cache status MISS, EXPIRED or BYPASS,
-- never in a subrequest (slices, background updates). A cached object may
-- hold one visitor's cookies; no other visitor ever receives them.
local _M = {}

local concat, gsub, gmatch = table.concat, string.gsub, string.gmatch

_M.HEADER = "X-Edgeweir-Set-Cookie"

-- FROM_ORIGIN are the cache statuses of responses fetched for the request.
_M.FROM_ORIGIN = { MISS = true, EXPIRED = true, BYPASS = true }

local ESCAPE = { ["%"] = "%25", [","] = "%2C" }
local UNESCAPE = { ["%25"] = "%", ["%2C"] = ",", ["%2c"] = "," }

-- encode joins Set-Cookie lines (a string or a list) into a carrier value.
function _M.encode(lines)
  if type(lines) == "string" then
    lines = { lines }
  end
  local out = {}
  for i = 1, #lines do
    out[i] = gsub(lines[i], "[%%,]", ESCAPE)
  end
  return concat(out, ",")
end

-- decode splits a carrier value into its Set-Cookie lines.
function _M.decode(value)
  local out = {}
  if type(value) ~= "string" or value == "" then
    return out
  end
  for item in gmatch(value, "[^,]+") do
    out[#out + 1] = gsub(item, "%%2[5Cc]", UNESCAPE)
  end
  return out
end

-- carry moves the response's Set-Cookie lines into the carrier (origin
-- layer header filter).
function _M.carry(h)
  local lines = h["Set-Cookie"]
  if lines == nil then
    return
  end
  h[_M.HEADER] = _M.encode(lines)
  h["Set-Cookie"] = nil
end

-- restore adds the carried lines to the response as Set-Cookie (edge
-- layer header filter): carried is $upstream_http_x_edgeweir_set_cookie,
-- cache_status $upstream_cache_status.
function _M.restore(h, carried, cache_status, subrequest)
  if subrequest or not carried or carried == "" or not _M.FROM_ORIGIN[cache_status or ""] then
    return false
  end
  local lines = _M.decode(carried)
  if #lines == 0 then
    return false
  end
  local existing = h["Set-Cookie"]
  if existing ~= nil then
    if type(existing) == "string" then
      existing = { existing }
    end
    for i = 1, #lines do
      existing[#existing + 1] = lines[i]
    end
    lines = existing
  end
  h["Set-Cookie"] = lines
  return true
end

return _M
