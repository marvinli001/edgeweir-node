-- edgeweir.cachekey: the cache key of a request.
--
-- Key layout (every part after the path is optional):
--
--   <site id>:<generation>:<scheme>://<host><path>[?<query>][|d=<m|d>]
--     [|h:<name>=<value>...][|c:<name>=<value>...][#<purge epoch>]
--
-- With the default policy (full query string, host included) the key equals
-- the Phase 0 key "<site>:<gen>:<scheme>://<host><request_uri>", so cached
-- objects survive the upgrade. The purge epoch (edgeweir.purge) changes the
-- key of purged URLs, which makes the next request a genuine MISS for every
-- variant (query forms, devices, headers, cookies, slices) at once.
local _M = {}

local concat, sort = table.concat, table.sort
local format, gmatch, find, sub = string.format, string.gmatch, string.find, string.sub
local re_find = ngx.re.find
local unescape = ngx.unescape_uri

-- Common mobile user agent tokens (MDN recommends "Mobi"); tablets count as
-- mobile.
local MOBILE_RE = [[Mobi|Android|iPhone|iPad|iPod|Windows Phone|BlackBerry|Opera Mini|webOS]]

-- prepare precomputes lookup tables on a decoded cache key policy.
function _M.prepare(key)
  key = type(key) == "table" and key or {}
  key.query = key.query or "all"
  local params = {}
  for _, p in ipairs(key.query_params or {}) do
    params[p] = true
  end
  key._params = params
  key.headers = key.headers or {}
  key.cookies = key.cookies or {}
  return key
end

local function param_name(segment)
  local eq = find(segment, "=", 1, true)
  return eq and sub(segment, 1, eq - 1) or segment
end

-- normalize_query returns the part of the raw query string args that enters
-- the key under policy key (without "?").
function _M.normalize_query(args, key)
  if not args or args == "" or key.query == "ignore" then
    return ""
  end
  local include = key.query == "include"
  if not include and not key.sort_query then
    return args
  end
  local parts = {}
  for segment in gmatch(args, "[^&]+") do
    if not include then
      parts[#parts + 1] = segment
    else
      local name = param_name(segment)
      if key._params[name] or key._params[unescape(name)] then
        parts[#parts + 1] = segment
      end
    end
  end
  if key.sort_query then
    sort(parts)
  end
  return concat(parts, "&")
end

-- device returns "m" for mobile user agents and "d" otherwise.
function _M.device(user_agent)
  if user_agent and re_find(user_agent, MOBILE_RE, "jo") then
    return "m"
  end
  return "d"
end

local function header_value(v)
  if type(v) == "table" then
    return concat(v, ",")
  end
  return v or ""
end

-- build returns the cache key. req = { scheme, host, path, args,
-- user_agent, headers (lowercase name -> value), cookie (name -> value) }.
function _M.build(site, req, epoch)
  local key = site.cache_key
  local parts = { site.id, ":", site.cache_generation, ":", req.scheme, "://" }
  if not key.exclude_host then
    parts[#parts + 1] = req.host
  end
  parts[#parts + 1] = req.path
  local q = _M.normalize_query(req.args, key)
  if q ~= "" then
    parts[#parts + 1] = "?"
    parts[#parts + 1] = q
  end
  if key.device then
    parts[#parts + 1] = "|d="
    parts[#parts + 1] = _M.device(req.user_agent)
  end
  local headers = key.headers
  for i = 1, #headers do
    local name = headers[i]
    parts[#parts + 1] = "|h:" .. name .. "=" .. header_value(req.headers and req.headers[name])
  end
  local cookies = key.cookies
  for i = 1, #cookies do
    local name = cookies[i]
    parts[#parts + 1] = "|c:" .. name .. "=" .. (req.cookie and req.cookie(name) or "")
  end
  if epoch and epoch > 0 then
    parts[#parts + 1] = "#"
    parts[#parts + 1] = format("%.0f", epoch) -- integer milliseconds
  end
  return concat(parts)
end

return _M
