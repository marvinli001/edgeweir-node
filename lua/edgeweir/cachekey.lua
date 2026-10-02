-- edgeweir.cachekey: the cache key of a request.
--
-- Key layout (every part after the path is optional):
--
--   <site id>:<generation>:<scheme>://<host><path>[?<query>][|d=<m|d>]
--     [|h:<name>=<value>...][|c:<name>=<value>...][#<purge epoch>]
--
-- The path is nginx's normalized $uri (percent-decoded, dot segments
-- resolved, slashes merged), the same path cache rules and purge markers
-- are matched against, so "/%73tatic/x" and "/static/x" share one key and
-- one purge. Every variable part is escaped (percent-encoding "%", "|",
-- "#", control characters and, depending on the part, "?", "/", ":" and
-- "="), so no host, path, query, header or cookie value can imitate
-- another part: the key is unambiguous. Header values are read from all
-- request headers (the same table the internal-header stripping uses).
--
-- For ordinary URLs with the default policy (full query string, host
-- included) the key still equals the Phase 0 key
-- "<site>:<gen>:<scheme>://<host><request_uri>". The purge epoch
-- (edgeweir.purge) changes the key of purged URLs, which makes the next
-- request a genuine MISS for every variant (query forms, devices, headers,
-- cookies, slices) at once.
local _M = {}

local concat, sort = table.concat, table.sort
local byte, char, format, gmatch, gsub, find, lower, match, sub = string.byte, string.char, string.format,
  string.gmatch, string.gsub, string.find, string.lower, string.match, string.sub
local re_find = ngx.re.find
local unescape = ngx.unescape_uri

local function hex_escape(c)
  return format("%%%02X", byte(c))
end

-- Characters escaped in each part of the key.
local ESC_HOST = "[%%|#?/%c]"
local ESC_PATH = "[%%|#?%c]"
local ESC_QUERY = "[%%|#%c]"
local ESC_VALUE = "[%%|#:=%c]"

-- escape percent-encodes the characters of set in s.
local function escape(s, set)
  return (gsub(s, set, hex_escape))
end

-- Common mobile user agent tokens (MDN recommends "Mobi"); tablets count as
-- mobile.
local MOBILE_RE = [[Mobi|Android|iPhone|iPad|iPod|Windows Phone|BlackBerry|Opera Mini|webOS]]

_M.escape = escape
_M.ESC_HOST, _M.ESC_PATH, _M.ESC_QUERY, _M.ESC_VALUE = ESC_HOST, ESC_PATH, ESC_QUERY, ESC_VALUE

local function decode_hex(h)
  return char(tonumber(h, 16))
end

-- normalize_path mirrors nginx's $uri normalization for a raw path (as
-- sent in a purge request): decode %XX (but not "+"), resolve "." and
-- ".." segments (never above the root) and merge slashes; a trailing
-- slash, or one implied by a final "." or "..", is kept.
function _M.normalize_path(raw)
  if type(raw) ~= "string" or raw == "" then
    return "/"
  end
  local p = gsub(raw, "%%(%x%x)", decode_hex)
  local out, last = {}, nil
  for seg in gmatch(p, "[^/]+") do
    last = seg
    if seg == ".." then
      out[#out] = nil
    elseif seg ~= "." then
      out[#out + 1] = seg
    end
  end
  local res = "/" .. concat(out, "/")
  if res ~= "/" and (sub(p, -1) == "/" or last == "." or last == "..") then
    res = res .. "/"
  end
  return res
end

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

-- purge_query is the form in which purge markers compare query strings
-- (edgeweir.purge): normalize_query with every segment percent-decoded
-- before sorting. A URL purge then also covers the spellings of its query
-- that differ only in percent-encoding ("q=%E4%B8%AD" and the console's
-- re-encoding of what was typed, "%3c" and "<", "%41" and "A"); the key
-- itself keeps the raw query, so this may purge more variants than the
-- operator named, never fewer.
function _M.purge_query(args, key)
  if not args or args == "" or key.query == "ignore" then
    return ""
  end
  local include = key.query == "include"
  local parts = {}
  for segment in gmatch(args, "[^&]+") do
    if not include or key._params[param_name(segment)] or key._params[unescape(param_name(segment))] then
      parts[#parts + 1] = gsub(segment, "%%(%x%x)", decode_hex)
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

-- header_value escapes a header value; repeated fields are joined with
-- "," as HTTP allows (RFC 9110, section 5.3).
local function header_value(v)
  if type(v) == "table" then
    local out = {}
    for i = 1, #v do
      out[i] = escape(v[i], ESC_VALUE)
    end
    return concat(out, ",")
  end
  return v and escape(v, ESC_VALUE) or ""
end

local function trim(s)
  return (match(s, "^[ \t]*(.-)[ \t]*$"))
end

-- key_cookies reads the cookies the key names (names) from the request's
-- Cookie header (a string, a list of fields, or nil) as origins do (RFC
-- 6265, section 5.4): pairs separated by ";", names compared exactly.
-- Returns name -> raw value, or nil when the key would be ambiguous: a key
-- cookie that appears twice, in another case, percent-encoded, without
-- "=", or after a "," (nginx's $cookie_ and other parsers split there and
-- compare names in any case). Origins disagree about which of those
-- counts, so such requests are not cached at all.
function _M.key_cookies(header, names)
  if type(header) == "table" then
    header = concat(header, "; ")
  end
  local values = {}
  if type(header) ~= "string" or header == "" then
    return values
  end
  local exact, loose, wanted = {}, {}, {}
  for i = 1, #names do
    exact[names[i]] = 0
    wanted[lower(names[i])] = true
  end
  for pair in gmatch(header, "[^;]+") do
    local eq = find(pair, "=", 1, true)
    local name = eq and match(sub(pair, 1, eq - 1), "^[ \t]*(.*)$")
    if name and exact[name] then
      exact[name] = exact[name] + 1
      values[name] = sub(pair, eq + 1)
    end
  end
  for segment in gmatch(header, "[^;,]+") do
    local name = lower(unescape(trim(match(segment, "^[^=]*"))))
    if wanted[name] then
      loose[name] = (loose[name] or 0) + 1
    end
  end
  for i = 1, #names do
    local n = loose[lower(names[i])] or 0
    if n > 1 or (n == 1 and exact[names[i]] ~= 1) then
      return nil
    end
  end
  return values
end

-- build returns the cache key. req = { scheme, host, path (normalized
-- $uri), args (raw query string), user_agent, headers (lowercase name ->
-- value or list, e.g. ngx.req.get_headers(0)), cookie (name -> value, see
-- key_cookies) }.
function _M.build(site, req, epoch)
  local key = site.cache_key
  local parts = { site.id, ":", site.cache_generation, ":", req.scheme, "://" }
  if not key.exclude_host then
    parts[#parts + 1] = escape(req.host or "", ESC_HOST)
  end
  parts[#parts + 1] = escape(req.path, ESC_PATH)
  local q = _M.normalize_query(req.args, key)
  if q ~= "" then
    parts[#parts + 1] = "?"
    parts[#parts + 1] = escape(q, ESC_QUERY)
  end
  if key.device then
    parts[#parts + 1] = "|d="
    parts[#parts + 1] = _M.device(req.user_agent)
  end
  local headers = key.headers
  for i = 1, #headers do
    local name = headers[i]
    parts[#parts + 1] = "|h:" .. escape(name, ESC_VALUE) .. "=" .. header_value(req.headers and req.headers[name])
  end
  local cookies = key.cookies
  for i = 1, #cookies do
    local name = cookies[i]
    local v = req.cookie and req.cookie(name)
    parts[#parts + 1] = "|c:" .. escape(name, ESC_VALUE) .. "=" .. (v and escape(v, ESC_VALUE) or "")
  end
  return _M.with_epoch(concat(parts), epoch)
end

-- with_epoch appends a purge epoch to a key built without one ("#" never
-- appears elsewhere in a key: edgeweir.cachetags splits keys on it).
function _M.with_epoch(base, epoch)
  if epoch and epoch > 0 then
    return base .. "#" .. format("%.0f", epoch) -- integer milliseconds
  end
  return base
end

return _M
