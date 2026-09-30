-- edgeweir.compress: response compression negotiation (edge layer).
--
-- The site's server block enables gzip, Brotli and Zstandard as configured
-- (nginx.conf); each filter compresses when the request's Accept-Encoding
-- names its coding. Filters ignore q-values and would all try, so the
-- edge layer chooses first: in its header filter (which runs before the
-- compression filters) it picks one coding from the client's
-- Accept-Encoding by q-value among the codings enabled for the site and
-- applicable to this response, zstd > br > gzip at equal q, and rewrites
-- Accept-Encoding to that coding alone (or removes it). Responses that
-- already carry a Content-Encoding are never compressed again.
--
-- Towards the origin, sites the edge compresses send no Accept-Encoding
-- (router: $edgeweir_upstream_ae), and the origin layer drops
-- Accept-Encoding from the Vary of uncompressed responses (strip_vary):
-- the cache keeps one identity object that serves every coding. The
-- filters add Vary: Accept-Encoding to responses they could encode.
local _M = {}

local lower, find, sub, match = string.lower, string.find, string.sub, string.match
local gmatch, tonumber = string.gmatch, tonumber

-- Codings in preference order at equal q-values.
_M.PREFERENCE = { "zstd", "br", "gzip" }

-- parse_qvalue returns a weight in [0, 1] from "q=..." (RFC 9110, 12.4.2),
-- or nil when malformed.
local function parse_qvalue(params)
  if not params or params == "" then return 1 end
  local q = match(params, "^%s*;%s*[qQ]%s*=%s*([0-9.]+)%s*$")
  if not q then return nil end
  -- qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
  if q == "0" or q == "1" or match(q, "^0%.%d?%d?%d?$") or match(q, "^1%.0?0?0?$") then
    return tonumber(q) or 0
  end
  return nil
end

-- parse returns the q-value of every coding named in an Accept-Encoding
-- value (lowercase names; "x-gzip" counts as gzip) and whether any element
-- was present. A coding named twice keeps its lowest q-value; malformed
-- elements are ignored.
function _M.parse(value)
  local q = {}
  if not value then return q end
  for element in gmatch(value, "[^,]+") do
    local name, params = match(element, "^%s*([%w!#$%%&'*+.^_`|~-]+)%s*(.-)%s*$")
    if name then
      name = lower(name)
      if name == "x-gzip" then name = "gzip" end
      local weight = parse_qvalue(params)
      if weight and (q[name] == nil or weight < q[name]) then
        q[name] = weight
      end
    end
  end
  return q
end

-- choose returns the coding for a client's Accept-Encoding value among
-- candidates (codings enabled and applicable), or nil for identity.
-- A coding the client does not name is acceptable with the q-value of "*"
-- (RFC 9110, 12.5.3); q=0 means not acceptable; no Accept-Encoding at all
-- means identity. Ties go to the candidate listed first in PREFERENCE.
function _M.choose(accept_encoding, candidates)
  if not accept_encoding or not candidates or #candidates == 0 then return nil end
  local q = _M.parse(accept_encoding)
  local star = q["*"]
  local best, best_q = nil, 0
  for _, coding in ipairs(_M.PREFERENCE) do
    local offered = false
    for i = 1, #candidates do
      if candidates[i] == coding then offered = true; break end
    end
    if offered then
      local weight = q[coding]
      if weight == nil then weight = star end
      if weight and weight > best_q then
        best, best_q = coding, weight
      end
    end
  end
  return best
end

-- type_matches reports whether a Content-Type value (parameters ignored,
-- case-insensitive) is text/html or one of types, like nginx's
-- *_types directives (text/html is always included).
function _M.type_matches(content_type, types)
  if not content_type then return false end
  local mime = lower(match(content_type, "^%s*([^;%s]+)") or "")
  if mime == "" then return false end
  if mime == "text/html" then return true end
  if types then
    for i = 1, #types do
      if types[i] == mime then return true end
    end
  end
  return false
end

-- applicable returns the codings of the site's tls options that nginx's
-- filters would apply to a response: status 200, 403 or 404, not already
-- encoded, a known length not below the minimum, a listed type.
-- resp: { status, content_type, content_length (number or nil),
-- content_encoding, head (HEAD request) }.
function _M.applicable(tls, resp)
  local out = {}
  if not tls or resp.head then return out end
  local status = resp.status
  if status ~= 200 and status ~= 403 and status ~= 404 then return out end
  if resp.content_encoding and resp.content_encoding ~= "" then return out end
  local length = resp.content_length
  local function add(coding, on, min_length, types)
    if not on then return end
    if length and length < math.max(tonumber(min_length) or 0, 1) then return end
    if not _M.type_matches(resp.content_type, types) then return end
    out[#out + 1] = coding
  end
  add("zstd", tls.zstd, tls.zstd_min_length, tls.zstd_types)
  add("br", tls.brotli, tls.brotli_min_length, tls.brotli_types)
  add("gzip", tls.gzip, tls.gzip_min_length, tls.gzip_types)
  return out
end

-- enabled reports whether the edge compresses any coding for the site.
function _M.enabled(site)
  local tls = site and site.tls
  return tls ~= nil and (tls.gzip == true or tls.brotli == true or tls.zstd == true)
end

-- strip_vary returns a Vary value without Accept-Encoding ("" when nothing
-- remains); "*" and values without Accept-Encoding come back unchanged.
function _M.strip_vary(value)
  if not value or value == "" then return value end
  if not find(lower(value), "accept-encoding", 1, true) then return value end
  local kept = {}
  for token in gmatch(value, "[^,]+") do
    local name = match(token, "^%s*(.-)%s*$")
    if name ~= "" and lower(name) ~= "accept-encoding" then
      kept[#kept + 1] = name
    end
  end
  return table.concat(kept, ", ")
end

-- header_value joins a header that may occur several times.
local function header_value(v)
  if type(v) == "table" then return table.concat(v, ", ") end
  return v
end

-- header_filter rewrites the request's Accept-Encoding for the filters
-- (edge layer header filter, before the compression filters run).
function _M.header_filter(site)
  if not _M.enabled(site) then return end
  local h = ngx.header
  local length = tonumber(header_value(h["Content-Length"]) or "")
  local candidates = _M.applicable(site.tls, {
    status = ngx.status,
    content_type = header_value(h["Content-Type"]),
    content_length = length,
    content_encoding = header_value(h["Content-Encoding"]),
    head = ngx.req.get_method() == "HEAD",
  })
  local coding = _M.choose(ngx.var.http_accept_encoding, candidates)
  if coding then
    ngx.req.set_header("Accept-Encoding", coding)
  else
    ngx.req.clear_header("Accept-Encoding")
  end
end

-- origin_header_filter drops Accept-Encoding from the Vary of an
-- uncompressed origin response of a site the edge compresses (origin
-- layer header filter, before the edge layer caches the response).
function _M.origin_header_filter(site)
  if not _M.enabled(site) then return end
  local h = ngx.header
  local encoding = header_value(h["Content-Encoding"])
  if encoding and encoding ~= "" and lower(encoding) ~= "identity" then return end
  local vary = header_value(h["Vary"])
  if not vary then return end
  local stripped = _M.strip_vary(vary)
  if stripped ~= vary then
    h["Vary"] = stripped ~= "" and stripped or nil
  end
end

return _M
