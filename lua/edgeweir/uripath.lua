-- edgeweir.uripath: whether a request's raw path may reach the origin as a
-- different path than nginx's normalized $uri.
--
-- Path scopes (access authentication, access control, maintenance, HTTP-01)
-- and the cache key compare $uri, which nginx decodes and resolves dot
-- segments in, while the origin receives the raw request URI. An origin that
-- decodes "%2F" or "%5C" into separators, treats "\" as "/", resolves dot
-- segments after decoding or drops ";" parameters (Java servlets) can route
-- such a request to another path than the one checked: "/admin/..%2Fx" is
-- "/x" here and under "/admin/" at a Go ServeMux origin. A request is
-- ambiguous when its raw path holds an encoded "/", "\" or ".", a "\", a
-- ";" or a dot segment. Then scopes that add a check include it, exemptions
-- and scopes that grant something (CORS) never apply, HTTP-01 is not
-- recognized and nothing is cached.
local _M = {}

local find, lower, sub = string.find, string.lower, string.sub

-- ambiguous reports whether raw_path (the request URI before "?") is
-- ambiguous in the sense above.
function _M.ambiguous(raw_path)
  if find(raw_path, "[\\;]") then return true end
  local p = lower(raw_path)
  if find(p, "%2f", 1, true) or find(p, "%5c", 1, true) or find(p, "%2e", 1, true) then
    return true
  end
  -- Dot segments: "/./", "/../", or one at the end.
  return find(p, "/%.%.?/") ~= nil or find(p, "/%.%.?$") ~= nil
end

-- raw_path is the request URI before its query string.
function _M.raw_path(request_uri)
  local q = find(request_uri, "?", 1, true)
  return q and sub(request_uri, 1, q - 1) or request_uri
end

local function request_uri() return ngx.var.request_uri end

-- request_ambiguous is ambiguous() for the current request, computed once
-- (false outside a request, as in timers).
function _M.request_ambiguous()
  local ctx = ngx.ctx
  local v = ctx.edgeweir_path_ambiguous
  if v == nil then
    local ok, uri = pcall(request_uri)
    v = ok and uri ~= nil and _M.ambiguous(_M.raw_path(uri)) or false
    ctx.edgeweir_path_ambiguous = v
  end
  return v
end

return _M
