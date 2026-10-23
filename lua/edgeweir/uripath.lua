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
-- ambiguous when its raw path holds an encoded "/", "\", ".", "%" or ";",
-- a "%u" escape, a "\", a ";", a "#" (nginx cuts $uri there), a dot segment,
-- or starts with "//" (a host to URL parsers such as Node's). Then scopes that add a check include it, exemptions
-- and scopes that grant something (CORS) never apply, HTTP-01 is not
-- recognized and nothing is cached.
--
-- Exemptions (excluded and exception prefixes, the allowed paths of
-- maintenance, CRS exclusion entries) also never apply to a raw path with
-- "//" anywhere: nginx merges slashes in $uri, so "/admin//public/x" is under
-- an excluded "/admin/public/" here, while an origin that keeps the empty
-- segment may route it to a handler of "/admin/". Such a path is otherwise
-- compared as $uri: an empty segment does not move it out of the prefix it
-- starts with.
--
-- A site's encoded path exemptions (Site.encoded_path_exemptions, feature
-- encoded-path-exemptions-v1) let raw paths that start with a listed
-- prefix (bytes, exactly) carry encoded slashes ("%2F", any case) and / or
-- ";" path parameters. Such a path is still ambiguous unless, with every
-- "%2F" read as "/" and every ";" up to the end of its segment removed, it
-- is not ambiguous; so "..%2F", "..;" or an encoded dot never pass. It is
-- then compared in every way an origin may read it (its views): decoded
-- as nginx does, with "%2F" kept inside its segment, and either of those
-- with ";" parameters removed. A scope that adds a check applies when $uri
-- or any view is in it (any_view); an exemption or grant only when $uri
-- and every view are (all_views). Access authentication refuses the
-- request when the readings select different rules. It is cached; with
-- "%2F" the key keeps it apart from "/" (class.key), while cache rules and
-- purges still match $uri. Exemptions still never apply when the path, or
-- its plain form, has "//". The console's reference is rule-engine
-- encoded-path.ts (shared encoded_path_vectors.json).
local _M = {}

local char, find, gsub, lower, sub = string.char, string.find, string.gsub, string.lower, string.sub

-- Escapes origins decode into separators, dots or parameters (lowercase).
local MARKERS = { "%2f", "%5c", "%2e", "%25", "%3b", "%u" }

-- ambiguous reports whether raw_path (the request URI before "?") is
-- ambiguous in the sense above.
function _M.ambiguous(raw_path)
  if find(raw_path, "[\\;#]") or sub(raw_path, 1, 2) == "//" then return true end
  local p = lower(raw_path)
  for _, m in ipairs(MARKERS) do
    if find(p, m, 1, true) then return true end
  end
  -- Dot segments: "/./", "/../", or one at the end.
  return find(p, "/%.%.?/") ~= nil or find(p, "/%.%.?$") ~= nil
end

-- raw_path is the request URI before its query string.
function _M.raw_path(request_uri)
  local q = find(request_uri, "?", 1, true)
  return q and sub(request_uri, 1, q - 1) or request_uri
end

-- no_exemption reports whether exemptions must not apply to raw_path (see
-- above): an ambiguous path, or one with "//".
function _M.no_exemption(raw_path)
  return find(raw_path, "//", 1, true) ~= nil or _M.ambiguous(raw_path)
end

local function hex_char(h) return char(tonumber(h, 16)) end
local function hex_char_keep_slash(h)
  if lower(h) == "2f" then return "%2F" end
  return char(tonumber(h, 16))
end
local function decode_all(s) return (gsub(s, "%%(%x%x)", hex_char)) end
local function decode_keep_slash(s) return (gsub(s, "%%(%x%x)", hex_char_keep_slash)) end
local function merge_slashes(s) return (gsub(s, "//+", "/")) end
-- strip_parameters removes ";" path parameters: from each ";" to the end
-- of its segment.
local function strip_parameters(s) return (gsub(s, ";[^/]*", "")) end

local AMBIGUOUS = { ambiguous = true, no_exemption = true }

-- classify returns how raw_path compares to path scopes given a site's
-- encoded path exemptions (a list of { prefix, encoded_slash, semicolon },
-- or nil): { ambiguous, no_exemption, views, key }. views (nil unless an
-- exemption applies) are the readings besides $uri; key the cache key's
-- path when it keeps "%2F" (nil: $uri).
function _M.classify(raw_path, exemptions)
  if not _M.ambiguous(raw_path) then
    return { ambiguous = false, no_exemption = find(raw_path, "//", 1, true) ~= nil }
  end
  local slash, semicolon = false, false
  for _, e in ipairs(type(exemptions) == "table" and exemptions or {}) do
    local p = e.prefix
    if type(p) == "string" and p ~= "" and sub(raw_path, 1, #p) == p then
      slash = slash or e.encoded_slash == true
      semicolon = semicolon or e.semicolon == true
    end
  end
  if not slash and not semicolon then return AMBIGUOUS end
  local plain = raw_path
  if slash then plain = gsub(plain, "%%2[fF]", "/") end
  if semicolon then plain = strip_parameters(plain) end
  if _M.ambiguous(plain) then return AMBIGUOUS end
  local decoded = merge_slashes(decode_all(raw_path))
  local kept = slash and find(raw_path, "%%2[fF]") and merge_slashes(decode_keep_slash(raw_path)) or nil
  local views, seen = {}, {}
  local function add(v)
    if not seen[v] then
      seen[v] = true
      views[#views + 1] = v
    end
  end
  add(decoded)
  if kept then add(kept) end
  if semicolon and find(raw_path, ";", 1, true) then
    add(strip_parameters(decoded))
    if kept then add(strip_parameters(kept)) end
  end
  return {
    ambiguous = false,
    no_exemption = find(raw_path, "//", 1, true) ~= nil or find(plain, "//", 1, true) ~= nil,
    views = views,
    key = kept,
  }
end

-- any_view reports whether test(path) holds for path ($uri) or any of
-- views (a scope that adds a check).
function _M.any_view(path, views, test)
  if test(path) then return true end
  if views then
    for i = 1, #views do
      if test(views[i]) then return true end
    end
  end
  return false
end

-- all_views reports whether test(path) holds for path ($uri) and every one
-- of views (an exemption or a grant).
function _M.all_views(path, views, test)
  if not test(path) then return false end
  if views then
    for i = 1, #views do
      if not test(views[i]) then return false end
    end
  end
  return true
end

local function request_uri() return ngx.var.request_uri end

-- request_class is classify() for the current request and site, computed
-- once (not ambiguous outside a request, as in timers).
function _M.request_class(site)
  local ctx = ngx.ctx
  local c = ctx.edgeweir_path_class
  if c == nil then
    local ok, uri = pcall(request_uri)
    if ok and uri ~= nil then
      c = _M.classify(_M.raw_path(uri), site and site.encoded_path_exemptions)
    else
      c = { ambiguous = false, no_exemption = false }
    end
    ctx.edgeweir_path_class = c
  end
  return c
end

-- request_ambiguous is the current request's class.ambiguous.
function _M.request_ambiguous(site)
  return _M.request_class(site).ambiguous
end

-- request_no_exemption is the current request's class.no_exemption.
function _M.request_no_exemption(site)
  return _M.request_class(site).no_exemption
end

-- request_views is the current request's class.views (nil: $uri alone).
function _M.request_views(site)
  return _M.request_class(site).views
end

-- cut_prefix removes a signed URL's two leading segments (prefix, as cut
-- from $uri) from the current request's views and key (edgeweir.auth).
function _M.cut_prefix(site, prefix)
  local c = _M.request_class(site)
  local function cut(v)
    if sub(v, 1, #prefix + 1) == prefix .. "/" then return sub(v, #prefix + 1) end
    return v
  end
  if c.views then
    local views = {}
    for i = 1, #c.views do views[i] = cut(c.views[i]) end
    c = { ambiguous = c.ambiguous, no_exemption = c.no_exemption, views = views, key = c.key and cut(c.key) }
    ngx.ctx.edgeweir_path_class = c
  end
end

return _M
