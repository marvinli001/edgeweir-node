-- edgeweir.markdown: Markdown for Agents (edge layer).
--
-- A site's markdown (Site.markdown) converts its HTML responses to
-- Markdown for GET and HEAD requests whose Accept names text/markdown with
-- q > 0 (text/* and */* do not count). Only paths qualify whose last
-- segment has no extension or an HTML one (EXTENSIONS), that start with one
-- of the site's include prefixes (none: every path) and with none of its
-- exclude prefixes.
--
-- A Markdown request goes to the agent's Markdown converter (upstream
-- edgeweir_markdown) with X-Edgeweir-Markdown naming the origin layer it
-- would have used, cached or not; the converter fetches the whole document
-- there and converts an HTML answer, or passes what it got. When the
-- request is cached, "|m=md" joins its cache key (edgeweir.cachekey; the
-- HTML's key is unchanged): the two variants are stored apart, and purges
-- (URL, prefix, host, tag markers, the site's cache generation) reach both,
-- as they work on the path. HTML and Markdown responses of eligible
-- requests get Vary: Accept towards clients, whatever their variant; the
-- cached responses carry none, so the edge's cache does not split them by
-- every client's Accept.
local _M = {}

local lower, match, gmatch, find, sub = string.lower, string.match, string.gmatch, string.find, string.sub
local concat, tonumber, type = table.concat, tonumber, type

-- The edge layer's upstream of the Markdown converter (nginx.conf).
_M.UPSTREAM = "edgeweir_markdown"

-- The cache key's class of the Markdown variant.
_M.CLASS = "md"

-- Extensions (lowercase, without the dot) of paths that may name HTML.
_M.EXTENSIONS = {
  html = true, htm = true, xhtml = true, shtml = true, php = true, asp = true, aspx = true,
  jsp = true, jspx = true, cfm = true, cgi = true, pl = true, ["do"] = true, action = true,
}

-- Media types whose responses vary by Accept on eligible requests.
local VARY_TYPES = { ["text/html"] = true, ["application/xhtml+xml"] = true, ["text/markdown"] = true }

-- qvalue parses the parameters of a media range: the weight of "q=..."
-- (RFC 9110, section 12.4.2), 1 without one, nil when malformed.
local function qvalue(params)
  local q = 1
  for param in gmatch(params, "[^;]+") do
    local name, value = match(param, "^%s*([%w!#$%%&'*+.^_`|~-]+)%s*=%s*(.-)%s*$")
    if name and lower(name) == "q" then
      if value == "0" or value == "1" or match(value, "^0%.%d?%d?%d?$") or match(value, "^1%.0?0?0?$") then
        q = tonumber(value) or 0
      else
        return nil
      end
    end
  end
  return q
end

-- accept reports whether an Accept value (a string, a list of field lines
-- or nil) names text/markdown with q > 0 (a type named twice keeps its
-- lowest weight).
function _M.accept(value)
  if type(value) == "table" then
    value = concat(value, ",")
  end
  if type(value) ~= "string" then
    return false
  end
  local q
  for element in gmatch(value, "[^,]+") do
    local media, params = match(element, "^%s*([%w!#$%%&'*+.^_`|~-]+/[%w!#$%%&'*+.^_`|~-]+)%s*(.-)%s*$")
    if media and lower(media) == "text/markdown" then
      local weight = qvalue(params)
      if weight and (q == nil or weight < q) then
        q = weight
      end
    end
  end
  return q ~= nil and q > 0
end

local function has_prefix(list, path)
  for i = 1, #list do
    local p = list[i]
    if sub(path, 1, #p) == p then
      return true
    end
  end
  return false
end

-- path_eligible reports whether a path (nginx's normalized $uri) may be
-- converted for a site's markdown md.
function _M.path_eligible(md, path)
  path = path or ""
  local last = match(path, "[^/]*$")
  if find(last, ".", 1, true) then
    local ext = lower(match(last, "%.([^.]*)$"))
    if not _M.EXTENSIONS[ext] then
      return false
    end
  end
  local include = md.include or {}
  if #include > 0 and not has_prefix(include, path) then
    return false
  end
  return not has_prefix(md.exclude or {}, path)
end

-- route sets up a GET or HEAD request of a site that converts (router.
-- route, before the cache decision): marks an eligible request for Vary
-- and, when it asks for Markdown, points it at the converter (whole
-- documents: no ranges or slices) and returns the cache key's class.
-- headers are the request headers (ngx.req.get_headers(0)); path is the
-- normalized path.
function _M.route(site, var, ctx, headers, path)
  local md = site.markdown
  if type(md) ~= "table" or not _M.path_eligible(md, path) then
    return nil
  end
  ctx.edgeweir_markdown_vary = true
  if not _M.accept(headers and headers["accept"]) then
    return nil
  end
  var.edgeweir_range_mode = ""
  var.edgeweir_markdown = "up=" .. var.edgeweir_origin_layer
  var.edgeweir_origin_layer = _M.UPSTREAM
  return _M.CLASS
end

-- media_type returns the lowercase media type of a Content-Type value.
local function media_type(value)
  if type(value) == "table" then
    value = value[1]
  end
  if type(value) ~= "string" then
    return nil
  end
  return lower(match(value, "^%s*([^;%s]+)") or "")
end

-- has_token reports whether a Vary value (string or list) names token
-- (lowercase) or "*".
local function has_token(vary, token)
  if type(vary) == "table" then
    vary = concat(vary, ",")
  end
  if type(vary) ~= "string" then
    return false
  end
  for element in gmatch(vary, "[^,]+") do
    local name = lower(match(element, "^%s*(.-)%s*$"))
    if name == token or name == "*" then
      return true
    end
  end
  return false
end

-- vary adds Accept to the Vary of an HTML or Markdown response (h:
-- ngx.header) of an eligible request.
function _M.vary(h)
  if not VARY_TYPES[media_type(h["Content-Type"]) or ""] then
    return
  end
  local vary = h["Vary"]
  if has_token(vary, "accept") then
    return
  end
  if vary == nil or vary == "" then
    h["Vary"] = "Accept"
  elseif type(vary) == "table" then
    vary[#vary + 1] = "Accept"
    h["Vary"] = vary
  else
    h["Vary"] = vary .. ", Accept"
  end
end

-- converted returns 1 for a complete 200 answer to a GET that the
-- converter marked (X-Edgeweir-Markdown-Converted, cache hits included),
-- else 0 (MinuteStats.markdown_responses).
function _M.converted(value, status, method)
  if value == nil or value == "" or status ~= 200 or method ~= "GET" then
    return 0
  end
  return 1
end

return _M
