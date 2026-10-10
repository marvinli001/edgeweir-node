-- edgeweir.imageconv: WebP / AVIF variants of cached images (edge layer,
-- ADR-0043).
--
-- A site's image_convert (Site.image_convert) offers WebP and / or AVIF for
-- its JPEG and PNG responses. For a request that is cached (a cache rule
-- applies) the edge layer picks a class from Accept: avif, webp or the
-- original (nil). Only explicit image/avif and image/webp with q > 0
-- count (image/* and */* do not), avif first; requests whose Accept names
-- text/html with q > 0 (browser navigations) always get the original, so
-- HTML is never cached once per browser. A path whose last segment has an
-- extension other than the source types' gets the original too.
--
-- The class goes into the cache key ("|i=avif" / "|i=webp", edgeweir.
-- cachekey; the original's key is unchanged) and a variant request goes
-- to the agent's image converter (upstream edgeweir_image) with
-- X-Edgeweir-Image naming the class, the site's limits and the origin
-- layer it would have used; the converter fetches the original there and
-- converts it, or answers with the original when it cannot. Responses of
-- eligible requests that are images get Vary: Accept, whatever their
-- class.
local _M = {}

local lower, match, gmatch, find, format = string.lower, string.match, string.gmatch, string.find, string.format
local concat, tonumber, type = table.concat, tonumber, type

-- The edge layer's upstream of the image converter (nginx.conf).
_M.UPSTREAM = "edgeweir_image"

-- Extensions of the source types (lowercase, without the dot).
local EXTENSIONS = {
  jpeg = { jpg = true, jpeg = true, jpe = true, jfif = true },
  png = { png = true },
}

-- Media types whose responses vary by Accept on eligible requests.
local IMAGE_TYPES = { ["image/jpeg"] = true, ["image/png"] = true, ["image/webp"] = true, ["image/avif"] = true }

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

-- accept returns the q-values Accept gives image/avif, image/webp and
-- text/html (0 when not named; a type named twice keeps its lowest).
-- value is a string, a list of field lines, or nil.
function _M.accept(value)
  local q = { ["image/avif"] = false, ["image/webp"] = false, ["text/html"] = false }
  if type(value) == "table" then
    value = concat(value, ",")
  end
  if type(value) ~= "string" then
    return 0, 0, 0
  end
  for element in gmatch(value, "[^,]+") do
    local media, params = match(element, "^%s*([%w!#$%%&'*+.^_`|~-]+/[%w!#$%%&'*+.^_`|~-]+)%s*(.-)%s*$")
    if media then
      media = lower(media)
      if q[media] ~= nil then
        local weight = qvalue(params)
        if weight and (q[media] == false or weight < q[media]) then
          q[media] = weight
        end
      end
    end
  end
  return q["image/avif"] or 0, q["image/webp"] or 0, q["text/html"] or 0
end

-- class returns "avif", "webp" or nil (the original) for a request with
-- Accept value accept to a site converting with conv.
function _M.class(conv, accept)
  local avif, webp, html = _M.accept(accept)
  if html > 0 then
    return nil
  end
  if conv.avif and avif > 0 then
    return "avif"
  end
  if conv.webp and webp > 0 then
    return "webp"
  end
  return nil
end

-- path_eligible reports whether a path (nginx's normalized $uri) may name
-- an image of conv's source types: its last segment has no extension, or
-- the extension of a source type (any case).
function _M.path_eligible(conv, path)
  local last = match(path or "", "[^/]*$")
  local dot = find(last, ".", 1, true)
  if not dot then
    return true
  end
  local ext = lower(match(last, "%.([^.]*)$"))
  return (conv.jpeg and EXTENSIONS.jpeg[ext]) or (conv.png and EXTENSIONS.png[ext]) or false
end

-- header returns the X-Edgeweir-Image value of a variant request: the
-- class, its quality, the size and pixel limits, the source types and the
-- origin layer's upstream (the agent's imageconv.ParseHeader).
function _M.header(conv, class, layer)
  local quality = class == "avif" and conv.avif_quality or conv.webp_quality
  local src = (conv.jpeg and conv.png) and "jpeg,png" or (conv.jpeg and "jpeg" or "png")
  return format("%s;q=%d;min=%d;max=%d;px=%d;src=%s;up=%s", class, tonumber(quality) or 0,
    tonumber(conv.min_size) or 0, tonumber(conv.max_size) or 0, tonumber(conv.max_pixels) or 0, src, layer)
end

-- route sets up a cacheable request of a site that converts (router.
-- access, after the cache decision): marks it for Vary and, for a
-- variant, returns its class after pointing the request at the converter
-- (whole objects: no slices). headers are the request headers
-- (ngx.req.get_headers(0)); path is the normalized path.
function _M.route(site, var, ctx, headers, path)
  local conv = site.image_convert
  if type(conv) ~= "table" or not _M.path_eligible(conv, path) then
    return nil
  end
  ctx.edgeweir_image_vary = true
  local class = _M.class(conv, headers and headers["accept"])
  if not class then
    return nil
  end
  var.edgeweir_range_mode = ""
  var.edgeweir_image = _M.header(conv, class, var.edgeweir_origin_layer)
  var.edgeweir_origin_layer = _M.UPSTREAM
  return class
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

-- vary adds Accept to the Vary of an image response (h: ngx.header) of an
-- eligible request.
function _M.vary(h)
  if not IMAGE_TYPES[media_type(h["Content-Type"]) or ""] then
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

-- saved returns the bytes a response saved for the statistics: the
-- converter's X-Edgeweir-Image-Saved on a complete 200 answer to a GET
-- (cache hits included), else 0.
function _M.saved(value, status, method)
  if status ~= 200 or method ~= "GET" then
    return 0
  end
  local n = tonumber(value)
  if not n or n <= 0 or n ~= n or n == math.huge then
    return 0
  end
  return math.floor(n)
end

return _M
