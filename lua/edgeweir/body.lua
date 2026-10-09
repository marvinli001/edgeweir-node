-- edgeweir.body: the request body of the rules (proto v0.29.0, feature
-- rules-body-v1, ADR-0040).
--
-- The fields http.request.body.size, .raw, .truncated and .filenames and
-- the functions form_value and json_value. The parsers are a byte-for-byte
-- port of the console's packages/rule-engine/src/body.ts (shared vectors in
-- test/lua/body_vectors.json); every string is a byte string.
--
-- Reading (load): only for sites whose rules (the site's or the platform's)
-- read the body (site._body, edgeweir.store), and only when an expression
-- evaluates such a field or function (edgeweir.policy makes the request
-- values lazy). size is Content-Length (-1 without) and never reads. A body
-- is read when it has a Content-Length of at most the site's
-- rules_body_limit (0: 65536), with ngx.req.read_body() (in memory or from
-- nginx's temporary file); an HTTP/1.x request without Content-Length and
-- Transfer-Encoding has none (empty, not truncated). Every other body is
-- truncated and never read: over the limit, chunked, HTTP/2 and HTTP/3
-- without Content-Length (GET included), WebSocket upgrades and the gRPC
-- requests of sites that proxy gRPC. A truncated body reads as "".
--
-- Each request parses its body once per kind and Content-Type (the parse
-- cache travels in the request values' metatable, shared by their copies).
-- form_value and json_value are not bounded by edgeweir.expressions'
-- MAX_VALUE, like fields.
local _M = {}

local sub, find, byte, char, lower, gsub, gmatch, match = string.sub, string.find, string.byte, string.char,
  string.lower, string.gsub, string.gmatch, string.match
local concat = table.concat
local tonumber, type = tonumber, type

_M.DEFAULT_LIMIT = 65536
_M.MAX_PARTS = 1000
_M.MAX_JSON_DEPTH = 128
_M.MAX_FORM_NAME = 256
_M.MAX_JSON_PATH = 256
_M.MAX_JSON_SEGMENTS = 32

_M.SIZE = "http.request.body.size"
_M.RAW = "http.request.body.raw"
_M.TRUNCATED = "http.request.body.truncated"
_M.FILENAMES = "http.request.body.filenames"
_M.CONTENT_TYPE = "http.request.headers.content-type"
-- FIELDS are the body fields; FUNCTIONS the functions over the body.
_M.FIELDS = { [_M.SIZE] = true, [_M.RAW] = true, [_M.TRUNCATED] = true, [_M.FILENAMES] = true }
_M.FUNCTIONS = { form_value = true, json_value = true }

local function control(s)
  return find(s, "[%z\1-\31\127]") ~= nil
end

-- valid_form_name: 1-256 bytes without control characters.
function _M.valid_form_name(name)
  return type(name) == "string" and #name >= 1 and #name <= _M.MAX_FORM_NAME and not control(name)
end

-- split returns the parts of s between the separators sep, empty ones
-- included (JavaScript's split).
local function split(s, sep)
  local out, n, pos = {}, 0, 1
  while true do
    local at = find(s, sep, pos, true)
    n = n + 1
    if not at then
      out[n] = sub(s, pos)
      return out
    end
    out[n] = sub(s, pos, at - 1)
    pos = at + #sep
  end
end

-- valid_json_path: 1-256 bytes without control characters, 1-32 non-empty
-- segments separated by ".".
function _M.valid_json_path(path)
  if type(path) ~= "string" or #path < 1 or #path > _M.MAX_JSON_PATH or control(path) then return false end
  local segments = split(path, ".")
  if #segments > _M.MAX_JSON_SEGMENTS then return false end
  for i = 1, #segments do
    if segments[i] == "" then return false end
  end
  return true
end

-- media_type is the lowercase media type of a Content-Type value, its
-- parameters removed ("" when absent).
function _M.media_type(content_type)
  return lower(match(content_type or "", "^[ \t]*([^; \t]+)") or "")
end

local function decode_escape(c, hex)
  if c == "+" then return " " .. hex end
  if #hex == 2 then return char(tonumber(hex, 16)) end
  return nil
end

-- url_decode decodes once: "%XX" (either case) to a byte, "+" to a space;
-- an incomplete "%" stays.
function _M.url_decode(s)
  return (gsub(s, "([%%+])(%x?%x?)", decode_escape))
end

local function is_space(c)
  return c == 32 or c == 9
end

local function rtrim(s)
  return (gsub(s, "[ \t]+$", ""))
end

local function trim(s)
  return (gsub(gsub(s, "^[ \t]+", ""), "[ \t]+$", ""))
end

-- header_params returns the parameters of a header value from byte start
-- as {name, value} pairs: separated by ";", names trimmed and lowercased,
-- values a token (to ";", trailing blanks removed) or a quoted string (a
-- backslash takes the next byte; an unterminated one runs to the end; what
-- follows it up to ";" is ignored). Pairs without "=" are skipped.
function _M.header_params(header, start)
  local out = {}
  local i, n = start, #header
  while i <= n do
    while i <= n do
      local c = byte(header, i)
      if is_space(c) or c == 59 then i = i + 1 else break end
    end
    if i > n then break end
    local name_start = i
    while i <= n do
      local c = byte(header, i)
      if c == 61 or c == 59 then break end
      i = i + 1
    end
    local name = lower(rtrim(sub(header, name_start, i - 1)))
    if byte(header, i) == 61 then
      i = i + 1
      while i <= n and is_space(byte(header, i)) do i = i + 1 end
      local value
      if byte(header, i) == 34 then
        i = i + 1
        local parts, k = {}, 0
        while i <= n do
          local c = byte(header, i)
          if c == 92 and i + 1 <= n then
            k = k + 1; parts[k] = sub(header, i + 1, i + 1); i = i + 2
          elseif c == 34 then
            i = i + 1
            break
          else
            k = k + 1; parts[k] = sub(header, i, i); i = i + 1
          end
        end
        value = concat(parts)
        while i <= n and byte(header, i) ~= 59 do i = i + 1 end
      else
        local value_start = i
        while i <= n and byte(header, i) ~= 59 do i = i + 1 end
        value = rtrim(sub(header, value_start, i - 1))
      end
      out[#out + 1] = { name, value }
    end
  end
  return out
end

-- multipart_boundary returns the boundary of a multipart Content-Type
-- (1-70 bytes), or nil.
function _M.multipart_boundary(content_type)
  local semicolon = find(content_type, ";", 1, true)
  if not semicolon then return nil end
  for _, p in ipairs(_M.header_params(content_type, semicolon + 1)) do
    if p[1] == "boundary" then
      local b = p[2]
      if #b >= 1 and #b <= 70 then return b end
      return nil
    end
  end
  return nil
end

local function part(headers, content, out)
  local disposition
  for _, line in ipairs(split(headers, "\r\n")) do
    local colon = find(line, ":", 1, true)
    if colon and lower(trim(sub(line, 1, colon - 1))) == "content-disposition" then
      disposition = sub(line, colon + 1)
      break
    end
  end
  if not disposition then return end
  local semicolon = find(disposition, ";", 1, true)
  local kind = semicolon and sub(disposition, 1, semicolon - 1) or disposition
  if lower(trim(kind)) ~= "form-data" then return end
  local params = semicolon and _M.header_params(disposition, semicolon + 1) or {}
  for _, p in ipairs(params) do
    if p[1] == "filename" then
      if p[2] ~= "" then out.filenames[#out.filenames + 1] = p[2] end
      return
    end
  end
  for _, p in ipairs(params) do
    if p[1] == "name" then
      if out.fields[p[2]] == nil then out.fields[p[2]] = content end
      return
    end
  end
end

-- parse_multipart parses a multipart/form-data body into {fields = {name
-- = first value}, filenames = {...}}: the first delimiter "--boundary" at
-- the start of the body or after "\r\n"; after a delimiter "--" (the end) or
-- optional blanks and "\r\n"; a part's headers end at the first "\r\n\r\n"
-- (none: "\r\n" right away), its body at the next "\r\n--boundary". Stops at
-- the first malformed part and after 1000 parts, keeping what came before.
function _M.parse_multipart(body, content_type)
  local out = { fields = {}, filenames = {} }
  local boundary = _M.multipart_boundary(content_type)
  if not boundary then return out end
  local dash = "--" .. boundary
  local delimiter = "\r\n" .. dash
  local pos
  if sub(body, 1, #dash) == dash then
    pos = 1
  else
    local first = find(body, delimiter, 1, true)
    if not first then return out end
    pos = first + 2
  end
  for _ = 1, _M.MAX_PARTS do
    pos = pos + #dash
    if sub(body, pos, pos + 1) == "--" then break end
    while is_space(byte(body, pos)) do pos = pos + 1 end
    if sub(body, pos, pos + 1) ~= "\r\n" then break end
    pos = pos + 2
    local headers, content_start
    if sub(body, pos, pos + 1) == "\r\n" then
      headers, content_start = "", pos + 2
    else
      local e = find(body, "\r\n\r\n", pos, true)
      if not e then break end
      headers, content_start = sub(body, pos, e - 1), e + 4
    end
    local nxt = find(body, delimiter, content_start, true)
    if not nxt then break end
    part(headers, sub(body, content_start, nxt - 1), out)
    pos = nxt + 2
  end
  return out
end

-- parse_form returns the first value of every field of an
-- application/x-www-form-urlencoded body (name and value url-decoded once;
-- an element without "=" has the value "").
function _M.parse_form(body)
  local fields = {}
  for element in gmatch(body, "[^&]+") do
    local eq = find(element, "=", 1, true)
    local name = _M.url_decode(eq and sub(element, 1, eq - 1) or element)
    if fields[name] == nil then
      fields[name] = eq and _M.url_decode(sub(element, eq + 1)) or ""
    end
  end
  return fields
end

-- ---------------------------------------------------------------------
-- JSON

-- is_json_media_type: application/json or a type ending in "+json".
function _M.is_json_media_type(media)
  return media == "application/json" or (#media >= 5 and sub(media, -5) == "+json")
end

-- utf8 encodes a code point (U+FFFD for surrogates).
local function utf8(c)
  if c >= 0xD800 and c <= 0xDFFF then c = 0xFFFD end
  if c < 0x80 then return char(c) end
  if c < 0x800 then return char(0xC0 + math.floor(c / 64), 0x80 + c % 64) end
  if c < 0x10000 then
    return char(0xE0 + math.floor(c / 4096), 0x80 + math.floor(c / 64) % 64, 0x80 + c % 64)
  end
  return char(0xF0 + math.floor(c / 262144), 0x80 + math.floor(c / 4096) % 64, 0x80 + math.floor(c / 64) % 64, 0x80 + c % 64)
end

local SIMPLE = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
local TRUE, FALSE, NULL = { t = "b", v = true }, { t = "b", v = false }, { t = "z" }

local function digit(c)
  return c ~= nil and c >= 48 and c <= 57
end

-- parse_json parses a JSON text (RFC 8259) of bytes: whitespace is space,
-- tab, "\n" and "\r"; no byte order mark; at most 128 levels of nesting;
-- strings may hold any byte but control characters (\u escapes become
-- UTF-8, surrogate pairs combined, lone surrogates U+FFFD); a key given
-- twice keeps its last value. Values: {t = "s"|"n", v = bytes},
-- {t = "b", v = boolean}, {t = "z"}, {t = "o", m = {}}, {t = "a", items =
-- {}}. Returns nil for anything invalid.
function _M.parse_json(text)
  local i, n = 1, #text
  local function ws()
    while i <= n do
      local c = byte(text, i)
      if c == 32 or c == 9 or c == 10 or c == 13 then i = i + 1 else break end
    end
  end
  local function str()
    i = i + 1 -- the opening quote
    local buf, k, start = {}, 0, i
    while i <= n do
      local c = byte(text, i)
      if c < 0x20 then return nil end
      if c == 34 then
        k = k + 1; buf[k] = sub(text, start, i - 1)
        i = i + 1
        return concat(buf)
      end
      if c ~= 92 then
        i = i + 1
      else
        k = k + 1; buf[k] = sub(text, start, i - 1)
        local e = sub(text, i + 1, i + 1)
        if e == "" then return nil end
        local simple = SIMPLE[e]
        if simple then
          k = k + 1; buf[k] = simple
          i = i + 2
        elseif e == "u" then
          local hex = sub(text, i + 2, i + 5)
          if not match(hex, "^%x%x%x%x$") then return nil end
          local high = tonumber(hex, 16)
          i = i + 6
          local pair = false
          if high >= 0xD800 and high <= 0xDBFF and sub(text, i, i + 1) == "\\u" then
            local nxt = sub(text, i + 2, i + 5)
            local low = match(nxt, "^%x%x%x%x$") and tonumber(nxt, 16) or -1
            if low >= 0xDC00 and low <= 0xDFFF then
              k = k + 1; buf[k] = utf8(0x10000 + (high - 0xD800) * 1024 + (low - 0xDC00))
              i = i + 6
              pair = true
            end
          end
          if not pair then
            k = k + 1; buf[k] = utf8(high)
          end
        else
          return nil
        end
        start = i
      end
    end
    return nil
  end
  local function number()
    local s = i
    if byte(text, i) == 45 then i = i + 1 end
    local c = byte(text, i)
    if c == 48 then
      i = i + 1
    elseif digit(c) then
      repeat i = i + 1 until not digit(byte(text, i))
    else
      return nil
    end
    if byte(text, i) == 46 and digit(byte(text, i + 1)) then
      i = i + 2
      while digit(byte(text, i)) do i = i + 1 end
    end
    local e = byte(text, i)
    if e == 101 or e == 69 then
      local j = i + 1
      local sign = byte(text, j)
      if sign == 43 or sign == 45 then j = j + 1 end
      if digit(byte(text, j)) then
        repeat j = j + 1 until not digit(byte(text, j))
        i = j
      end
    end
    return sub(text, s, i - 1)
  end
  local value
  value = function(depth)
    ws()
    local c = byte(text, i)
    if c == 123 or c == 91 then
      if depth >= _M.MAX_JSON_DEPTH then return nil end
      i = i + 1
      ws()
      if c == 123 then
        local m = {}
        if byte(text, i) == 125 then
          i = i + 1
          return { t = "o", m = m }
        end
        while true do
          ws()
          if byte(text, i) ~= 34 then return nil end
          local key = str()
          if key == nil then return nil end
          ws()
          if byte(text, i) ~= 58 then return nil end
          i = i + 1
          local v = value(depth + 1)
          if v == nil then return nil end
          m[key] = v
          ws()
          local d = byte(text, i)
          if d == 44 then
            i = i + 1
          elseif d == 125 then
            i = i + 1
            return { t = "o", m = m }
          else
            return nil
          end
        end
      end
      local items = {}
      if byte(text, i) == 93 then
        i = i + 1
        return { t = "a", items = items }
      end
      while true do
        local v = value(depth + 1)
        if v == nil then return nil end
        items[#items + 1] = v
        ws()
        local d = byte(text, i)
        if d == 44 then
          i = i + 1
        elseif d == 93 then
          i = i + 1
          return { t = "a", items = items }
        else
          return nil
        end
      end
    end
    if c == 34 then
      local s = str()
      if s == nil then return nil end
      return { t = "s", v = s }
    end
    if c == 45 or digit(c) then
      local num = number()
      if num == nil then return nil end
      return { t = "n", v = num }
    end
    if sub(text, i, i + 3) == "true" then
      i = i + 4
      return TRUE
    end
    if sub(text, i, i + 4) == "false" then
      i = i + 5
      return FALSE
    end
    if sub(text, i, i + 3) == "null" then
      i = i + 4
      return NULL
    end
    return nil
  end
  local result = value(0)
  if result == nil then return nil end
  ws()
  if i ~= n + 1 then return nil end
  return result
end

-- json_path_value: the value of a parsed document at path: segments
-- select object keys (bytes) and array indexes (a canonical non-negative
-- integer); strings come out as their bytes, numbers as their text,
-- booleans as "true" or "false"; null, objects, arrays and missing values
-- as "".
function _M.json_path_value(doc, path)
  local v = doc
  for _, segment in ipairs(split(path, ".")) do
    if v and v.t == "o" then
      v = v.m[segment]
    elseif v and v.t == "a" and (segment == "0" or match(segment, "^[1-9]%d*$")) then
      v = v.items[tonumber(segment) + 1]
    else
      return ""
    end
  end
  if v and (v.t == "s" or v.t == "n") then return v.v end
  if v and v.t == "b" then return v.v and "true" or "false" end
  return ""
end

-- ---------------------------------------------------------------------
-- The functions, over byte strings, with an optional parse cache.

-- parsed returns the parse of body by kind ("form", "multipart" or "json")
-- for content_type, from cache when given (one per request).
local function parsed(cache, kind, body, content_type)
  local key = kind .. "\0" .. content_type
  local hit = cache and cache[key]
  if hit and hit.body == body then return hit.value end
  local value
  if kind == "form" then
    value = _M.parse_form(body)
  elseif kind == "multipart" then
    value = _M.parse_multipart(body, content_type)
  else
    value = _M.parse_json(body) or false
  end
  if cache then cache[key] = { body = body, value = value } end
  return value
end

-- form_value: the first value of the field name of an
-- application/x-www-form-urlencoded or multipart/form-data body (fields,
-- not files, as they are); "" for other types and absent fields.
function _M.form_value(body, content_type, name, cache)
  local media = _M.media_type(content_type)
  if media == "application/x-www-form-urlencoded" then
    return parsed(cache, "form", body, content_type)[name] or ""
  end
  if media == "multipart/form-data" then
    return parsed(cache, "multipart", body, content_type).fields[name] or ""
  end
  return ""
end

-- filenames is http.request.body.filenames: the non-empty file names of a
-- multipart body joined by "\n".
function _M.filenames(body, content_type, cache)
  if _M.media_type(content_type) ~= "multipart/form-data" then return "" end
  return concat(parsed(cache, "multipart", body, content_type).filenames, "\n")
end

-- json_value: the value at path of a JSON body.
function _M.json_value(body, content_type, path, cache)
  if not _M.is_json_media_type(_M.media_type(content_type)) then return "" end
  return _M.json_path_value(parsed(cache, "json", body, content_type) or nil, path)
end

-- cache_of returns the parse cache of request values (nil for a plain
-- table: the shared vectors and unit tests).
local function cache_of(req)
  local mt = getmetatable(req)
  return mt and mt.edgeweir_body_cache
end

-- of returns the body and Content-Type the functions see in request
-- values: http.request.body.raw (read now when the values are lazy) and
-- the Content-Type request header, "" when absent.
local function of(req)
  local body, content_type = req[_M.RAW], req[_M.CONTENT_TYPE]
  return type(body) == "string" and body or "", type(content_type) == "string" and content_type or ""
end

function _M.form_value_of(req, name)
  local body, content_type = of(req)
  return _M.form_value(body, content_type, name, cache_of(req))
end

function _M.json_value_of(req, path)
  local body, content_type = of(req)
  return _M.json_value(body, content_type, path, cache_of(req))
end

function _M.filenames_of(req)
  local body, content_type = of(req)
  return _M.filenames(body, content_type, cache_of(req))
end

-- ---------------------------------------------------------------------
-- Reading

-- decide says what to do with a request's body: "read", "empty" (no body)
-- or "truncated" (not read). limit is the site's rules_body_limit (0:
-- DEFAULT_LIMIT), content_length and transfer_encoding the request
-- headers (nil when absent), version ngx.req.http_version(), skip true for
-- WebSocket upgrades and gRPC requests.
function _M.decide(limit, content_length, transfer_encoding, version, skip)
  limit = tonumber(limit) or 0
  if limit <= 0 then limit = _M.DEFAULT_LIMIT end
  if skip then return "truncated" end
  if transfer_encoding ~= nil then return "truncated" end
  if content_length ~= nil then
    local n = tonumber(content_length)
    if n and n >= 0 and n <= limit then return "read" end
    return "truncated"
  end
  if version ~= nil and version < 2 then return "empty" end
  return "truncated"
end

-- read_body reads the request body (in memory, or nginx's temporary
-- file); nil when it cannot be read.
function _M.read_body()
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if data then return data end
  local file = ngx.req.get_body_file()
  if not file then return "" end
  local f = io.open(file, "rb")
  if not f then return nil end
  local raw = f:read("*a")
  f:close()
  return raw
end

-- size is http.request.body.size: Content-Length, -1 without.
function _M.size()
  local n = tonumber(ngx.var.http_content_length)
  if not n or n < 0 then return -1 end
  return n
end

-- load returns the request's body and whether it was truncated, reading
-- it the first time (state: per request, see edgeweir.policy).
function _M.load(state)
  if state.raw ~= nil then return state.raw, state.truncated end
  local var = ngx.var
  local site = state.site
  local upgrade = var.http_upgrade
  local skip = (upgrade ~= nil and lower(upgrade) == "websocket")
    or (site.grpc == true and require("edgeweir.router").is_grpc(var.http_content_type))
  local decision = _M.decide(site.rules_body_limit, var.http_content_length, var.http_transfer_encoding,
    ngx.req.http_version(), skip)
  local raw, truncated = "", decision == "truncated"
  if decision == "read" then
    local ok, data = pcall(_M.read_body)
    if ok and type(data) == "string" then
      raw = data
    else
      truncated = true
    end
  end
  state.raw, state.truncated = raw, truncated
  state.reads = (state.reads or 0) + (decision == "read" and 1 or 0)
  return raw, truncated
end

return _M
