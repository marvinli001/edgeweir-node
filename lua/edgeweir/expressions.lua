-- Bounded expression IR -> closures. Never evaluates user text as Lua code.
--
-- compile(e, lists) turns a condition into a function of the request
-- values (field name -> value) that returns a boolean; compile_value(e) a
-- value expression (redirect targets, rewrite paths, since proto v0.22.0
-- header values and set query parameters) into one that returns a string.
-- Since proto v0.13.0 (feature rules-v2) conditions and values may call
-- functions (call, field and const nodes); the pure helpers below
-- (url_decode, wildcard_replace, regex_replace, path_extension,
-- media_type, full_uri, and with rules-v3 cookies, args, base64_decode,
-- substring, to_string) are shared with the request and response fields.
-- rules-v3 also adds the wildcard and strict_wildcard comparisons and
-- header_value, the check of a computed header value. rules-body-v1 (proto
-- v0.29.0) adds form_value and json_value and derives
-- http.request.body.filenames from http.request.body.raw and the
-- Content-Type header when the request values do not hold it, as the
-- console's evaluator does (edgeweir.body).
local ip = require("edgeweir.ipaddr")
local bit = require("bit")
local _M = {}

local function address(value)
  local a = ip.parse(value)
  if a and #a == 16 then
    local mapped = a[11] == 255 and a[12] == 255
    for i = 1, 10 do if a[i] ~= 0 then mapped = false end end
    if mapped then return { a[13], a[14], a[15], a[16] } end
  end
  return a
end

-- Binary prefix trie: lookup is bounded by address bits, not list length.
function _M.ip_set(entries)
  local roots = { [4] = {}, [16] = {} }
  for _, entry in ipairs(entries or {}) do
    local p = assert(ip.parse_prefix(entry), "invalid IP prefix")
    local n = roots[#p.bytes]
    for b = 0, p.len - 1 do
      local v = bit.band(bit.rshift(p.bytes[math.floor(b / 8) + 1], 7 - b % 8), 1)
      n[v] = n[v] or {}; n = n[v]
    end
    n.hit = true
  end
  return function(value)
    local a = address(value)
    if not a then return false end
    local n = roots[#a]
    for b = 0, #a * 8 do
      if n.hit then return true end
      if b == #a * 8 then break end
      n = n[bit.band(bit.rshift(a[math.floor(b / 8) + 1], 7 - b % 8), 1)]
      if not n then return false end
    end
    return false
  end
end

-- PCRE2 source for a `matches` pattern. configir (validPattern) admits only the
-- subset that JavaScript, RE2 and PCRE2 without UTF read alike, where `$` is the
-- end of the value and `.` any byte but "\n": `$` becomes `\z` (PCRE2's `$` also
-- matches before a final "\n") and (*LF) keeps `.` independent of the newline
-- default PCRE2 was built with. Match work is bounded even for costly patterns.
function _M.pcre_pattern(pattern)
  local out, i, class = {}, 1, false
  while i <= #pattern do
    local c = pattern:sub(i, i)
    if c == "\\" then
      c = pattern:sub(i, i + 1); i = i + 1
    elseif class then
      class = c ~= "]"
    elseif c == "[" then
      class = true
    elseif c == "$" then
      c = "\\z"
    end
    out[#out + 1] = c
    i = i + 1
  end
  return "(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(*LF)" .. table.concat(out)
end

-- Functions (proto v0.13.0, feature rules-v2) over byte strings, exactly as
-- the console's reference evaluator (packages/rule-engine) computes them.
-- configir validated names, arities and argument types; every string a
-- function computes is at most MAX_VALUE bytes, longer ones raise an error
-- (the caller fails closed).
_M.MAX_VALUE = 8192

local lower, upper, sub, find, gsub, match, char, byte, format, gmatch = string.lower, string.upper, string.sub, string.find, string.gsub, string.match, string.char, string.byte, string.format, string.gmatch
local concat = table.concat
local resty_sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex

local function checked(s)
  if #s > _M.MAX_VALUE then error("expression value is too long") end
  return s
end

local function decode_escape(c, hex)
  if c == "+" then return " " .. hex end
  if #hex == 2 then return char(tonumber(hex, 16)) end
  return nil -- an incomplete escape stays as it is
end

-- url_decode decodes once: "%" and two hex digits (either case) become that
-- byte, "+" a space; everything else, an incomplete "%" included, is kept.
function _M.url_decode(s)
  return (gsub(s, "([%%+])(%x?%x?)", decode_escape))
end

-- path_extension is http.request.uri.path.extension: the lowercase text
-- after the last "." of the last segment of path, "" without one.
function _M.path_extension(path)
  local last = match(path, "([^/]*)$") or ""
  return lower(match(last, "%.([^.]*)$") or "")
end

-- media_type is http.response.content_type.media_type: the lowercase media
-- type of a Content-Type value without parameters, "" when absent.
function _M.media_type(content_type)
  return lower(match(content_type or "", "^[ \t]*([^; \t]+)") or "")
end

-- full_uri is http.request.full_uri: scheme://host followed by the request
-- URI as received.
function _M.full_uri(scheme, host, request_uri)
  return (scheme or "") .. "://" .. (host or "") .. (request_uri or "")
end

-- url_encode percent-encodes every byte but the RFC 3986 unreserved
-- characters (%XX, uppercase hex).
function _M.url_encode(s)
  return (gsub(s, "[^A-Za-z0-9%-._~]", function(c) return format("%%%02X", byte(c)) end))
end

local BASE64_URL = { ["-"] = "+", ["_"] = "/" }

-- base64_decode accepts the standard and the URL-safe alphabet (mixed
-- too), with or without padding, and ignores unused trailing bits. Other
-- characters, whitespace, misplaced or excess padding and a length that
-- leaves one character decode to "".
function _M.base64_decode(s)
  local text = gsub(s, "[-_]", BASE64_URL)
  local body = text
  if sub(body, -1) == "=" then body = sub(body, 1, -2) end
  if sub(body, -1) == "=" then body = sub(body, 1, -2) end
  if (body ~= text and #text % 4 ~= 0) or find(body, "[^A-Za-z0-9+/]") or #body % 4 == 1 or body == "" then
    return ""
  end
  return ngx.decode_base64(body) or ""
end

-- substring returns length bytes (all when nil) of s from byte start
-- (0-based; negative counts from the end, clamped to the first byte), ""
-- past the end.
function _M.substring(s, start, length)
  local n = #s
  if start < 0 then
    start = n + start
    if start < 0 then start = 0 end
  end
  if start >= n then return "" end
  local finish = n
  if length and start + length < n then finish = start + length end
  return sub(s, start + 1, finish)
end

-- to_string writes integers in decimal, booleans as true / false; strings
-- (addresses included) stay as they are.
function _M.to_string(v)
  local t = type(v)
  if t == "number" then return format("%d", v) end
  if t == "boolean" then return v and "true" or "false" end
  return v
end

local function trim(s)
  return (match(s, "^[ \t]*(.-)[ \t]*$"))
end

-- cookies adds to out the first value of every cookie named in names
-- (a set) of a Cookie header value: pairs separated by ";", spaces and
-- tabs around a pair, its name and its value ignored, pairs without "="
-- skipped; values as sent (not decoded).
function _M.cookies(header, names, out)
  for pair in gmatch(header, "[^;]+") do
    local eq = find(pair, "=", 1, true)
    if eq then
      local name = trim(sub(pair, 1, eq - 1))
      if names[name] and out[name] == nil then out[name] = trim(sub(pair, eq + 1)) end
    end
  end
  return out
end

-- args adds to out the first value of every query parameter named in
-- names (a set): parameters separated by "&", the name before the first
-- "=" (all of it without one, the value then ""), neither decoded.
function _M.args(query, names, out)
  for element in gmatch(query, "[^&]+") do
    local eq = find(element, "=", 1, true)
    local name = eq and sub(element, 1, eq - 1) or element
    if names[name] and out[name] == nil then out[name] = eq and sub(element, eq + 1) or "" end
  end
  return out
end

-- cookie and arg read one name (shared test vectors).
function _M.cookie(header, name)
  return _M.cookies(header, { [name] = true }, {})[name] or ""
end
function _M.arg(query, name)
  return _M.args(query, { [name] = true }, {})[name] or ""
end

_M.MAX_HEADER_VALUE = 4096

-- header_value runs the value expression fn of a header action: its value,
-- or nil when the node skips the action (the evaluation fails, or the value
-- has more than 4096 bytes or a control character).
function _M.header_value(fn, req)
  local ok, v = pcall(fn, req)
  if not ok or type(v) ~= "string" or #v > _M.MAX_HEADER_VALUE or find(v, "%c") then return nil end
  return v
end

-- expand replaces ${1} to ${8} with captures (missing ones are "").
local function expand(replacement, captures)
  return (gsub(replacement, "%${([1-8])}", function(n) return captures[tonumber(n)] or "" end))
end

-- sub_template turns a regex_replace replacement into an ngx.re.sub
-- template: ${1} to ${8} stay, every other "$" is a literal ("$$").
function _M.sub_template(replacement)
  local out, i = {}, 1
  while i <= #replacement do
    local c = sub(replacement, i, i)
    if c == "$" then
      local ref = match(replacement, "^%${[1-8]}", i)
      if ref then out[#out + 1] = ref; i = i + 4
      else out[#out + 1] = "$$"; i = i + 1 end
    else
      out[#out + 1] = c; i = i + 1
    end
  end
  return concat(out)
end

-- wildcard_segments splits a wildcard pattern at its unescaped "*" ("\*"
-- and "\\" are literals).
function _M.wildcard_segments(pattern)
  local segments, current, i = {}, {}, 1
  while i <= #pattern do
    local c = sub(pattern, i, i)
    if c == "\\" then
      current[#current + 1] = sub(pattern, i + 1, i + 1); i = i + 2
    elseif c == "*" then
      segments[#segments + 1] = concat(current); current = {}; i = i + 1
    else
      current[#current + 1] = c; i = i + 1
    end
  end
  segments[#segments + 1] = concat(current)
  return segments
end

-- wildcard_match matches source against segments (ASCII-lowercased unless
-- case_sensitive) with leftmost placement: the first segment is a prefix,
-- each middle one the first occurrence after the previous, the last a
-- suffix at or after that. Returns the captures (bytes of source between
-- the segments) or nil.
local function wildcard_match(source, segments, case_sensitive)
  local subject = case_sensitive and source or lower(source)
  local n = #segments
  if n == 1 then
    if subject == segments[1] then return {} end
    return nil
  end
  local first = segments[1]
  if sub(subject, 1, #first) ~= first then return nil end
  local pos, captures = #first + 1, {}
  for i = 2, n - 1 do
    local part = segments[i]
    local at = find(subject, part, pos, true)
    if not at then return nil end
    captures[#captures + 1] = sub(source, pos, at - 1)
    pos = at + #part
  end
  local last = segments[n]
  local tail = #subject - #last + 1
  if tail < pos or sub(subject, tail) ~= last then return nil end
  captures[#captures + 1] = sub(source, pos, tail - 1)
  return captures
end

local function fold_segments(pattern, case_sensitive)
  local segments = _M.wildcard_segments(pattern)
  if not case_sensitive then
    for i = 1, #segments do segments[i] = lower(segments[i]) end
  end
  return segments
end

-- wildcard_matcher returns a function telling whether a value fully matches
-- a wildcard pattern, ASCII case-insensitively unless strict, as the
-- wildcard comparisons do (edgeweir.access: user agent rules).
function _M.wildcard_matcher(pattern, strict)
  local segments = fold_segments(pattern, strict)
  return function(source) return wildcard_match(source, segments, strict) ~= nil end
end

-- wildcard_replace(source, pattern, replacement[, flag]): the replacement
-- with the captures of a full wildcard match, source unchanged without one.
function _M.wildcard_replace(source, pattern, replacement, flag)
  local case_sensitive = flag == "s"
  local captures = wildcard_match(source, fold_segments(pattern, case_sensitive), case_sensitive)
  if not captures then return source end
  return checked(expand(replacement, captures))
end

-- regex_replace(source, pattern, replacement): the first match of a
-- validated pattern replaced (groups that did not take part insert "");
-- source unchanged without a match.
function _M.regex_replace(source, pattern, replacement)
  local out, _, err = ngx.re.sub(source, _M.pcre_pattern(pattern), _M.sub_template(replacement), "jo")
  if not out then error("regular expression evaluation failed: " .. tostring(err)) end
  return checked(out)
end

local function value_type(e)
  return e.value_type or e.valueType
end

local FILENAMES = "http.request.body.filenames"

-- field_getter returns a function of the request values reading field
-- (default when absent; http.request.body.filenames derived from the body).
local function field_getter(field, typ)
  local default = ""
  if typ == "number" then default = 0 elseif typ == "boolean" then default = false end
  if field == FILENAMES then
    local body = require("edgeweir.body")
    return function(req)
      local v = req[field]
      if v == nil then return body.filenames_of(req) end
      return v
    end
  end
  return function(req)
    local v = req[field]
    if v == nil then return default end
    return v
  end
end

-- value compiles a value node (field, const or call) into a function of
-- the request values.
local function value(e)
  local op, typ = e.op, value_type(e)
  if op == "field" then
    return field_getter(e.field, typ)
  end
  if op == "const" then
    local v = e.value or ""
    return function() return v end
  end
  assert(op == "call", "unknown value expression")
  local name, children = e.field, e.children or {}
  local args = {}
  for i = 1, #children do args[i] = value(children[i]) end
  local a, b = args[1], args[2]
  if name == "lower" then return function(req) return checked(lower(a(req))) end end
  if name == "upper" then return function(req) return checked(upper(a(req))) end end
  if name == "len" then return function(req) return #a(req) end end
  if name == "starts_with" then
    return function(req)
      local s, prefix = a(req), b(req)
      return sub(s, 1, #prefix) == prefix
    end
  end
  if name == "ends_with" then
    return function(req)
      local s, suffix = a(req), b(req)
      return #suffix == 0 or sub(s, -#suffix) == suffix
    end
  end
  if name == "url_decode" then return function(req) return checked(_M.url_decode(a(req))) end end
  if name == "concat" then
    local n = #args
    return function(req)
      local parts = {}
      for i = 1, n do parts[i] = args[i](req) end
      return checked(concat(parts))
    end
  end
  if name == "regex_replace" then
    local pattern = _M.pcre_pattern(children[2].value or "")
    local template = _M.sub_template(children[3].value or "")
    local _, _, err = ngx.re.find("", pattern, "j")
    assert(not err, "invalid regular expression")
    return function(req)
      local out, _, failure = ngx.re.sub(a(req), pattern, template, "jo")
      if not out then error("regular expression evaluation failed: " .. tostring(failure)) end
      return checked(out)
    end
  end
  if name == "wildcard_replace" then
    local case_sensitive = children[4] ~= nil and children[4].value == "s"
    local segments = fold_segments(children[2].value or "", case_sensitive)
    local replacement = children[3].value or ""
    return function(req)
      local source = a(req)
      local captures = wildcard_match(source, segments, case_sensitive)
      if not captures then return source end
      return checked(expand(replacement, captures))
    end
  end
  -- rules-v3
  if name == "url_encode" then return function(req) return checked(_M.url_encode(a(req))) end end
  if name == "base64_encode" then return function(req) return checked(ngx.encode_base64(a(req))) end end
  if name == "base64_decode" then return function(req) return checked(_M.base64_decode(a(req))) end end
  if name == "md5" then return function(req) return ngx.md5(a(req)) end end
  if name == "sha1" then return function(req) return to_hex(ngx.sha1_bin(a(req))) end end
  if name == "sha256" then
    return function(req)
      local h = resty_sha256:new()
      h:update(a(req))
      return to_hex(h:final())
    end
  end
  if name == "substring" then
    local start = assert(tonumber(children[2].value), "invalid substring start")
    local length = children[3] and assert(tonumber(children[3].value), "invalid substring length") or nil
    return function(req) return _M.substring(a(req), start, length) end
  end
  if name == "to_string" then return function(req) return _M.to_string(a(req)) end end
  -- rules-body-v1: like reading a field, not bounded by MAX_VALUE.
  if name == "form_value" or name == "json_value" then
    local body = require("edgeweir.body")
    local arg = children[1] and children[1].value
    assert(type(arg) == "string", "invalid " .. name .. " argument")
    local fn = name == "form_value" and body.form_value_of or body.json_value_of
    return function(req) return fn(req, arg) end
  end
  error("unknown function")
end

-- compile_value compiles a value expression (RuleAction.target) into a
-- function of the request values that returns its string.
function _M.compile_value(e)
  assert(type(e) == "table", "missing value expression")
  return value(e)
end

function _M.compile(e, lists)
  local op, typ = e.op, value_type(e)
  if op == "literal" then local yes = e.value == "true"; return function() return yes end end
  if op == "not" then local fn = _M.compile(e.children[1], lists); return function(req) return not fn(req) end end
  if op == "and" or op == "or" then
    local fns = {}; for _, child in ipairs(e.children) do fns[#fns + 1] = _M.compile(child, lists) end
    return function(req)
      for _, fn in ipairs(fns) do
        local v = fn(req)
        if op == "and" and not v then return false end
        if op == "or" and v then return true end
      end
      return op == "and"
    end
  end
  -- A boolean function stands alone.
  if op == "call" then local fn = value(e); return function(req) return fn(req) == true end end
  local get
  if (e.field or "") == "" and e.children and e.children[1] then
    get = value(e.children[1]) -- computed left side
  else
    get = field_getter(e.field, typ)
  end
  if op == "in_list" then
    local matches = assert(lists[e.value], "missing IP list")
    return function(req) return matches(get(req)) end
  end
  local values = op == "in" and e.values or { e.value or "" }
  local equal
  if typ == "ip" then equal = _M.ip_set(values)
  else
    local set = {}
    for _, v in ipairs(values) do
      if typ == "number" then v = assert(tonumber(v))
      elseif typ == "boolean" then v = v == "true" end
      set[v] = true
    end
    equal = function(actual) return set[actual] == true end
  end
  if op == "eq" or op == "in" then return function(req) return equal(get(req)) end end
  if op == "ne" then return function(req) return not equal(get(req)) end end
  if op == "contains" then local needle = e.value or ""; return function(req) return find(get(req), needle, 1, true) ~= nil end end
  if op == "wildcard" or op == "strict_wildcard" then
    -- rules-v3: a full match of the pattern, ASCII case-insensitive unless strict.
    local strict = op == "strict_wildcard"
    local segments = fold_segments(e.value or "", strict)
    return function(req) return wildcard_match(get(req), segments, strict) ~= nil end
  end
  if op == "matches" then
    local pattern = _M.pcre_pattern(e.value or "")
    local _, _, err = ngx.re.find("", pattern, "j")
    assert(not err, "invalid regular expression")
    return function(req)
      local found, _, failure = ngx.re.find(get(req), pattern, "jo")
      assert(not failure, "regular expression evaluation failed") -- caller fails closed
      return found ~= nil
    end
  end
  local v = assert(tonumber(e.value))
  if op == "lt" then return function(req) return get(req) < v end end
  if op == "le" then return function(req) return get(req) <= v end end
  if op == "gt" then return function(req) return get(req) > v end end
  if op == "ge" then return function(req) return get(req) >= v end end
  error("unknown expression operator")
end

-- names adds to out (a set) the names after prefix of the fields of
-- expression e that start with prefix (cookies and query parameters by
-- name).
function _M.names(e, prefix, out)
  if type(e) ~= "table" then return out end
  if e.op ~= "call" and type(e.field) == "string" and sub(e.field, 1, #prefix) == prefix then
    out[sub(e.field, #prefix + 1)] = true
  end
  for _, c in ipairs(e.children or {}) do _M.names(c, prefix, out) end
  return out
end

-- calls reports whether expression e calls a function of the set names.
function _M.calls(e, names)
  if type(e) ~= "table" then return false end
  if e.op == "call" and names[e.field] then return true end
  for _, c in ipairs(e.children or {}) do
    if _M.calls(c, names) then return true end
  end
  return false
end

-- reads reports whether expression e reads a field for which test(field)
-- is true (function names are not fields).
function _M.reads(e, test)
  if type(e) ~= "table" then return false end
  if e.op ~= "call" and type(e.field) == "string" and test(e.field) then return true end
  for _, c in ipairs(e.children or {}) do
    if _M.reads(c, test) then return true end
  end
  return false
end
return _M
