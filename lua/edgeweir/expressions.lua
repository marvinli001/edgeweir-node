-- Bounded expression IR -> closures. Never evaluates user text as Lua code.
--
-- compile(e, lists) turns a condition into a function of the request
-- values (field name -> value) that returns a boolean; compile_value(e) a
-- value expression (redirect targets, rewrite paths) into one that returns
-- a string. Since proto v0.13.0 (feature rules-v2) conditions and values
-- may call functions (call, field and const nodes); the pure helpers below
-- (url_decode, wildcard_replace, regex_replace, path_extension,
-- media_type, full_uri) are shared with the request and response fields.
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

local lower, upper, sub, find, gsub, match, char = string.lower, string.upper, string.sub, string.find, string.gsub, string.match, string.char
local concat = table.concat

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

-- value compiles a value node (field, const or call) into a function of
-- the request values.
local function value(e)
  local op, typ = e.op, value_type(e)
  if op == "field" then
    local field = e.field
    local default = ""
    if typ == "number" then default = 0 elseif typ == "boolean" then default = false end
    return function(req)
      local v = req[field]
      if v == nil then return default end
      return v
    end
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
    local field = e.field
    get = function(req)
      local actual = req[field]
      if actual ~= nil then return actual end
      if typ == "number" then return 0 end
      if typ == "boolean" then return false end
      return ""
    end
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
