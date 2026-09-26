-- Bounded expression IR -> closures. Never evaluates user text as Lua code.
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

function _M.compile(e, lists)
  local op, typ = e.op, e.value_type or e.valueType
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
  local function get(req)
    local actual = req[e.field]
    if actual ~= nil then return actual end
    if typ == "number" then return 0 end
    if typ == "boolean" then return false end
    return ""
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
    for _, value in ipairs(values) do
      if typ == "number" then value = assert(tonumber(value))
      elseif typ == "boolean" then value = value == "true" end
      set[value] = true
    end
    equal = function(actual) return set[actual] == true end
  end
  if op == "eq" or op == "in" then return function(req) return equal(get(req)) end end
  if op == "ne" then return function(req) return not equal(get(req)) end end
  if op == "contains" then return function(req) return string.find(get(req), e.value, 1, true) ~= nil end end
  if op == "matches" then
    -- PCRE work is bounded even if a future parser admits an expensive pattern.
    local pattern = "(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)" .. e.value
    local _, _, err = ngx.re.find("", pattern, "j")
    assert(not err, "invalid regular expression")
    return function(req)
      local found, _, failure = ngx.re.find(get(req), pattern, "jo")
      assert(not failure, "regular expression evaluation failed") -- caller fails closed
      return found ~= nil
    end
  end
  local value = assert(tonumber(e.value))
  if op == "lt" then return function(req) return get(req) < value end end
  if op == "le" then return function(req) return get(req) <= value end end
  if op == "gt" then return function(req) return get(req) > value end end
  if op == "ge" then return function(req) return get(req) >= value end end
  error("unknown expression operator")
end
return _M
