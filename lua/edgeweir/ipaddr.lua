-- edgeweir.ipaddr: IP address parsing and the origin address policy.
--
-- Origins may not connect to special-purpose addresses (loopback,
-- link-local, private, CGNAT, documentation, multicast, ...) unless the
-- platform administrator allows them (NodeConfig.origin_allowed_cidrs).
-- The agent already refuses configured IP literals
-- (internal/configir/address.go, same list); this module checks literals
-- again and every DNS answer (edgeweir.dns). IPv4-mapped (::ffff:0:0/96)
-- and NAT64 (64:ff9b::/96) addresses are checked by their embedded IPv4
-- address.
--
-- Addresses are arrays of 4 (IPv4) or 16 (IPv6) byte values.
local bit = require("bit")

local _M = {}

local band, lshift, rshift = bit.band, bit.lshift, bit.rshift
local find, match, sub = string.find, string.match, string.sub
local tonumber = tonumber

local FORBIDDEN = {
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
  "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
  "::/128", "::1/128", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
}
_M.FORBIDDEN = FORBIDDEN

local function parse4(s)
  local a, b, c, d = match(s, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    return nil
  end
  local out = { a, b, c, d }
  for i = 1, 4 do
    local v = out[i]
    -- No leading zeros (ambiguous octal forms), like Go's netip.
    if #v > 3 or (#v > 1 and sub(v, 1, 1) == "0") then
      return nil
    end
    v = tonumber(v)
    if v > 255 then
      return nil
    end
    out[i] = v
  end
  return out
end

-- groups parses the colon-separated 16-bit groups of part; the last field
-- may be a dotted IPv4 address when last is true.
local function groups(part, last, out)
  if part == "" then
    return out
  end
  local fields = {}
  for f in (part .. ":"):gmatch("([^:]*):") do
    fields[#fields + 1] = f
  end
  for i = 1, #fields do
    local f = fields[i]
    if last and i == #fields and find(f, ".", 1, true) then
      local v4 = parse4(f)
      if not v4 then
        return nil
      end
      out[#out + 1] = v4[1] * 256 + v4[2]
      out[#out + 1] = v4[3] * 256 + v4[4]
    else
      if f == "" or #f > 4 or find(f, "[^%x]") then
        return nil
      end
      out[#out + 1] = tonumber(f, 16)
    end
  end
  return out
end

local function parse6(s)
  if find(s, "[^%x:%.]") then
    return nil -- zones and anything else are not addresses we accept
  end
  local dbl = find(s, "::", 1, true)
  local g
  if dbl then
    local head, tail = sub(s, 1, dbl - 1), sub(s, dbl + 2)
    if find(tail, "::", 1, true) then
      return nil
    end
    local h = groups(head, false, {})
    local t = h and groups(tail, true, {})
    if not t or #h + #t > 7 then
      return nil
    end
    g = h
    for _ = 1, 8 - #h - #t do
      g[#g + 1] = 0
    end
    for i = 1, #t do
      g[#g + 1] = t[i]
    end
  else
    g = groups(s, true, {})
    if not g or #g ~= 8 then
      return nil
    end
  end
  local out = {}
  for i = 1, 8 do
    out[#out + 1] = rshift(g[i], 8)
    out[#out + 1] = band(g[i], 0xff)
  end
  return out
end

-- parse returns the bytes of an IPv4 or IPv6 literal, or nil.
function _M.parse(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  if find(s, ":", 1, true) then
    return parse6(s)
  end
  return parse4(s)
end

-- is_literal reports whether s is an IP address (not a host name).
function _M.is_literal(s)
  return _M.parse(s) ~= nil
end

-- parse_prefix returns { bytes, len } for "addr/len", or nil.
function _M.parse_prefix(s)
  if type(s) ~= "string" then
    return nil
  end
  local addr, len = match(s, "^([^/]+)/(%d+)$")
  local bytes = addr and _M.parse(addr)
  len = tonumber(len)
  if not bytes or not len or len > #bytes * 8 then
    return nil
  end
  return { bytes = bytes, len = len }
end

-- contains reports whether prefix p contains address a (same family).
function _M.contains(p, a)
  local pb = p.bytes
  if #pb ~= #a then
    return false
  end
  local bits, i = p.len, 1
  while bits >= 8 do
    if pb[i] ~= a[i] then
      return false
    end
    i, bits = i + 1, bits - 8
  end
  if bits > 0 then
    local mask = band(lshift(0xff, 8 - bits), 0xff)
    return band(pb[i], mask) == band(a[i], mask)
  end
  return true
end

-- embedded_ipv4 returns the IPv4 address inside an IPv4-mapped or NAT64
-- IPv6 address, or nil.
function _M.embedded_ipv4(a)
  if #a ~= 16 then
    return nil
  end
  for i = 5, 10 do
    if a[i] ~= 0 then
      return nil
    end
  end
  local mapped = a[1] == 0 and a[2] == 0 and a[3] == 0 and a[4] == 0 and a[11] == 0xff and a[12] == 0xff
  local nat64 = a[1] == 0 and a[2] == 0x64 and a[3] == 0xff and a[4] == 0x9b and a[11] == 0 and a[12] == 0
  if mapped or nat64 then
    return { a[13], a[14], a[15], a[16] }
  end
  return nil
end

local forbidden_prefixes = {}
for i = 1, #FORBIDDEN do
  forbidden_prefixes[i] = assert(_M.parse_prefix(FORBIDDEN[i]))
end

-- prefixes parses a list of CIDR strings, skipping invalid entries.
function _M.prefixes(list)
  local out = {}
  if type(list) ~= "table" then
    return out
  end
  for i = 1, #list do
    local p = _M.parse_prefix(list[i])
    if p then
      out[#out + 1] = p
    end
  end
  return out
end

-- forbidden reports whether origins may not connect to address s: it is
-- not a valid literal, or it lies in a special-purpose range and in no
-- prefix of allowed (a list from prefixes()).
function _M.forbidden(s, allowed)
  local a = _M.parse(s)
  if not a then
    return true
  end
  local v4 = _M.embedded_ipv4(a)
  if allowed then
    for i = 1, #allowed do
      local p = allowed[i]
      if _M.contains(p, a) or (v4 and _M.contains(p, v4)) then
        return false
      end
    end
  end
  local check = v4 or a
  for i = 1, #forbidden_prefixes do
    if _M.contains(forbidden_prefixes[i], check) then
      return true
    end
  end
  return false
end

return _M
