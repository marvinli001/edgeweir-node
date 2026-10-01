-- edgeweir.proxyproto: PROXY protocol headers (haproxy's
-- proxy-protocol.txt, versions 1 and 2) for the layer-4 relay
-- (edgeweir.l4).
--
-- nginx's own proxy_protocol (on / v2) writes the TCP peer of the client
-- connection; the relay writes the client's address from the PROXY
-- header it received instead. Pure functions: addresses are IP literals
-- (IPv4 or IPv6 text), ports numbers or decimal strings.
--
--   v1  "PROXY TCP4 <src> <dst> <sport> <dport>\r\n" (TCP6 for IPv6)
--   v2  the 12-byte signature, 0x21 (version 2, command PROXY), 0x11
--       (AF_INET, STREAM) or 0x21 (AF_INET6, STREAM), the length of the
--       address block (12 or 36, network order), source and destination
--       addresses, source and destination ports (network order); no TLVs
--
-- When one address is IPv4 and the other IPv6, the IPv4 one is written as
-- an IPv4-mapped IPv6 address. Unusable input gives "PROXY UNKNOWN\r\n"
-- (v1) or a PROXY command with family AF_UNSPEC and no addresses (v2): the
-- origin then uses the connection's own endpoints.
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

local char, concat, floor = string.char, table.concat, math.floor
local tonumber = tonumber

_M.V2_SIGNATURE = "\r\n\r\n\0\r\nQUIT\n"

local function port(p)
  p = tonumber(p)
  if not p or p < 0 or p > 65535 or p ~= floor(p) then
    return nil
  end
  return p
end

local function mapped(a)
  return { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a[1], a[2], a[3], a[4] }
end

-- endpoints returns the bytes of src and dst in one family (IPv4 as
-- IPv4-mapped IPv6 when the families differ) and the ports, or nil.
local function endpoints(src, dst, sport, dport)
  local a, b = ipaddr.parse(src), ipaddr.parse(dst)
  sport, dport = port(sport), port(dport)
  if not a or not b or not sport or not dport then
    return nil
  end
  if #a ~= #b then
    if #a == 4 then
      a = mapped(a)
    else
      b = mapped(b)
    end
  end
  return a, b, sport, dport
end

local function text(bytes)
  if #bytes == 4 then
    return concat(bytes, ".")
  end
  local groups = {}
  for i = 1, 16, 2 do
    groups[#groups + 1] = string.format("%x", bytes[i] * 256 + bytes[i + 1])
  end
  return concat(groups, ":")
end

-- v1 returns the text header for a TCP connection from src:sport to
-- dst:dport.
function _M.v1(src, dst, sport, dport)
  local a, b, sp, dp = endpoints(src, dst, sport, dport)
  if not a then
    return "PROXY UNKNOWN\r\n"
  end
  -- Literals keep their own text when both are of one family; mapped
  -- addresses are written out in full.
  local s, d = src, dst
  if #ipaddr.parse(src) ~= #a then
    s = text(a)
  end
  if #ipaddr.parse(dst) ~= #b then
    d = text(b)
  end
  return concat({ "PROXY ", #a == 4 and "TCP4 " or "TCP6 ", s, " ", d, " ", sp, " ", dp, "\r\n" })
end

local function u16(v)
  return char(floor(v / 256), v % 256)
end

-- v2 returns the binary header for a TCP connection from src:sport to
-- dst:dport.
function _M.v2(src, dst, sport, dport)
  local a, b, sp, dp = endpoints(src, dst, sport, dport)
  if not a then
    return _M.V2_SIGNATURE .. "\x21\x00\x00\x00"
  end
  local out = { _M.V2_SIGNATURE, "\x21", #a == 4 and "\x11" or "\x21", u16(#a * 2 + 4) }
  out[#out + 1] = char(unpack(a))
  out[#out + 1] = char(unpack(b))
  out[#out + 1] = u16(sp)
  out[#out + 1] = u16(dp)
  return concat(out)
end

return _M
