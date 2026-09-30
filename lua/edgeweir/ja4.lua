-- edgeweir.ja4: JA4 TLS client fingerprints (FoxIO JA4, BSD-3-Clause
-- method; only JA4 itself, none of the other JA4+ methods).
--
--   <proto><version><sni><ciphers><extensions><alpn>_<cipher hash>_<extension hash>
--
-- client_hello() runs in ssl_client_hello_by_lua for sites that need the
-- fingerprint (rules or rate limits on tls.ja4, JA4 in access logs) and
-- stores it in ngx.ctx.edgeweir_ja4; requests on the connection inherit
-- ngx.ctx from the handshake. value() finishes it in the request phase:
-- "q" instead of "t" on HTTP/3, the negotiated version when the ClientHello
-- had no supported_versions extension (JA4 takes the ClientHello's legacy
-- version there, which the API does not expose), "" on plain HTTP.
--
-- The ClientHello comes from lua-resty-core (ngx.ssl.clienthello), which
-- lists only the extensions OpenSSL knows; unknown ones (for example ALPS
-- or ECH) are missing from the count and the hash.
local bit = require("bit")
local sha256 = require("resty.sha256")
local str = require("resty.string")

local _M = {}

local band, rshift = bit.band, bit.rshift
local byte, sub, format, concat, sort = string.byte, string.sub, string.format, table.concat, table.sort

-- grease reports GREASE values (RFC 8701): 0x?a?a with equal bytes.
function _M.grease(v)
  return band(v, 0x0f0f) == 0x0a0a and rshift(v, 8) == band(v, 0xff)
end
local grease = _M.grease

local VERSIONS = {
  [0x0304] = "13", [0x0303] = "12", [0x0302] = "11", [0x0301] = "10", [0x0300] = "s3", [0x0002] = "s2",
  [0xfeff] = "d1", [0xfefd] = "d2", [0xfefc] = "d3",
}
local NEGOTIATED = { ["TLSv1.3"] = "13", ["TLSv1.2"] = "12", ["TLSv1.1"] = "11", ["TLSv1"] = "10", ["SSLv3"] = "s3" }

-- negotiated_version maps $ssl_protocol to the JA4 version ("00" unknown).
function _M.negotiated_version(protocol)
  return NEGOTIATED[protocol or ""] or "00"
end

local function u16(s, i)
  local a, b = byte(s, i, i + 1)
  return a * 256 + b
end

-- parse_versions reads the supported_versions extension (ClientHello
-- form: one length byte, then 16-bit versions) into numbers; nil when
-- malformed.
function _M.parse_versions(raw)
  if not raw or #raw < 1 then return nil end
  local n = byte(raw, 1)
  if n % 2 ~= 0 or n + 1 ~= #raw then return nil end
  local out = {}
  for i = 2, n, 2 do out[#out + 1] = u16(raw, i) end
  return out
end

-- parse_u16_list reads a 16-bit length followed by 16-bit values
-- (signature_algorithms); nil when malformed.
function _M.parse_u16_list(raw)
  if not raw or #raw < 2 then return nil end
  local n = u16(raw, 1)
  if n % 2 ~= 0 or n + 2 ~= #raw then return nil end
  local out = {}
  for i = 3, n + 1, 2 do out[#out + 1] = u16(raw, i) end
  return out
end

-- parse_alpn returns the first protocol of an ALPN extension ("" when the
-- list or the first name is empty); nil when malformed.
function _M.parse_alpn(raw)
  if not raw or #raw < 2 then return nil end
  local n = u16(raw, 1)
  if n + 2 ~= #raw then return nil end
  if n == 0 then return "" end
  local len = byte(raw, 3)
  if 3 + len > #raw then return nil end
  return sub(raw, 4, 3 + len)
end

local function alnum(b)
  return (b >= 0x30 and b <= 0x39) or (b >= 0x41 and b <= 0x5a) or (b >= 0x61 and b <= 0x7a)
end

-- alpn_chars returns the first and last characters of the first ALPN
-- value, or of its hex form when either byte is not alphanumeric; "00"
-- without a value.
function _M.alpn_chars(alpn)
  if not alpn or alpn == "" then return "00" end
  local first, last = byte(alpn, 1), byte(alpn, #alpn)
  if alnum(first) and alnum(last) then
    return string.char(first, last)
  end
  local hex = str.to_hex(alpn)
  return sub(hex, 1, 1) .. sub(hex, -1)
end

local function hash12(s)
  if s == "" then return "000000000000" end
  local h = sha256:new()
  h:update(s)
  return sub(str.to_hex(h:final()), 1, 12)
end

local function hex_list(values, skip)
  local out = {}
  for i = 1, #values do
    local v = values[i]
    if not grease(v) and not (skip and skip[v]) then out[#out + 1] = format("%04x", v) end
  end
  return out
end

local function count(n)
  return format("%02d", n > 99 and 99 or n)
end

local SNI_ALPN = { [0x0000] = true, [0x0010] = true }

-- fingerprint computes JA4 from a ClientHello:
--   h.ciphers, h.extensions (numbers, as received), h.signature_algorithms
--   (numbers, as received), h.alpn (first protocol, raw) or nil,
--   h.versions (supported_versions numbers) or nil, h.protocol ("t"/"q").
-- The version is "??" without supported_versions (see value()). Returns
-- JA4, JA4_r (sorted raw) and JA4_ro (raw in original order).
function _M.fingerprint(h)
  local ciphers = hex_list(h.ciphers or {})
  local extensions = hex_list(h.extensions or {})
  local sigalgs = concat(hex_list(h.signature_algorithms or {}), ",")
  local version = "??"
  if h.versions then
    local best
    for _, v in ipairs(h.versions) do
      if not grease(v) and (not best or v > best) then best = v end
    end
    version = best and VERSIONS[best] or "00"
  end
  local sni = "i"
  for _, v in ipairs(h.extensions or {}) do
    if v == 0 then sni = "d"; break end
  end
  local a = (h.protocol or "t") .. version .. sni .. count(#ciphers) .. count(#extensions) .. _M.alpn_chars(h.alpn)
  local original_ciphers, original_extensions = concat(ciphers, ","), concat(extensions, ",")
  sort(ciphers)
  local sorted = hex_list(h.extensions or {}, SNI_ALPN)
  sort(sorted)
  local cipher_list, extension_list = concat(ciphers, ","), concat(sorted, ",")
  local c = extension_list
  if extension_list ~= "" and sigalgs ~= "" then c = c .. "_" .. sigalgs end
  local tail = sigalgs ~= "" and ("_" .. sigalgs) or ""
  return a .. "_" .. hash12(cipher_list) .. "_" .. (extension_list == "" and "000000000000" or hash12(c)),
    a .. "_" .. cipher_list .. "_" .. extension_list .. tail,
    a .. "_" .. original_ciphers .. "_" .. original_extensions .. tail
end

-- client_hello stores the fingerprint of the connection's ClientHello in
-- ngx.ctx (ssl_client_hello_by_lua only).
function _M.client_hello()
  local hello = require("ngx.ssl.clienthello")
  local ciphers = hello.get_client_hello_ciphers() or {}
  local extensions = hello.get_client_hello_ext_present() or {}
  local h = {
    ciphers = ciphers,
    extensions = extensions,
    signature_algorithms = _M.parse_u16_list(hello.get_client_hello_ext(13)) or {},
    alpn = _M.parse_alpn(hello.get_client_hello_ext(16)),
    versions = _M.parse_versions(hello.get_client_hello_ext(43)),
  }
  ngx.ctx.edgeweir_ja4 = _M.fingerprint(h)
end

-- finish turns a stored fingerprint into the request's: the negotiated
-- version fills in a missing supported_versions, HTTP/3 uses "q".
function _M.finish(fp, negotiated, http3)
  if not fp then return "" end
  if sub(fp, 2, 3) == "??" then
    fp = sub(fp, 1, 1) .. _M.negotiated_version(negotiated) .. sub(fp, 4)
  end
  if http3 then fp = "q" .. sub(fp, 2) end
  return fp
end

-- value returns the request's JA4 ("" on plain HTTP or when the site did
-- not need it at the handshake). Cached in the request's ngx.ctx.
function _M.value()
  local ctx = ngx.ctx
  local v = rawget(ctx, "edgeweir_ja4_value")
  if v then return v end
  local fp = ctx.edgeweir_ja4
  if fp then
    local var = ngx.var
    v = _M.finish(fp, var.ssl_protocol, var.http3 == "h3")
  else
    v = ""
  end
  ctx.edgeweir_ja4_value = v
  return v
end

return _M
