-- Lua unit tests for edgeweir.ja4 (see `make lua-test`): the vectors in
-- ja4-vectors.json are the worked example of FoxIO's JA4.md and cases
-- constructed from its specification text.
local cjson = require("cjson.safe")
local ja4 = require("edgeweir.ja4")

local vectors = assert(cjson.decode(assert(io.open("/t/ja4-vectors.json")):read("*a")))
local function nums(list)
  local out = {}
  for i, v in ipairs(list or {}) do out[i] = tonumber(v, 16) end
  return out
end
local function unhex(s)
  return (s:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

local count = 0
for _, v in ipairs(vectors) do
  local alpn = v.alpn
  if alpn == cjson.null then alpn = nil elseif alpn then alpn = unhex(alpn) end
  local versions = v.supported_versions
  if versions == cjson.null then versions = nil else versions = nums(versions) end
  local fp, raw, original = ja4.fingerprint({
    protocol = v.protocol, ciphers = nums(v.ciphers), extensions = nums(v.extensions),
    signature_algorithms = nums(v.signature_algorithms), alpn = alpn, versions = versions,
  })
  local got = ja4.finish(fp, v.negotiated, false)
  assert(got == v.ja4, v.name .. ": JA4 " .. got .. ", want " .. v.ja4)
  local function finish(s) return (ja4.finish(s, v.negotiated, false)) end
  assert(finish(raw) == v.ja4_r, v.name .. ": JA4_r " .. finish(raw) .. ", want " .. v.ja4_r)
  assert(finish(original) == v.ja4_ro, v.name .. ": JA4_ro " .. finish(original) .. ", want " .. v.ja4_ro)
  count = count + 1
end

-- HTTP/3 turns the protocol into "q"; plain HTTP has no fingerprint.
assert(ja4.finish("t13d1516h2_8daaf6152771_e5627efa2ab1", "TLSv1.3", true) == "q13d1516h2_8daaf6152771_e5627efa2ab1")
assert(ja4.finish(nil, nil, false) == "")
assert(ja4.finish("t??d1516h2_x_y", "TLSv1.2", false) == "t12d1516h2_x_y")
assert(ja4.finish("t??d1516h2_x_y", nil, false) == "t00d1516h2_x_y")

-- Extension parsers (ClientHello wire format).
local versions = ja4.parse_versions("\6\42\42\3\4\3\3")
assert(#versions == 3 and versions[1] == 0x2a2a and versions[2] == 0x0304 and versions[3] == 0x0303)
assert(ja4.parse_versions("\5\3\4\3\3") == nil and ja4.parse_versions("") == nil and ja4.parse_versions(nil) == nil)
local sig = ja4.parse_u16_list("\0\4\4\3\8\4")
assert(#sig == 2 and sig[1] == 0x0403 and sig[2] == 0x0804)
assert(ja4.parse_u16_list("\0\5\4\3\8\4\1") == nil)
assert(ja4.parse_alpn("\0\12\2h2\8http/1.1") == "h2")
assert(ja4.parse_alpn("\0\0") == "")
assert(ja4.parse_alpn("\0\1\0") == "")
assert(ja4.parse_alpn("\0\3\5h2") == nil)
assert(ja4.grease(0x0a0a) and ja4.grease(0xfafa) and not ja4.grease(0x0a1a) and not ja4.grease(0x1301))

print(tostring(count) .. " JA4 vectors passed")
