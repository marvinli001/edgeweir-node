-- Proto v0.26.0 in the data plane (ADR-0037): the certificate a handshake
-- gets among a site's certificates (edgeweir.tls.select) and what the
-- client can use (client_caps), the session id context of every
-- handshake, client certificates (verify_client, the visitor's X-Client-*
-- headers removed everywhere, the 403 of sites that require them, the
-- headers towards the origin, the expression fields).
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_bans 1m' \
--         --shdict 'edgeweir_cc 1m' test/lua/tls.lua

-- Stand-ins for ngx.ssl, ngx.ssl.clienthello and ngx.ocsp (usable only in
-- the TLS phases), installed before edgeweir.tls loads them.
local tls_state = {}
package.loaded["ngx.ssl"] = {
  server_name = function() return tls_state.name end,
  server_port = function() return tls_state.port end,
  parse_pem_cert = function(pem)
    -- CA bundles are real PEM here, site chains "<name>-CHAIN".
    if pem:find("-----BEGIN", 1, true) then tls_state.parsed_ca = (tls_state.parsed_ca or 0) + 1 end
    return "cert:" .. pem
  end,
  parse_pem_priv_key = function(pem) return "key:" .. pem end,
  clear_certs = function() return true end,
  set_cert = function(c) tls_state.cert = c; return true end,
  set_priv_key = function(k) tls_state.key = k; return true end,
  verify_client = function(chain, depth) tls_state.verify = { chain, depth }; return true end,
}
package.loaded["ngx.ssl.clienthello"] = {
  get_client_hello_server_name = function() return tls_state.name end,
  set_protocols = function(p) tls_state.protocols = p; return true end,
  get_client_hello_ext = function(t) return tls_state.ext and tls_state.ext[t] end,
  get_client_hello_ciphers = function() return tls_state.ciphers end,
}
package.loaded["ngx.ocsp"] = { set_ocsp_status_resp = function(r) tls_state.ocsp = r; return true end }

local tls = require("edgeweir.tls")
local store = require("edgeweir.store")
local policy = require("edgeweir.policy")
local router = require("edgeweir.router")
local clientcert = require("edgeweir.clientcert")
local expressions = require("edgeweir.expressions")
local resty_sha256 = require("resty.sha256")

-- The FFI call is replaced: it records the context it was given.
tls.set_session_context = function(raw)
  tls_state.context = raw
  return true
end

local passed, failed = 0, 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    print("ok   " .. name)
  else
    failed = failed + 1
    print("FAIL " .. name .. ": " .. tostring(err))
  end
end

local function eq(got, want, msg)
  if got ~= want then
    error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2)
  end
end

local function u16(...)
  local out = {}
  for _, v in ipairs({ ... }) do out[#out + 1] = string.char(math.floor(v / 256), v % 256) end
  return table.concat(out)
end
-- sigalgs is a signature_algorithms extension; versions supported_versions.
local function sigalgs(...) local body = u16(...); return u16(#body) .. body end
local function versions(...) local body = u16(...); return string.char(#body) .. body end

local function cert(name, key_type, curve, names)
  return { chain_pem = name .. "-CHAIN", private_key_pem = name .. "-KEY", fingerprint = "fp-" .. name,
    key_type = key_type, curve = curve, dns_names = names, ocsp = ngx.encode_base64("ocsp-" .. name), ocsp_until = ngx.time() + 3600 }
end

test("client_caps: the curves whose scheme the client signs with, given TLS 1.3 or an ECDHE-ECDSA suite", function()
  local caps = tls.client_caps(sigalgs(0x0804, 0x0403, 0x0503), versions(0x0304, 0x0303), { 0x1301 }, "modern")
  eq(caps["P-256"], true)
  eq(caps["P-384"], true)
  eq(caps["P-521"], nil)
  -- TLS 1.2 only: an ECDHE-ECDSA suite of the profile is needed.
  caps = tls.client_caps(sigalgs(0x0403), nil, { 0xC02F }, "modern")
  eq(next(caps), nil, "RSA suites only")
  caps = tls.client_caps(sigalgs(0x0403), versions(0x0303), { 0xC02F, 0xC02B }, "modern")
  eq(caps["P-256"], true, "ECDHE-ECDSA-AES128-GCM-SHA256")
  caps = tls.client_caps(sigalgs(0x0403), nil, { 0xCCA9 }, nil)
  eq(caps["P-256"], true, "ECDHE-ECDSA-CHACHA20-POLY1305, the modern profile by default")
  eq(next(tls.client_caps(sigalgs(0x0403), nil, { 0xC02C }, "modern")), nil, "AES256 is compatible only")
  eq(tls.client_caps(sigalgs(0x0403), nil, { 0xC02C }, "compatible")["P-256"], true)
  -- TLS 1.3 needs no suite, but the curve's scheme.
  eq(next(tls.client_caps(sigalgs(0x0804, 0x0401), versions(0x0304), {}, "modern")), nil, "RSA schemes only")
  eq(tls.client_caps(sigalgs(0x0603), versions(0x7a7a, 0x0304), {}, "modern")["P-521"], true, "GREASE ignored")
  -- No signature_algorithms extension, or a malformed one: no ECDSA.
  eq(next(tls.client_caps(nil, versions(0x0304), { 0xC02B }, "modern")), nil)
  eq(next(tls.client_caps("\0\3\4\3", versions(0x0304), {}, "modern")), nil)
end)

test("select: the certificates naming the SNI, exact over wildcard, ECDSA for clients that can use it, then the site's order", function()
  local ec = cert("ec", "ec", "P-256", { "a.test", "*.a.test" })
  local rsa = cert("rsa", "rsa", nil, { "a.test", "*.a.test" })
  local other = cert("other", "ec", "P-256", { "b.test" })
  local wild = cert("wild", "rsa", nil, { "*.b.test" })
  local certs = { ec, rsa, other, wild }
  local p256, none = { ["P-256"] = true }, {}
  eq(tls.select(certs, "a.test", p256), ec, "ECDSA client")
  eq(tls.select(certs, "a.test", none), rsa, "RSA-only client")
  eq(tls.select(certs, "x.a.test", none), rsa, "wildcard, RSA-only client")
  eq(tls.select(certs, "b.test", none), other, "the one naming the SNI, even when the client cannot use it")
  eq(tls.select(certs, "x.b.test", p256), wild, "the only one naming it")
  eq(tls.select(certs, "c.test", p256), ec, "none names it: the first")
  eq(tls.select(certs, "c.test", none), ec, "the first even for RSA-only clients")
  -- Exact names win over a wildcard of the preferred type.
  local exact_rsa = cert("exact", "rsa", nil, { "x.a.test" })
  eq(tls.select({ ec, exact_rsa }, "x.a.test", p256), exact_rsa)
  -- ...unless the client cannot use the exact one.
  local exact_ec = cert("exact-ec", "ec", "P-384", { "x.a.test" })
  eq(tls.select({ exact_ec, rsa }, "x.a.test", p256), rsa, "P-384 unusable for a P-256-only client")
  eq(tls.select({ exact_ec, rsa }, "x.a.test", { ["P-384"] = true }), exact_ec)
  -- The site's order breaks ties.
  local ec2 = cert("ec2", "ec", "P-384", { "a.test" })
  eq(tls.select({ ec2, ec, rsa }, "a.test", { ["P-256"] = true, ["P-384"] = true }), ec2)
  eq(tls.select({ rsa, cert("rsa2", "rsa", nil, { "a.test" }) }, "a.test", nil), rsa, "one key type: no capabilities needed")
  eq(tls.select({ ec, ec2 }, "a.test", nil), ec)
  eq(tls.select({ ec }, "zzz", none), ec, "one certificate")
end)

-- site_table installs sites: a with an ECDSA and an RSA certificate and
-- required client certificates, b with one certificate, d with optional
-- ones.
local CA = "-----BEGIN CERTIFICATE-----\nMIIBVzCB/qADAgECAgILETAKBggqhkjOPQQDAjAhMR8wHQYDVQQDExZFZGdld2Vp\nciBHMTEgdmVjdG9yIENBMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFow\nITEfMB0GA1UEAxMWRWRnZXdlaXIgRzExIHZlY3RvciBDQTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABNIvw6o2z+Y6TdXLM3Zg8ho9YLAkLylVVArzoR4CaByEcafl\nTd2x94FNKW76LHSCeMl3y1+7y9HFKjkPxtgVHDCjJjAkMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIQDNW4suHpPe\n2oyav7yguz8JNo1fe2082+r9KO6vrHQR9AIgV7mT2XiwYAeaNu/AUDm5eDSIpVxq\n/13mwC976EolPR4=\n-----END CERTIFICATE-----\n"
local CA_DER_SHA256 = "982e432fafc4f5720ee6464a626a7aa7fa4b316e6b8974caae027a39973ea27b"
local CTX_A, CTX_B = string.rep("a1", 32), string.rep("b2", 32)

local function site(id, names, extra)
  local domains = {}
  for _, n in ipairs(names) do domains[#domains + 1] = { name = n } end
  local s = { id = id, cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random",
    domains = domains, origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } } }
  for k, v in pairs(extra or {}) do s[k] = v end
  return s
end

local function site_table(revision)
  local ec, rsa = cert("a-ec", "ec", "P-256", { "a.test" }), cert("a-rsa", "rsa", nil, { "a.test" })
  assert(store.replace({ revision = revision, content_hash = revision, cdn_id = "edgeweir-tlstest",
    health_certificate = { chain_pem = "HEALTH-CHAIN", private_key_pem = "HEALTH-KEY", fingerprint = "fh" },
    sites = {
      site("a", { "a.test" }, { certificate_id = "a-ec", certificate = ec, certificates = { ec, rsa },
        tls = { minimum_version = "1.2", cipher_profile = "modern", ocsp_stapling = true, force_https = true },
        tls_session_context = CTX_A,
        client_certificate = { mode = "required", ca_pem = CA, depth = 3, forward_headers = true } }),
      site("b", { "b.test" }, { certificate_id = "b", certificate = cert("b", "ec", "P-256"),
        tls = { minimum_version = "1.3", cipher_profile = "modern" }, tls_session_context = CTX_B }),
      site("nocontext", { "n.test" }, { certificate_id = "n", certificate = cert("n", "rsa") }),
      site("d", { "d.test" }, { certificate_id = "d", certificate = cert("d", "ec", "P-256"), tls_session_context = CTX_B,
        client_certificate = { mode = "optional", ca_pem = CA, depth = 2 } }),
    } }))
end

-- tls_phase runs a TLS hook with SNI name and the ClientHello in hello
-- ({ ext = { [13] = ..., [43] = ... }, ciphers = { ... } }); it returns
-- whether the handshake was aborted. ngx.ctx is shared between the hooks,
-- as for one connection.
local conn_ctx = {}
local function tls_phase(fn, name, hello)
  tls_state.name, tls_state.cert, tls_state.key, tls_state.verify, tls_state.ocsp, tls_state.context, tls_state.protocols =
    name, nil, nil, nil, nil, nil, nil
  tls_state.ext, tls_state.ciphers = hello and hello.ext, hello and hello.ciphers
  local runtime = ngx
  local aborted = false
  _G.ngx = setmetatable({ ctx = conn_ctx, exit = function(code) aborted = code == runtime.ERROR end, log = function() end }, { __index = runtime })
  local ok, err = pcall(fn)
  _G.ngx = runtime
  assert(ok, err)
  return aborted
end

local function unhex(s)
  return (s:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

test("session context: the site's for its names, the health context for the health certificate, none aborts", function()
  site_table("1")
  conn_ctx = {}
  eq(tls_phase(tls.client_hello, "a.test"), false)
  eq(tls_state.context, unhex(CTX_A), "site a")
  eq(tls_phase(tls.client_hello, "B.TEST"), false)
  eq(tls_state.context, unhex(CTX_B), "site b")
  eq(tls_state.protocols and tls_state.protocols[1], "TLSv1.3", "b's minimum version")
  local h = resty_sha256:new()
  h:update("edgeweir-tls-v1\0health")
  local health = h:final()
  eq(#health, 32)
  for _, name in ipairs({ "health.edgeweir.invalid", nil }) do
    eq(tls_phase(tls.client_hello, name), false)
    eq(tls_state.context, health, "health")
  end
  -- A site without a context never completes (it could resume another's).
  eq(tls_phase(tls.client_hello, "n.test"), true, "no context")
  -- The context call failing aborts too.
  local real = tls.set_session_context
  tls.set_session_context = function() return nil, "no SSL" end
  eq(tls_phase(tls.client_hello, "a.test"), true, "failed context")
  eq(tls_phase(tls.client_hello, "health.edgeweir.invalid"), true, "failed health context")
  tls.set_session_context = real
end)

test("certificate: ECDSA or RSA by the ClientHello, its OCSP response, client certificates asked for", function()
  site_table("2")
  -- A default client: TLS 1.3 and ecdsa_secp256r1_sha256.
  conn_ctx = {}
  local modern = { ext = { [13] = sigalgs(0x0403, 0x0804), [43] = versions(0x0304, 0x0303) }, ciphers = { 0x1301, 0xC02B } }
  eq(tls_phase(tls.client_hello, "a.test", modern), false)
  eq(conn_ctx.edgeweir_tls_caps["P-256"], true)
  eq(tls_phase(tls.certificate, "a.test"), false)
  eq(tls_state.cert, "cert:a-ec-CHAIN")
  eq(tls_state.key, "key:a-ec-KEY")
  eq(tls_state.ocsp, "ocsp-a-ec", "the chosen certificate's OCSP response")
  eq(tls_state.verify[1], "cert:" .. CA, "the site's CA bundle")
  eq(tls_state.verify[2], 3, "the site's depth")
  -- An RSA-only TLS 1.2 client.
  conn_ctx = {}
  local rsa_only = { ext = { [13] = sigalgs(0x0804, 0x0401) }, ciphers = { 0xC02F } }
  eq(tls_phase(tls.client_hello, "a.test", rsa_only), false)
  eq(tls_phase(tls.certificate, "a.test"), false)
  eq(tls_state.cert, "cert:a-rsa-CHAIN")
  eq(tls_state.ocsp, "ocsp-a-rsa")
  -- Without capabilities from the ClientHello (lost context): RSA, which
  -- every client can use.
  conn_ctx = {}
  eq(tls_phase(tls.certificate, "a.test"), false)
  eq(tls_state.cert, "cert:a-rsa-CHAIN")
  -- One key type: nothing computed, the one certificate, no client
  -- certificates asked for.
  conn_ctx = {}
  eq(tls_phase(tls.client_hello, "b.test", rsa_only), false)
  eq(conn_ctx.edgeweir_tls_caps, nil, "b has one key type")
  eq(tls_phase(tls.certificate, "b.test"), false)
  eq(tls_state.cert, "cert:b-CHAIN")
  eq(tls_state.verify, nil)
  eq(tls_state.ocsp, nil, "OCSP stapling off")
  -- The CA bundle is parsed once.
  eq(tls_state.parsed_ca, 1)
  eq(tls_phase(tls.certificate, "d.test"), false)
  eq(tls_state.verify[1], "cert:" .. CA)
  eq(tls_state.verify[2], 2)
  eq(tls_state.parsed_ca, 1, "same CA bundle as a: parsed once")
end)

test("clientcert: verify states, the leaf's SHA-256, values only for a verified certificate", function()
  eq(clientcert.verify_state("https", "SUCCESS"), "SUCCESS")
  eq(clientcert.verify_state("https", "FAILED:certificate has expired"), "FAILED")
  eq(clientcert.verify_state("https", "NONE"), "NONE")
  eq(clientcert.verify_state("https", nil), "NONE")
  eq(clientcert.verify_state("http", "SUCCESS"), "NONE", "plain HTTP has no certificate")
  eq(clientcert.cert_sha256(CA), CA_DER_SHA256)
  eq(clientcert.cert_sha256(CA .. CA), CA_DER_SHA256, "the first certificate")
  eq(clientcert.cert_sha256(""), "")
  eq(clientcert.cert_sha256(nil), "")
  eq(clientcert.cert_sha256("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), "")
  local v = clientcert.compute("https", "SUCCESS", CA, "CN=alice,OU=Ops", "0B11")
  eq(v.verify, "SUCCESS"); eq(v.verified, true); eq(v.sha256, CA_DER_SHA256); eq(v.subject, "CN=alice,OU=Ops"); eq(v.serial, "0B11")
  for _, case in ipairs({ { "https", "FAILED:x", "FAILED" }, { "https", "NONE", "NONE" }, { "http", "SUCCESS", "NONE" } }) do
    v = clientcert.compute(case[1], case[2], CA, "CN=alice", "0B11")
    eq(v.verify, case[3]); eq(v.verified, false); eq(v.sha256, ""); eq(v.subject, ""); eq(v.serial, "")
  end
end)

test("clientcert: forward sets X-Client-Verify always and the others when set", function()
  local real = ngx
  local set = {}
  _G.ngx = setmetatable({ req = { set_header = function(k, val) set[k] = val == nil and "<cleared>" or val end } }, { __index = real })
  clientcert.forward(clientcert.compute("https", "SUCCESS", CA, "CN=alice", "0B11"))
  _G.ngx = real
  eq(set["X-Client-Verify"], "SUCCESS"); eq(set["X-Client-Cert-SHA256"], CA_DER_SHA256)
  eq(set["X-Client-Cert-Subject"], "CN=alice"); eq(set["X-Client-Cert-Serial"], "0B11")
  set = {}
  _G.ngx = setmetatable({ req = { set_header = function(k, val) set[k] = val == nil and "<cleared>" or val end } }, { __index = real })
  clientcert.forward(clientcert.compute("https", "FAILED:x", CA, "CN=alice\r\nX-Injected: 1", "0B11"))
  clientcert.forward({ verify = "SUCCESS", verified = true, sha256 = "", subject = "CN=a\nb", serial = "" })
  _G.ngx = real
  eq(set["X-Client-Verify"], "SUCCESS")
  for _, name in ipairs({ "X-Client-Cert-SHA256", "X-Client-Cert-Subject", "X-Client-Cert-Serial" }) do
    eq(set[name], "<cleared>", name)
  end
  for _, name in ipairs({ "x-client-verify", "x-client-cert-sha256", "x-client-cert-subject", "x-client-cert-serial" }) do
    eq(clientcert.STRIP[name], true, name)
  end
  eq(clientcert.STRIP["x-client"], nil)
end)

test("decision: sites that require a certificate deny without a verified one; plain HTTP redirects first; HTTP-01 goes on", function()
  local required = { _client_required = true }
  eq(clientcert.decision(required, "https", "SUCCESS", false), nil)
  eq(clientcert.decision(required, "https", "NONE", false), "deny")
  eq(clientcert.decision(required, "https", "FAILED:unable to get local issuer certificate", false), "deny")
  eq(clientcert.decision(required, "https", nil, false), "deny")
  eq(clientcert.decision(required, "https", "NONE", true), "deny", "HTTPS HTTP-01 requests need one too")
  eq(clientcert.decision(required, "http", nil, false), "http")
  eq(clientcert.decision(required, "http", nil, true), nil, "HTTP-01 for the origin")
  eq(clientcert.decision({}, "https", "NONE", false), nil, "optional or off")
  eq(clientcert.decision(nil, "https", "NONE", false), nil)
  -- The site's own HTTPS redirect for plain HTTP.
  local s = store.prepare(site("r", { "r.test", "p.test" }, { certificate_id = "c", certificate = cert("r", "ec", "P-256"),
    tls = { force_https = true, redirect_excluded = { "p.test" } } }))
  local r = policy.site_https_redirect(s, "r.test", "/x?y", "exact")
  eq(r.status, 301); eq(r.location, "https://r.test/x?y")
  eq(policy.site_https_redirect(s, "p.test", "/", "exact"), nil, "excluded")
  s.tls.force_https = false
  eq(policy.site_https_redirect(s, "r.test", "/", "exact"), nil, "no Force HTTPS")
end)

-- access runs the edge access phase with a stand-in ngx for request var
-- and request headers; it returns what it answered and the headers left.
local function access(var, headers)
  local runtime = ngx
  local out = { header = {}, body = {} }
  var.uri = var.uri or "/"
  var.request_uri = var.request_uri or var.uri
  var.remote_addr = var.remote_addr or "192.0.2.10"
  var.server_port = var.server_port or (var.scheme == "https" and "443" or "80")
  var.edgeweir_request_id = "req-1"
  local hdrs = {}
  for k, v in pairs(headers or {}) do hdrs[k] = v end
  out.headers = hdrs
  _G.ngx = setmetatable({
    var = var,
    ctx = {},
    header = out.header,
    req = {
      get_method = function() return "GET" end,
      get_headers = function() local copy = {}; for k, v in pairs(hdrs) do copy[k] = v end; return copy end,
      clear_header = function(k) hdrs[k:lower()] = nil end,
      set_header = function(k, v) hdrs[k:lower()] = v end,
      start_time = function() return 0 end,
    },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    exit = function(code) out.exit = code; error("exit", 0) end,
    redirect = function(location, status) out.location, out.status = location, status; error("exit", 0) end,
    log = function() end,
  }, { __index = runtime })
  local ok, err = pcall(router.access)
  out.status = out.status or rawget(ngx, "status")
  _G.ngx = runtime
  out.ok, out.err = ok or err == "exit", err
  out.body = table.concat(out.body)
  return out
end

test("router: the visitor's X-Client-* headers are removed on every site, with X-Edgeweir-*", function()
  site_table("3")
  -- CDN-Loop answers right after the headers were cleaned up.
  local out = access({ scheme = "http", host = "b.test", http_cdn_loop = "edgeweir-tlstest" }, {
    ["x-client-verify"] = "SUCCESS", ["x-client-cert-sha256"] = "aa", ["x-client-cert-subject"] = "CN=me",
    ["x-client-cert-serial"] = "01", ["x-edgeweir-site"] = "a", ["x-client-other"] = "kept", accept = "*/*",
  })
  assert(out.ok, out.err)
  eq(out.status, 508)
  for _, name in ipairs({ "x-client-verify", "x-client-cert-sha256", "x-client-cert-subject", "x-client-cert-serial", "x-edgeweir-site" }) do
    eq(out.headers[name], nil, name)
  end
  eq(out.headers["x-client-other"], "kept")
  eq(out.headers.accept, "*/*")
end)

test("router: a site that requires client certificates answers 403 client-cert-required before the site logic", function()
  site_table("4")
  for _, verify in ipairs({ "NONE", "FAILED:certificate has expired" }) do
    local out = access({ scheme = "https", host = "a.test", ssl_server_name = "a.test", ssl_client_verify = verify })
    assert(out.ok, out.err)
    eq(out.status, 403, verify)
    eq(out.header["X-Edgeweir-Error"], "client-cert-required")
    eq(out.header["Content-Type"], "text/html; charset=utf-8", "the error page")
  end
  -- Plain HTTP: the site's HTTPS redirect.
  local out = access({ scheme = "http", host = "a.test", uri = "/p" })
  assert(out.ok, out.err)
  eq(out.status, 301)
  eq(out.location, "https://a.test/p")
  -- A verified certificate goes on to the site logic (it stops at the
  -- unstubbed parts further on, never with this answer).
  out = access({ scheme = "https", host = "a.test", ssl_server_name = "a.test", ssl_client_verify = "SUCCESS" })
  eq(out.header["X-Edgeweir-Error"], nil)
  assert(out.status ~= 403, "denied")
  -- The local listener (prefetches) is not asked.
  out = access({ scheme = "https", host = "a.test", ssl_server_name = "a.test", ssl_client_verify = "NONE", edgeweir_local = "1" })
  eq(out.header["X-Edgeweir-Error"], nil)
  -- Optional sites serve requests without one.
  out = access({ scheme = "https", host = "d.test", ssl_server_name = "d.test", ssl_client_verify = "NONE" })
  eq(out.header["X-Edgeweir-Error"], nil)
end)

test("expression fields: tls.client.* only for sites whose rules read them", function()
  local rule = { id = "r", phase = "waf-custom", action = { kind = "block", status_code = 403 },
    expression = { op = "eq", field = "tls.client.verified", value_type = "boolean", value = "false" } }
  local s = store.prepare(site("x", { "x.test" }, { rules = { rule } }), policy.prepare_config({}))
  eq(s._client_fields, true)
  eq(store.prepare(site("y", { "y.test" }), policy.prepare_config({}))._client_fields, nil)
  local runtime = ngx
  local function values(var)
    _G.ngx = setmetatable({ var = var, ctx = {}, req = { get_method = function() return "GET" end, start_time = function() return 0 end } }, { __index = runtime })
    local ok, v = pcall(policy.request, s, {})
    _G.ngx = runtime
    assert(ok, v)
    return v
  end
  local v = values({ scheme = "https", host = "x.test", uri = "/", request_uri = "/", remote_addr = "192.0.2.1",
    ssl_client_verify = "SUCCESS", ssl_client_raw_cert = CA, ssl_client_s_dn = "CN=Edgeweir G11 vector CA", ssl_client_serial = "0B11" })
  eq(v["tls.client.verified"], true); eq(v["tls.client.cert_sha256"], CA_DER_SHA256); eq(v["tls.client.subject"], "CN=Edgeweir G11 vector CA")
  v = values({ scheme = "http", host = "x.test", uri = "/", request_uri = "/", remote_addr = "192.0.2.1" })
  eq(v["tls.client.verified"], false); eq(v["tls.client.cert_sha256"], ""); eq(v["tls.client.subject"], "")
  local match = expressions.compile(rule.expression, {})
  eq(match(v), true, "the rule matches without a certificate")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
