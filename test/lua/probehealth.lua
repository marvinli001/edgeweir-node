-- The probes' health endpoint (edgeweir.probehealth): which requests and
-- server names it covers, that the edge access phase answers it before any
-- site logic, that the health SNI reaches nothing else, and that the TLS
-- hooks hand out the health certificate of the site table.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' test/lua/probehealth.lua

-- Stand-ins for ngx.ssl and ngx.ssl.clienthello (only usable in the TLS
-- phases), installed before edgeweir.tls loads them.
local tls_state = {}
package.loaded["ngx.ssl"] = {
  server_name = function() return tls_state.name end,
  parse_pem_cert = function(pem) return "cert:" .. pem end,
  parse_pem_priv_key = function(pem) return "key:" .. pem end,
  clear_certs = function() return true end,
  set_cert = function(c) tls_state.cert = c; return true end,
  set_priv_key = function(k) tls_state.key = k; return true end,
}
package.loaded["ngx.ssl.clienthello"] = {
  get_client_hello_server_name = function() return tls_state.name end,
  set_protocols = function() return true end,
}

local probehealth = require("edgeweir.probehealth")
local router = require("edgeweir.router")
local store = require("edgeweir.store")
local tls = require("edgeweir.tls")

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

test("is_request: GET and HEAD of /.edgeweir/health only", function()
  eq(probehealth.is_request("GET", "/.edgeweir/health"), true)
  eq(probehealth.is_request("HEAD", "/.edgeweir/health"), true)
  eq(probehealth.is_request("POST", "/.edgeweir/health"), false)
  eq(probehealth.is_request("OPTIONS", "/.edgeweir/health"), false)
  eq(probehealth.is_request("GET", "/.edgeweir/health/"), false)
  eq(probehealth.is_request("GET", "/.edgeweir/healthz"), false)
  eq(probehealth.is_request("GET", "/.edgeweir/HEALTH"), false)
  eq(probehealth.is_request("GET", "/x/.edgeweir/health"), false)
  eq(probehealth.is_request("GET", "/"), false)
  eq(probehealth.is_request("GET", nil), false)
end)

test("is_health_sni: health.edgeweir.invalid in any case, or no SNI", function()
  eq(probehealth.is_health_sni(nil), true)
  eq(probehealth.is_health_sni(""), true)
  eq(probehealth.is_health_sni("health.edgeweir.invalid"), true)
  eq(probehealth.is_health_sni("HEALTH.Edgeweir.INVALID"), true)
  eq(probehealth.is_health_sni("demo.test"), false)
  eq(probehealth.is_health_sni("health.edgeweir.invalid.example.com"), false)
  eq(probehealth.is_health_sni("x.health.edgeweir.invalid"), false)
end)

test("material: complete certificate material only", function()
  local m = { chain_pem = "C", private_key_pem = "K", fingerprint = "F" }
  eq(probehealth.material({ health_certificate = m }), m)
  eq(probehealth.material(nil), nil)
  eq(probehealth.material({}), nil)
  eq(probehealth.material({ health_certificate = { chain_pem = "C", private_key_pem = "K" } }), nil)
  eq(probehealth.material({ health_certificate = { chain_pem = "", private_key_pem = "K", fingerprint = "F" } }), nil)
  eq(probehealth.material({ health_certificate = "C" }), nil)
end)

-- access runs the edge access phase with a stand-in ngx; anything past the
-- health checks (header reads, site lookup) is not stubbed and fails.
local function access(method, var)
  local runtime = ngx
  local out = { header = {}, body = {} }
  var.uri = var.uri or "/"
  _G.ngx = setmetatable({
    var = var,
    ctx = {},
    header = out.header,
    req = { get_method = function() return method end },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    exit = function(code) out.exit = code end,
  }, { __index = runtime })
  local ok, err = pcall(router.access)
  out.status = rawget(ngx, "status")
  _G.ngx = runtime
  out.ok, out.err = ok, err
  out.body = table.concat(out.body)
  return out
end

test("the health request is answered for any Host before the site logic", function()
  for _, case in ipairs({
    { "GET", { scheme = "http", host = "unknown.test", uri = "/.edgeweir/health" } },
    { "HEAD", { scheme = "http", host = "health.edgeweir.invalid", uri = "/.edgeweir/health" } },
    { "GET", { scheme = "https", host = "demo.test", ssl_server_name = "demo.test", uri = "/.edgeweir/health" } },
    { "GET", { scheme = "https", host = "health.edgeweir.invalid", ssl_server_name = "health.edgeweir.invalid", uri = "/.edgeweir/health" } },
    { "GET", { scheme = "https", host = "10.0.0.1", uri = "/.edgeweir/health" } }, -- no SNI
    -- A loop (CDN-Loop) or a banned client would be rejected later on.
    { "GET", { scheme = "http", host = "demo.test", uri = "/.edgeweir/health", http_cdn_loop = "edgeweir-0000000000000000" } },
  }) do
    local out = access(case[1], case[2])
    assert(out.ok, out.err)
    eq(out.status, 200, case[2].host .. " status")
    eq(out.body, "ok", "body")
    eq(out.header["Content-Type"], "text/plain")
    eq(out.header["Cache-Control"], "no-store")
    eq(out.exit, ngx.HTTP_OK)
  end
end)

test("connections with the health SNI or without SNI reach only the health path", function()
  for _, case in ipairs({
    { "GET", { scheme = "https", host = "demo.test", ssl_server_name = "health.edgeweir.invalid", uri = "/" } },
    { "GET", { scheme = "https", host = "demo.test", uri = "/index.html" } }, -- no SNI
    { "POST", { scheme = "https", host = "health.edgeweir.invalid", ssl_server_name = "health.edgeweir.invalid", uri = "/.edgeweir/health" } },
    { "GET", { scheme = "https", host = "health.edgeweir.invalid", ssl_server_name = "HEALTH.EDGEWEIR.INVALID", uri = "/.well-known/acme-challenge/abc" } },
  }) do
    local out = access(case[1], case[2])
    assert(out.ok, out.err)
    eq(out.status, 421, case[2].uri .. " status")
    eq(out.header["X-Edgeweir-Error"], "sni-host-mismatch")
  end
end)

test("other requests go on to the site logic", function()
  -- Not stubbed: reaching the header reads proves the request went on.
  for _, var in ipairs({
    { scheme = "http", host = "demo.test", uri = "/" },
    { scheme = "https", host = "demo.test", ssl_server_name = "demo.test", uri = "/.edgeweir/challenge/verify" },
  }) do
    local out = access("GET", var)
    eq(out.ok, false, var.uri)
    assert(tostring(out.err):find("get_headers", 1, true), "stopped elsewhere: " .. tostring(out.err))
    eq(out.status, nil, var.uri .. " answered by the health checks")
  end
end)

-- tls_phase runs a TLS hook with SNI name; it returns whether the
-- handshake was aborted and the certificate set.
local function tls_phase(fn, name)
  tls_state.name, tls_state.cert, tls_state.key = name, nil, nil
  local runtime = ngx
  local aborted = false
  _G.ngx = setmetatable({ exit = function(code) aborted = code == runtime.ERROR end }, { __index = runtime })
  local ok, err = pcall(fn)
  _G.ngx = runtime
  assert(ok, err)
  return aborted, tls_state.cert, tls_state.key
end

test("TLS: the health certificate of the site table for the health SNI and no SNI", function()
  -- Without a health certificate in the table every such handshake fails.
  assert(store.replace({ revision = "1", content_hash = "a", sites = {} }))
  eq((tls_phase(tls.client_hello, nil)), true, "no SNI without a health certificate")
  eq((tls_phase(tls.certificate, "health.edgeweir.invalid")), true)

  assert(store.replace({ revision = "2", content_hash = "b", sites = {},
    health_certificate = { chain_pem = "HEALTH-CHAIN", private_key_pem = "HEALTH-KEY", fingerprint = "f1" } }))
  for _, name in ipairs({ "health.edgeweir.invalid", "Health.Edgeweir.Invalid" }) do
    eq((tls_phase(tls.client_hello, name)), false, name .. ": client hello")
    local aborted, cert, key = tls_phase(tls.certificate, name)
    eq(aborted, false, name)
    eq(cert, "cert:HEALTH-CHAIN")
    eq(key, "key:HEALTH-KEY")
  end
  eq((tls_phase(tls.client_hello, nil)), false, "no SNI")
  local aborted, cert = tls_phase(tls.certificate, nil)
  eq(aborted, false)
  eq(cert, "cert:HEALTH-CHAIN")
  -- Names of no site still abort.
  eq((tls_phase(tls.client_hello, "unknown.test")), true, "unknown SNI")
  eq((tls_phase(tls.certificate, "unknown.test")), true)

  -- An invalid health certificate is ignored, the table still installs.
  assert(store.replace({ revision = "3", content_hash = "c", sites = {}, health_certificate = { chain_pem = "x" } }))
  eq(store.config().health_certificate, nil)
  eq((tls_phase(tls.client_hello, nil)), true)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
