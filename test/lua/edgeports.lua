-- Proto v0.23.0 in the HTTP data plane: the listener ports a site is
-- served on (edge-ports-v1), the HTTPS redirect's status, port and
-- excluded domains, ip.peer and the trusted proxies of the client address
-- setting (client-ip-v1).
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_health 1m' --shdict 'edgeweir_policy_logs 1m' \
--         --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' test/lua/edgeports.lua
local policy = require("edgeweir.policy")
local store = require("edgeweir.store")
local expressions = require("edgeweir.expressions")

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

local TRUE = { op = "literal", value_type = "boolean", value = "true" }

local function site(extra, cfg)
  local s = {
    id = "s1", cache_zone = "edgeweir_default", load_balance = "weighted_random", certificate_id = "c",
    domains = { { name = "a.test" }, { name = "b.test" }, { name = "w.test", wildcard = true }, { name = "x.w.test" } },
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
    tls = { force_https = true, minimum_version = "1.2", cipher_profile = "modern" },
  }
  for k, v in pairs(extra or {}) do s[k] = v end
  return store.prepare(s, cfg or policy.prepare_config({}))
end

-- access runs the access phase of one plain HTTP request with a fake ngx.
local function access(s, req)
  local real = ngx
  local vars = {
    host = req.host or "a.test", scheme = req.scheme or "http", remote_addr = req.remote_addr or "192.0.2.1",
    realip_remote_addr = req.peer or req.remote_addr or "192.0.2.1", server_port = req.port or "80",
    server_protocol = "HTTP/1.1", edgeweir_request_id = "req-1", uri = req.uri or "/p", args = req.args,
    request_uri = (req.uri or "/p") .. (req.args and ("?" .. req.args) or ""),
  }
  local headers = {}
  local fake = setmetatable({
    ctx = {}, var = vars, header = {},
    req = {
      get_method = function() return "GET" end,
      start_time = function() return 1791331200 end,
      set_header = function(k, v) headers[k:lower()] = v end,
      clear_header = function(k) headers[k:lower()] = nil end,
    },
  }, { __index = real })
  _G.ngx = fake
  local ok, result = pcall(policy.access, s, {})
  _G.ngx = real
  if not ok then error(result, 0) end
  return result, headers
end

test("HTTPS redirect: status and port of the site, 301 to 443 by default", function()
  local r = access(site(), { host = "a.test", uri = "/p", args = "q=1" })
  eq(r.status, 301)
  eq(r.location, "https://a.test/p?q=1")
  r = access(site({ tls = { force_https = true, redirect_status = 308, redirect_port = 9443 } }), { host = "b.test", port = "8081" })
  eq(r.status, 308)
  eq(r.location, "https://b.test:9443/p")
  for _, status in ipairs({ 302, 303, 307 }) do
    r = access(site({ tls = { force_https = true, redirect_status = status } }), {})
    eq(r.status, status)
  end
  eq(policy.https_redirect({ redirect_port = 443 }, "a.test", "/").location, "https://a.test/", "443 stays out of the URL")
  eq(policy.https_redirect(nil, "a.test", "/x").status, 301)
end)

test("HTTPS redirect: excluded domains, exact and wildcard; a config rule still redirects", function()
  local s = site({ tls = { force_https = true, redirect_excluded = { "*.w.test", "b.test" } } })
  eq(access(s, { host = "b.test" }), nil, "excluded exact name")
  eq(access(s, { host = "y.w.test" }), nil, "excluded through the wildcard")
  eq(access(s, { host = "x.w.test" }).status, 301, "an exact name of the site wins over its wildcard")
  eq(access(s, { host = "a.test" }).status, 301)
  local rule = site({
    tls = { force_https = false, redirect_excluded = { "b.test" }, redirect_status = 307 },
    rules = { { id = "r", phase = "config", expression = TRUE, action = { kind = "config", force_https = true } } },
  })
  local r = access(rule, { host = "b.test" })
  eq(r and r.status, 307, "a config rule's force_https redirects an excluded domain with the site's status")
  eq(access(s, { host = "b.test", scheme = "https" }), nil, "HTTPS requests are never redirected")
end)

test("serves_port: the site's ports only; every listener without ports", function()
  local s = site({ ports = { 80, 8081, 9443 } })
  eq(store.serves_port(s, "8081"), true)
  eq(store.serves_port(s, 9443), true)
  eq(store.serves_port(s, "443"), false)
  eq(store.serves_port(s, nil), false)
  eq(store.serves_port(site(), "12345"), true, "no ports")
end)

test("ip.peer: the TCP peer before realip; the local listeners' peer is ip.src", function()
  local peer = { op = "field", field = "ip.peer", value_type = "ip" }
  local s = site({ rules = { { id = "p", phase = "request-transform", expression = TRUE,
    action = { kind = "request_header", header = "x-peer", target = { op = "call", field = "to_string", value_type = "string", children = { peer } } } } } })
  eq(s._peer, true, "the site reads ip.peer")
  eq(site()._peer, nil, "no work for sites that do not")
  local _, h = access(s, { remote_addr = "203.0.113.9", peer = "10.0.0.2", scheme = "https" })
  eq(h["x-peer"], "10.0.0.2")
  _, h = access(s, { remote_addr = "127.0.0.1", peer = "unix:", scheme = "https" })
  eq(h["x-peer"], "127.0.0.1")
  local block = site({ rules = { { id = "b", phase = "waf-custom", action = { kind = "block", status_code = 403 },
    expression = { op = "in", field = "ip.peer", value_type = "ip", values = { "10.0.0.0/8" } } } }, tls = { force_https = false } })
  eq(access(block, { remote_addr = "203.0.113.9", peer = "10.0.0.2" }).status, 403)
  eq(access(block, { remote_addr = "10.0.0.2", peer = "203.0.113.9" }), nil, "ip.src is another field")
end)

test("trusted proxies: matched by the site table's setting", function()
  local cfg = policy.prepare_config({})
  cfg.trusted = expressions.ip_set({ "10.0.0.0/8", "2001:db8::/32" })
  local s = site({}, cfg)
  eq(store.trusted_proxy(s, "10.1.2.3"), true)
  eq(store.trusted_proxy(s, "2001:db8::5"), true)
  eq(store.trusted_proxy(s, "192.0.2.1"), false)
  eq(store.trusted_proxy(site(), "10.1.2.3"), false, "no setting")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
