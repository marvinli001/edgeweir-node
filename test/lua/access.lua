-- Access control (Site.access_control, proto v0.28.0, feature
-- access-control-v1, ADR-0039): every vector of the console's
-- access_vectors.json, then the edge's order and exemptions through
-- edgeweir.router (site lists before the bans, block lists, geo, CORS
-- preflights answered at the edge, hotlink, user agents, WebSocket origins,
-- challenges and CC bans), the response headers of the header filter and of
-- nginx's own error pages (CORS, Vary, kept origin headers, security headers
-- that rules override) and the WebSocket idle timeout.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_policy_logs 1m' --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' \
--     --shdict 'edgeweir_bans 1m' --shdict 'edgeweir_cc 1m' --shdict 'edgeweir_challenge 1m' \
--     --shdict 'edgeweir_purge 1m' --shdict 'edgeweir_tags 1m' test/lua/access.lua
local cjson = require("cjson.safe")
local access = require("edgeweir.access")
local store = require("edgeweir.store")
local router = require("edgeweir.router")
local origin = require("edgeweir.origin")
local geoip = require("edgeweir.geoip")
local bans = require("edgeweir.bans")
local cc = require("edgeweir.cc")

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

local vectors = assert(cjson.decode(assert(io.open("/t/access_vectors.json")):read("*a")))

-- JSON null is cjson.null.
local function null(v)
  if v == cjson.null then return nil end
  return v
end

local checked = 0
local function check(got, want, msg)
  checked = checked + 1
  eq(got, null(want), msg)
end

test("vectors: host forms", function()
  for _, v in ipairs(vectors.hostForms) do check(access.host_form_matches(v.form, v.host), v.match, v.form .. " " .. v.host) end
  for _, v in ipairs(vectors.normalizeHostForm) do check(access.normalize_host_form(v.input), v.output, v.input) end
end)

test("vectors: Referer hosts", function()
  for _, v in ipairs(vectors.refererHost) do check(access.referer_host(v.input), v.host, v.input) end
end)

test("vectors: origins", function()
  for _, v in ipairs(vectors.normalizeOriginForm) do check(access.normalize_origin_form(v.input, v.star), v.output, v.input) end
  for _, v in ipairs(vectors.normalizeOrigin) do check(access.normalize_origin(v.input), v.output, v.input) end
  for _, v in ipairs(vectors.originForms) do check(access.origin_form_matches(v.form, v.origin), v.match, v.form .. " " .. v.origin) end
end)

test("vectors: path scopes", function()
  for _, v in ipairs(vectors.pathScope) do check(access.path_in_scope(v.path, v.prefixes, v.excluded), v.result, v.path) end
end)

test("vectors: user agents", function()
  for _, v in ipairs(vectors.userAgents) do
    check(access.user_agent_decision(access.compile_user_agents(v.rules), v.ua), v.result, cjson.encode(v))
  end
  for _, v in ipairs(vectors.validUserAgentPattern) do check(access.valid_user_agent_pattern(v.pattern), v.valid, v.pattern) end
end)

test("vectors: hotlink", function()
  for _, v in ipairs(vectors.hotlink) do
    local c = v.cfg
    local compiled = access.compile_hotlink({
      allow_empty = c.allowEmpty, allow_site_domains = c.allowSiteDomains, allowed = c.allowed, denied = c.denied,
      check_origin = c.checkOrigin, extensions = c.extensions, path_prefixes = c.pathPrefixes,
      exclude_path_prefixes = c.excludePathPrefixes, redirect_url = c.redirectUrl,
    })
    local hosts = {}
    for _, h in ipairs(v.siteHosts) do hosts[h] = true end
    local r = v.req
    check(access.hotlink_decision(compiled, r.path, r.extension, r.referer, r.origin, function(h) return hosts[h] == true end), v.result, v.name)
  end
end)

test("vectors: geo", function()
  for _, v in ipairs(vectors.geo) do
    local c = v.cfg
    local compiled = access.compile_geo({ allow_only = c.allowOnly, countries = c.countries, subdivisions = c.subdivisions,
      asns = c.asns, path_prefixes = c.pathPrefixes, except_path_prefixes = c.exceptPathPrefixes })
    check(access.geo_decision(compiled, v.geo), v.result, cjson.encode(v))
  end
end)

test("vectors: CORS and WebSocket origins", function()
  for _, v in ipairs(vectors.cors) do
    local compiled = access.compile_cors({ allowed_origins = v.cfg.allowedOrigins, allow_credentials = v.cfg.allowCredentials, allowed_methods = { "GET" } })
    check(access.cors_allow_origin(compiled, v.origin), v.result, cjson.encode(v))
  end
  for _, v in ipairs(vectors.websocket) do
    check(access.websocket_origin_allowed(access.compile_websocket({ origins = v.origins }).origins, v.origin), v.result, cjson.encode(v))
  end
end)

test("vectors: every one was checked", function()
  local total = 0
  for _, list in pairs(vectors) do total = total + #list end
  eq(checked, total, "vectors checked")
  assert(total >= 190, "vectors read: " .. total)
end)

-- The site table: ac.test (and *.ac.test) with every part, other.test, the
-- hotlink redirect of redir.test, a CORS that hands preflights to the
-- origin, Under Attack and CC with site allow lists.
local SITE_BLOCK = { "203.0.113.0/24", "198.51.100.10/32" }
local SITE_ALLOW = { "192.0.2.50/32", "192.0.2.60/32", "203.0.113.5/32", "198.51.100.66/32" }

local function site(id, domains, extra)
  local s = { id = id, cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random",
    domains = domains, origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } } }
  for k, v in pairs(extra or {}) do s[k] = v end
  return s
end

local SECURITY = { nosniff = true, frame_options = "SAMEORIGIN", referrer_policy = "no-referrer", permissions_policy = "camera=()",
  hide_server = true, remove_powered_by = true }

local function full()
  return {
    block_list_ids = { "site-block" }, allow_list_ids = { "site-allow" },
    hotlink = { allow_empty = true, allow_site_domains = true, allowed = { "friend.test" }, denied = { "bad.ac.test" },
      extensions = { "png" }, path_prefixes = { "/dl/" } },
    user_agents = { rules = { { pattern = "*Googlebot*", allow = true }, { pattern = "*bot*" }, { pattern = "*curl*" } },
      exclude_path_prefixes = { "/robots.txt" } },
    cors = { allowed_origins = { "https://app.test", "https://*.app.test" }, allow_credentials = true, allowed_methods = { "GET", "POST" },
      allowed_headers = { "content-type", "x-token" }, exposed_headers = { "X-Total" }, max_age_seconds = 600, path_prefixes = { "/api/" } },
    geo = { countries = { "CN" }, path_prefixes = { "/geo/" } },
    websocket = { origins = { "https://chat.test" }, idle_timeout_seconds = 120 },
    security_headers = SECURITY,
  }
end

local function install(revision)
  assert(store.replace({ revision = revision, content_hash = revision,
    ip_lists = {
      { id = "platform-allow", kind = "allow", platform = true, entries = { "198.51.100.10/32" } },
      { id = "platform-block", kind = "block", platform = true, entries = { "198.51.100.66/32" } },
      { id = "site-block", kind = "collection", entries = SITE_BLOCK },
      { id = "site-allow", kind = "collection", entries = SITE_ALLOW },
    },
    sites = {
      site("ac", { { name = "ac.test" }, { name = "ac.test", wildcard = true } }, { access_control = full() }),
      site("other", { { name = "other.test" } }),
      site("redir", { { name = "redir.test" } }, { access_control = { hotlink = { redirect_url = "/hotlink.png?v=1" } } }),
      site("pto", { { name = "pto.test" } }, { access_control = { cors = { allowed_origins = { "*" }, allowed_methods = { "GET" },
        preflight_to_origin = true, keep_origin_headers = true, echo_request_headers = true }, user_agents = { rules = { { pattern = "*curl*" } } } } }),
      site("pto2", { { name = "pto2.test" } }, { access_control = { cors = { allowed_origins = { "https://app.test" }, allow_credentials = true,
        allowed_methods = { "GET", "PUT" }, allowed_headers = { "content-type" }, exposed_headers = { "X-Total" }, max_age_seconds = 300,
        preflight_to_origin = true } } }),
      site("guard", { { name = "guard.test" } }, { protection = { under_attack = true, under_attack_challenge = "js", pass_ttl = 3600 },
        access_control = { allow_list_ids = { "site-allow" } } }),
      site("cc", { { name = "cc.test" } }, { protection = { under_attack_challenge = "js", pass_ttl = 3600, cc = { ip_qps = 1, ip_ban = 60 } },
        access_control = { allow_list_ids = { "site-allow" } } }),
    } }))
end
install("1")

-- header_table is a case-insensitive response header table (ngx.header);
-- raw holds the values by lowercase name.
local function header_table(init)
  local raw = {}
  for k, v in pairs(init or {}) do raw[k:lower()] = v end
  return setmetatable({}, {
    __index = function(_, k) return raw[k:lower()] end,
    __newindex = function(_, k, v) raw[k:lower()] = v end,
  }), raw
end

-- request runs the edge access phase (edgeweir.router.access) with a
-- stand-in ngx: req = { host, uri, method, addr, headers, var, local }. It
-- returns { passed, status, code, header (lowercase), location, ctx, err }.
local function request(req)
  local runtime = ngx
  local header, raw = header_table()
  local out = { header = raw, body = {} }
  local headers = {}
  for k, v in pairs(req.headers or {}) do headers[k:lower()] = v end
  local uri = req.uri or "/"
  local var = {
    scheme = "http", host = req.host or "ac.test", uri = uri, request_uri = uri, server_port = "80",
    remote_addr = req.addr or "192.0.2.1", edgeweir_request_id = "req-1", edgeweir_local = req["local"] and "1" or "",
    http_origin = headers.origin, http_access_control_request_method = headers["access-control-request-method"],
    http_upgrade = headers.upgrade, http_user_agent = headers["user-agent"],
  }
  local ctx = {}
  local fake = setmetatable({
    var = var, ctx = ctx, header = header, is_subrequest = false,
    req = {
      get_method = function() return req.method or "GET" end,
      get_headers = function() local copy = {}; for k, v in pairs(headers) do copy[k] = v end; return copy end,
      clear_header = function(k) headers[k:lower()] = nil end,
      set_header = function(k, v) headers[k:lower()] = v end,
      start_time = function() return 0 end,
    },
    resp = { get_headers = function() local copy = {}; for k, v in pairs(raw) do copy[k] = v end; return copy end },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    exit = function(code) out.exit = code; error("exit", 0) end,
    redirect = function(location, status) out.location, out.redirect = location, status; error("exit", 0) end,
    log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(router.access)
  _G.ngx = runtime
  out.passed = ok
  out.err = not ok and err ~= "exit" and err or nil
  out.status = rawget(fake, "status") or out.redirect or out.exit
  out.code = raw["x-edgeweir-error"]
  out.ctx = ctx
  out.body = table.concat(out.body)
  return out
end

local function passes(req, msg)
  local out = request(req)
  assert(out.passed, (msg or "request") .. ": answered " .. tostring(out.status) .. " " .. tostring(out.code) .. " " .. tostring(out.err))
  return out
end

local function denied(req, status, code, msg)
  local out = request(req)
  assert(not out.passed and not out.err, (msg or "request") .. ": passed or failed: " .. tostring(out.err))
  eq(out.status, status, (msg or "request") .. " status")
  eq(out.code, code, (msg or "request") .. " code")
  return out
end

test("site lists: block lists 403 ip-blocked; site allow lists and platform allow lists skip them", function()
  denied({ addr = "203.0.113.9" }, 403, "ip-blocked")
  denied({ addr = "203.0.113.9", host = "www.ac.test" }, 403, "ip-blocked", "wildcard domain")
  passes({ addr = "203.0.113.5" }, "on a site block and a site allow list")
  passes({ addr = "198.51.100.10" }, "platform allow list")
  passes({ addr = "192.0.2.1" }, "on neither")
  passes({ addr = "203.0.113.9", host = "other.test" }, "another site")
  -- The page of a 403 is the error page.
  local out = denied({ addr = "203.0.113.9" }, 403, "ip-blocked")
  eq(out.header["content-type"], "text/html; charset=utf-8")
end)

test("site allow lists do not skip platform block lists and platform bans", function()
  denied({ addr = "198.51.100.66" }, 403, "policy-denied", "platform block list")
  bans.forget()
  local now = ngx.now()
  assert(bans.replace({ sequence = "1", bans = {
    { id = "b1", cidr = "192.0.2.50/32", scope = "site", site_id = "ac", kind = "m", expires_at = now + 3600 },
    { id = "b2", cidr = "192.0.2.51/32", scope = "site", site_id = "ac", kind = "m", expires_at = now + 3600 },
    { id = "b3", cidr = "192.0.2.60/32", scope = "platform", kind = "m", expires_at = now + 3600 },
  } }))
  denied({ addr = "192.0.2.51" }, 403, "ip-banned", "site ban")
  passes({ addr = "192.0.2.50" }, "site ban of a site-allowed client")
  denied({ addr = "192.0.2.60" }, 403, "ip-banned", "platform ban of a site-allowed client")
  passes({ addr = "192.0.2.51", host = "other.test" }, "site ban of another site")
  assert(bans.replace({ sequence = "2", bans = {} }))
end)

test("geo: 403 geo-denied in scope, a failing lookup 503 policy-unavailable, none outside the scope", function()
  local real = geoip.lookup
  local lookups = 0
  geoip.lookup = function(addr)
    lookups = lookups + 1
    if addr == "192.0.2.99" then return nil end
    if addr == "192.0.2.77" then return { country = "CN", subdivision = "GD", asnum = 4134 } end
    return { country = "NZ", subdivision = "", asnum = 0 }
  end
  local ok, err = pcall(function()
    denied({ addr = "192.0.2.77", uri = "/geo/x" }, 403, "geo-denied")
    passes({ addr = "192.0.2.78", uri = "/geo/x" }, "another country")
    denied({ addr = "192.0.2.99", uri = "/geo/x" }, 503, "policy-unavailable", "lookup failure")
    lookups = 0
    passes({ addr = "192.0.2.99", uri = "/other" }, "outside the scope")
    eq(lookups, 0, "no lookup outside the scope")
    passes({ addr = "192.0.2.50", uri = "/geo/x" }, "site allow list")
    eq(lookups, 0, "no lookup for site-allowed clients")
  end)
  geoip.lookup = real
  assert(ok, err)
end)

test("CORS preflights: 204 at the edge with the preflight headers, 403 for other origins", function()
  local preflight = { method = "OPTIONS", uri = "/api/items", headers = { origin = "https://x.app.test",
    ["access-control-request-method"] = "PUT", ["access-control-request-headers"] = "x-other" } }
  local out = request(preflight)
  eq(out.status, 204)
  local h = out.header
  eq(h["access-control-allow-origin"], "https://x.app.test")
  eq(h["access-control-allow-credentials"], "true")
  eq(h["access-control-allow-methods"], "GET, POST", "the list, though PUT was asked")
  eq(h["access-control-allow-headers"], "content-type, x-token")
  eq(h["access-control-max-age"], "600")
  eq(h["vary"], "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
  eq(h["cache-control"], "no-store")
  eq(out.ctx.edgeweir_preflight, true)
  -- Answered before hotlink, user agents, auth, rules and challenges: a
  -- denied user agent still gets its preflight.
  preflight.headers["user-agent"] = "curl/8"
  eq(request(preflight).status, 204, "a denied user agent")
  preflight.addr = "192.0.2.50"
  eq(request(preflight).status, 204, "site allow lists do not skip CORS")
  preflight.addr = nil
  preflight.headers.origin = "https://evil.test"
  out = denied(preflight, 403, "cors-origin-denied")
  eq(out.header["access-control-allow-origin"], nil)
  preflight.headers.origin = "null"
  denied(preflight, 403, "cors-origin-denied", "null")
  -- Site block lists come first.
  preflight.headers.origin = "https://app.test"
  preflight.addr = "203.0.113.9"
  denied(preflight, 403, "ip-blocked")
  preflight.addr = nil
  -- Not preflights: outside the scope, without Access-Control-Request-Method,
  -- other methods.
  passes({ method = "OPTIONS", uri = "/static/x", headers = { origin = "https://app.test", ["access-control-request-method"] = "GET" } })
  passes({ method = "OPTIONS", uri = "/api/x", headers = { origin = "https://app.test" } })
  passes({ method = "GET", uri = "/api/x", headers = { origin = "https://evil.test", ["access-control-request-method"] = "GET" } })
  -- Handed to the origin, through the later steps (a user agent rule).
  passes({ host = "pto.test", method = "OPTIONS", uri = "/x", headers = { origin = "https://a.test", ["access-control-request-method"] = "GET" } })
  denied({ host = "pto.test", method = "OPTIONS", uri = "/x", headers = { origin = "https://a.test", ["access-control-request-method"] = "GET",
    ["user-agent"] = "curl/8" } }, 403, "ua-denied")
end)

test("CORS preflights: echoed request headers, none without them", function()
  local s = store.site_current("ac")
  local cors = access.compile_cors({ allowed_origins = { "*" }, allowed_methods = { "GET" }, echo_request_headers = true, allowed_headers = { "a" } })
  local runtime = ngx
  local function answer(requested)
    local header, raw = header_table()
    local exit
    _G.ngx = setmetatable({ header = header, ctx = {}, exit = function(c) exit = c end }, { __index = runtime })
    access.preflight(cors, "*", requested)
    _G.ngx = runtime
    eq(exit, ngx.HTTP_NO_CONTENT)
    return raw
  end
  eq(answer("x-a, x-b")["access-control-allow-headers"], "x-a, x-b")
  eq(answer(nil)["access-control-allow-headers"], nil, "nothing to echo")
  eq(answer(nil)["access-control-allow-credentials"], nil)
  eq(answer(nil)["access-control-allow-origin"], "*")
  assert(s._access.cors.credentials)
end)

test("hotlink: 403 hotlink-denied, own domains, empty referers, scope, exemptions", function()
  local img = function(referer, extra)
    local req = { uri = "/i/a.png", headers = { referer = referer } }
    for k, v in pairs(extra or {}) do req[k] = v end
    return req
  end
  denied(img("https://evil.test/page"), 403, "hotlink-denied")
  passes(img("https://www.ac.test/page"), "a domain of the site (wildcard)")
  passes(img("https://ac.test/"), "a domain of the site")
  denied(img("https://bad.ac.test/"), 403, "hotlink-denied", "denied wins over own domains")
  denied(img("https://other.test/"), 403, "hotlink-denied", "another site's domain")
  passes(img("https://friend.test/"), "allowed")
  passes(img(nil), "no Referer")
  denied(img("android-app://x/"), 403, "hotlink-denied", "unparseable")
  passes({ uri = "/i/a.css", headers = { referer = "https://evil.test/" } }, "another extension")
  denied({ uri = "/dl/a.zip", headers = { referer = "https://evil.test/" } }, 403, "hotlink-denied", "path prefix")
  passes(img("https://evil.test/", { addr = "192.0.2.50" }), "site allow list")
  denied(img("https://evil.test/", { addr = "198.51.100.10" }), 403, "hotlink-denied", "platform allow lists do not skip it")
  -- HTTP-01 requests for the origin and the local listeners skip steps 4-8.
  passes({ uri = "/.well-known/acme-challenge/tok-1", addr = "203.0.113.9", headers = { referer = "https://evil.test/" } }, "HTTP-01")
  passes(img("https://evil.test/", { ["local"] = true, addr = "203.0.113.9" }), "local listener")
end)

test("hotlink: 302 to the site's target with Cache-Control: no-store, the target itself unchecked", function()
  local out = request({ host = "redir.test", uri = "/a.png", headers = { referer = "https://evil.test/" } })
  eq(out.status, 302)
  eq(out.location, "/hotlink.png?v=1")
  eq(out.header["cache-control"], "no-store")
  eq(out.code, "hotlink-denied")
  passes({ host = "redir.test", uri = "/hotlink.png", headers = { referer = "https://evil.test/" } }, "the target")
  eq(request({ host = "redir.test", uri = "/a.png" }).status, 302, "no empty referers allowed")
end)

test("user agents: an allow rule beats deny rules, excluded paths, exemptions", function()
  passes({ headers = { ["user-agent"] = "Mozilla/5.0 (compatible; Googlebot/2.1) curl" } }, "allow beats deny")
  denied({ headers = { ["user-agent"] = "curl/8.5.0" } }, 403, "ua-denied")
  denied({ headers = { ["user-agent"] = "SomeBOT/1" } }, 403, "ua-denied", "case-insensitive")
  passes({ headers = { ["user-agent"] = "Mozilla/5.0" } })
  passes({}, "no User-Agent")
  passes({ uri = "/robots.txt", headers = { ["user-agent"] = "curl/8" } }, "excluded path")
  passes({ addr = "192.0.2.50", headers = { ["user-agent"] = "curl/8" } }, "site allow list")
  -- Several headers are joined with ", " (http.user_agent).
  denied({ headers = { ["user-agent"] = { "x", "curl" } } }, 403, "ua-denied", "joined")
end)

test("WebSocket origins: 403 websocket-origin-denied; site allow lists checked too, local listeners not", function()
  local ws = function(o, extra)
    local req = { uri = "/ws", headers = { upgrade = "websocket", connection = "upgrade", origin = o } }
    for k, v in pairs(extra or {}) do req[k] = v end
    return req
  end
  local out = passes(ws("https://chat.test"))
  denied(ws("https://evil.test"), 403, "websocket-origin-denied")
  denied(ws(nil), 403, "websocket-origin-denied", "no Origin")
  denied(ws("null"), 403, "websocket-origin-denied", "null")
  denied(ws("https://evil.test", { addr = "192.0.2.50" }), 403, "websocket-origin-denied", "site allow list")
  passes(ws("https://evil.test", { ["local"] = true }), "local listener")
  passes(ws("https://evil.test", { host = "other.test" }), "another site")
  assert(out.passed)
end)

test("challenges and CC bans: site allow lists exempt", function()
  local out = request({ host = "guard.test" })
  assert(not out.passed and not out.err, "Under Attack challenged: " .. tostring(out.err))
  eq(out.code, "challenge-unavailable", "challenged (without keys here)")
  passes({ host = "guard.test", addr = "192.0.2.50" }, "site allow list")
  local count, check_ip = cc.count, cc.check_ip
  local banned = 0
  cc.count = function() return 99, 1, ngx.now() end
  cc.check_ip = function() banned = banned + 1; return true end
  local ok, err = pcall(function()
    denied({ host = "cc.test" }, 403, "ip-banned", "over its rate")
    denied({ host = "cc.test", uri = "/.edgeweir/x" }, 403, "ip-banned", "reserved prefix")
    banned = 0
    passes({ host = "cc.test", addr = "192.0.2.50" }, "site allow list")
    local reserved = request({ host = "cc.test", addr = "192.0.2.50", uri = "/.edgeweir/x" })
    assert(not reserved.err and reserved.code ~= "ip-banned", "reserved prefix of a site-allowed client: " .. tostring(reserved.code) .. " " .. tostring(reserved.err))
    eq(banned, 0, "never checked")
  end)
  cc.count, cc.check_ip = count, check_ip
  assert(ok, err)
end)

-- respond runs the edge header filter (edgeweir.router.header_filter) for
-- a response of site host with headers; req = { origin, uri, ctx, cache,
-- method, acrm (Access-Control-Request-Method), request_headers }. It
-- returns the response headers by lowercase name and the status.
local function respond(host, headers, req)
  req = req or {}
  local runtime = ngx
  local header, raw = header_table(headers)
  local s = store.lookup_host(host)
  local ctx = req.ctx or { edgeweir_site = s }
  local fake = setmetatable({
    var = { scheme = "http", host = host, uri = req.uri or "/api/x", upstream_cache_status = req.cache or "HIT", edgeweir_site = s.id,
      edgeweir_no_cache = "1", http_origin = req.origin, http_access_control_request_method = req.acrm },
    ctx = ctx, header = header, status = req.status or 200, is_subrequest = false,
    resp = { get_headers = function() local copy = {}; for k, v in pairs(raw) do copy[k] = v end; return copy end },
    req = { get_method = function() return req.method or "GET" end, set_header = function() end, clear_header = function() end,
      get_headers = function() return req.request_headers or {} end },
    log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(router.header_filter)
  _G.ngx = runtime
  assert(ok, err)
  return raw, rawget(fake, "status")
end

test("CORS response headers: replaced for allowed origins, Vary: Origin, cache hits included", function()
  local origin_headers = { ["Access-Control-Allow-Origin"] = "*", ["Access-Control-Max-Age"] = "5", ["Vary"] = "Accept-Encoding",
    ["Content-Type"] = "application/json" }
  local h = respond("ac.test", origin_headers, { origin = "https://app.test" })
  eq(h["access-control-allow-origin"], "https://app.test")
  eq(h["access-control-allow-credentials"], "true")
  eq(h["access-control-expose-headers"], "X-Total")
  eq(h["access-control-max-age"], nil, "the origin's own removed")
  eq(h["vary"], "Accept-Encoding, Origin")
  eq(h["content-type"], "application/json")
  h = respond("ac.test", origin_headers, { origin = "https://evil.test", cache = "MISS" })
  eq(h["access-control-allow-origin"], nil, "another origin")
  eq(h["access-control-max-age"], nil)
  eq(h["vary"], "Accept-Encoding, Origin")
  h = respond("ac.test", { ["Content-Type"] = "text/plain" })
  eq(h["vary"], "Origin", "without Origin too")
  eq(h["access-control-allow-origin"], nil)
  eq(respond("ac.test", { Vary = "origin" }, { origin = "https://app.test" })["vary"], "origin", "already named")
  eq(respond("ac.test", { Vary = "*" })["vary"], "*")
  eq(respond("ac.test", { Vary = { "Accept-Encoding", "Cookie" } })["vary"], "Accept-Encoding, Cookie, Origin", "lines")
  -- Outside the scope nothing changes.
  h = respond("ac.test", origin_headers, { origin = "https://app.test", uri = "/static/x" })
  eq(h["access-control-allow-origin"], "*")
  eq(h["vary"], "Accept-Encoding")
end)

test("CORS response headers: keep_origin_headers keeps a response's own, else adds them", function()
  local h = respond("pto.test", { ["Access-Control-Allow-Origin"] = "https://mine.test", ["Access-Control-Allow-Methods"] = "GET" },
    { origin = "https://a.test", uri = "/x" })
  eq(h["access-control-allow-origin"], "https://mine.test")
  eq(h["access-control-allow-methods"], "GET")
  eq(h["vary"], "Origin")
  h = respond("pto.test", { ["Access-Control-Allow-Methods"] = "GET" }, { origin = "https://a.test", uri = "/x" })
  eq(h["access-control-allow-origin"], "*", "\"*\" without credentials")
  eq(h["access-control-allow-methods"], nil, "replaced without the origin's Access-Control-Allow-Origin")
end)

test("preflights the origin answers get the edge's preflight headers, with the origin's status", function()
  local pre = { method = "OPTIONS", origin = "https://app.test", acrm = "PUT", uri = "/x",
    request_headers = { ["access-control-request-headers"] = "x-a" } }
  local h, status = respond("pto2.test", { ["Access-Control-Allow-Origin"] = "*", ["Access-Control-Allow-Methods"] = "DELETE",
    ["Content-Type"] = "text/plain", Vary = "Accept-Encoding" }, pre)
  eq(status, 200, "the origin's status")
  eq(h["access-control-allow-origin"], "https://app.test")
  eq(h["access-control-allow-credentials"], "true")
  eq(h["access-control-allow-methods"], "GET, PUT")
  eq(h["access-control-allow-headers"], "content-type", "the list")
  eq(h["access-control-max-age"], "300")
  eq(h["access-control-expose-headers"], nil, "as the edge's own answer")
  eq(h["vary"], "Accept-Encoding, Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
  eq(h["content-type"], "text/plain")
  h = respond("pto2.test", {}, pre)
  eq(h["vary"], access.PREFLIGHT_VARY, "the edge's Vary")
  eq(respond("pto2.test", { Vary = "origin, access-control-request-method" }, pre)["vary"],
    "origin, access-control-request-method, Access-Control-Request-Headers", "names already there")
  eq(respond("pto2.test", { Vary = "*" }, pre)["vary"], "*")
  -- Another origin: the origin's CORS headers go, none come.
  h = respond("pto2.test", { ["Access-Control-Allow-Origin"] = "*" }, { method = "OPTIONS", origin = "https://evil.test", acrm = "PUT", uri = "/x" })
  eq(h["access-control-allow-origin"], nil)
  eq(h["access-control-allow-methods"], nil)
  eq(h["vary"], "Origin")
  -- Not preflights (no Access-Control-Request-Method, or GET): as before.
  h = respond("pto2.test", {}, { method = "OPTIONS", origin = "https://app.test", uri = "/x" })
  eq(h["access-control-allow-methods"], nil)
  eq(h["access-control-expose-headers"], "X-Total")
  eq(h["vary"], "Origin")
  h = respond("pto2.test", {}, { origin = "https://app.test", acrm = "PUT", uri = "/x" })
  eq(h["access-control-allow-methods"], nil)
  eq(h["access-control-allow-origin"], "https://app.test")
  -- keep_origin_headers: the origin's own when it sent
  -- Access-Control-Allow-Origin, else the edge's (headers echoed).
  local keep = { method = "OPTIONS", origin = "https://a.test", acrm = "GET", uri = "/x",
    request_headers = { ["access-control-request-headers"] = { "x-a", "x-b" } } }
  h = respond("pto.test", { ["Access-Control-Allow-Origin"] = "https://a.test", ["Access-Control-Allow-Methods"] = "POST" }, keep)
  eq(h["access-control-allow-methods"], "POST")
  eq(h["access-control-max-age"], nil)
  eq(h["vary"], "Origin")
  h = respond("pto.test", { ["Access-Control-Allow-Methods"] = "POST" }, keep)
  eq(h["access-control-allow-origin"], "*")
  eq(h["access-control-allow-methods"], "GET")
  eq(h["access-control-allow-headers"], "x-a, x-b", "echoed")
  eq(h["access-control-max-age"], "0")
  eq(h["vary"], access.PREFLIGHT_VARY)
  -- Sites answering preflights at the edge: one that reached the origin
  -- anyway (a local listener) keeps the usual headers.
  h = respond("ac.test", {}, { method = "OPTIONS", origin = "https://app.test", acrm = "GET" })
  eq(h["access-control-allow-methods"], nil)
  eq(h["access-control-expose-headers"], "X-Total")
end)

test("the preflight 204 keeps its headers through the header filter and gets the security headers", function()
  local out = request({ method = "OPTIONS", uri = "/api/items", headers = { origin = "https://app.test", ["access-control-request-method"] = "GET" } })
  eq(out.status, 204)
  out.ctx.edgeweir_original_path = "/api/items"
  local h = respond("ac.test", out.header, { origin = "https://app.test", ctx = out.ctx, cache = "" })
  eq(h["access-control-allow-methods"], "GET, POST")
  eq(h["access-control-max-age"], "600")
  eq(h["vary"], "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
  eq(h["x-content-type-options"], "nosniff")
end)

test("security headers replace the response's, hide Server and X-Powered-By; response rules win", function()
  local h = respond("ac.test", { Server = "openresty", ["X-Powered-By"] = "PHP/8", ["X-Frame-Options"] = "ALLOWALL", ["Referrer-Policy"] = "unsafe-url" })
  eq(h["x-content-type-options"], "nosniff")
  eq(h["x-frame-options"], "SAMEORIGIN")
  eq(h["referrer-policy"], "no-referrer")
  eq(h["permissions-policy"], "camera=()")
  eq(h["server"], nil)
  eq(h["x-powered-by"], nil)
  eq(respond("other.test", { Server = "openresty" })["server"], "openresty", "a site without them")
  -- Response rules run after them.
  local rules = {
    { id = "frame", phase = "response-transform", expression = { op = "literal", value_type = "boolean", value = "true" },
      action = { kind = "response_header", header = "x-frame-options", value = "DENY" } },
    { id = "sniff", phase = "response-transform", expression = { op = "literal", value_type = "boolean", value = "true" },
      action = { kind = "response_header", header = "x-content-type-options", remove = true } },
  }
  assert(store.replace({ revision = "2", content_hash = "2", ip_lists = {}, sites = {
    site("ruled", { { name = "ruled.test" } }, { rules = rules, access_control = { security_headers = SECURITY } }) } }))
  local s = store.lookup_host("ruled.test")
  h = respond("ruled.test", { Server = "openresty" }, { ctx = { edgeweir_site = s, edgeweir_policy = { values = {} } } })
  eq(h["x-frame-options"], "DENY", "a rule's value")
  eq(h["x-content-type-options"], nil, "removed by a rule")
  eq(h["referrer-policy"], "no-referrer")
  eq(h["server"], nil)
  install("3")
end)

test("nginx's own error pages get the CORS and security headers", function()
  local runtime = ngx
  local header, raw = header_table()
  local fake = setmetatable({
    var = { scheme = "http", host = "ac.test", uri = "/api/x", edgeweir_site = "ac", http_origin = "https://app.test", remote_addr = "192.0.2.1",
      edgeweir_request_id = "req-2" },
    ctx = {}, header = header, status = 502, is_subrequest = false,
    resp = { get_headers = function() local copy = {}; for k, v in pairs(raw) do copy[k] = v end; return copy end },
    req = { get_method = function() return "GET" end },
    print = function() end, exit = function() end, log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(router.error_page)
  _G.ngx = runtime
  assert(ok, err)
  eq(raw["x-edgeweir-error"], "origin-unreachable")
  eq(raw["access-control-allow-origin"], "https://app.test")
  eq(raw["vary"], "Origin")
  eq(raw["x-frame-options"], "SAMEORIGIN")
  eq(raw["server"], nil)
end)

test("WebSocket idle timeout: the site's, 3600 s by default, config rules' timeouts win", function()
  local s = store.site_current("ac")
  eq(s._ws_idle_ms, 120000)
  local conn = { connect_timeout_ms = 10000, send_timeout_ms = 60000, read_timeout_ms = 60000 }
  local c, w, r = origin.timeouts(conn, {}, s._ws_idle_ms)
  eq(c, 10); eq(w, 120); eq(r, 120)
  c, w, r = origin.timeouts(conn, { read = 300000 }, s._ws_idle_ms)
  eq(w, 120); eq(r, 300, "a config rule's read timeout")
  c, w, r = origin.timeouts(conn, { send = 5000 }, s._ws_idle_ms)
  eq(w, 5, "a config rule's send timeout")
  eq(store.site_current("other")._ws_idle_ms, nil)
  c, w, r = origin.timeouts(conn, {}, store.site_current("other")._ws_idle_ms or true)
  eq(w, 3600); eq(r, 3600)
  local zero = store.prepare(site("z", { { name = "z.test" } }, { access_control = { websocket = { idle_timeout_seconds = 0 } } }))
  eq(zero._ws_idle_ms, 3600000, "0 is the default")
  c, w, r = origin.timeouts(conn, {}, false)
  eq(w, 60, "not upgraded")
end)

test("site tables: unknown IP lists are refused; a site without access control has none", function()
  local st, err, code = store.replace({ revision = "9", content_hash = "9", ip_lists = {}, sites = {
    site("bad", { { name = "bad.test" } }, { access_control = { block_list_ids = { "nope" } } }) } })
  eq(st, nil)
  eq(code, 400, tostring(err))
  local s = store.site_current("other")
  eq(s._access, nil)
  eq(s.access_control, nil)
  eq(access.site_allowed(s, "192.0.2.50"), false)
  eq(access.websocket_allowed(s, nil), true)
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
