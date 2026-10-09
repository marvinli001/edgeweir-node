-- Access authentication (Site.auth_rules, proto v0.27.0, feature
-- access-auth-v1): signed URLs of kinds A-D against the console's vectors,
-- removing the signature, scopes, constant-time comparison, Basic with
-- PBKDF2 hashes, its caches and failure limit, forward authentication
-- answers and their cache, the HTTPS redirect first, and failure counts.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_policy_logs 1m' --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' \
--     --shdict 'edgeweir_auth 1m' test/lua/auth.lua
local cjson = require("cjson.safe")
local kdf = require("resty.openssl.kdf")
local to_hex = require("resty.string").to_hex
local auth = require("edgeweir.auth")
local errorpages = require("edgeweir.errorpages")
local policy = require("edgeweir.policy")
local stats = require("edgeweir.stats")
local store = require("edgeweir.store")

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

local vectors = assert(cjson.decode(assert(io.open("/t/url_auth_vectors.json")):read("*a")))

local KEY, BACKUP = "url-signing-key-0123456789", "backup-signing-key-abcdefghij"

local function hash_of(password, salt, iterations)
  return to_hex(assert(kdf.derive({ type = kdf.PBKDF2, md = "sha256", outlen = 32, pass = password, salt = salt, pbkdf2_iter = iterations })))
end

local function rule(kind, extra)
  local r = { id = "r-" .. kind, kind = kind, secret_version = 1 }
  if kind == "basic" then
    r.basic = { realm = "Admin" }
    r.users = { { name = "alice", iterations = 1000, salt = to_hex("0123456789abcdef"), hash = hash_of("correct horse", "0123456789abcdef", 1000) } }
  elseif kind == "forward" then
    r.secret_version = nil
    r.forward = { url = "https://auth.test/v", request_headers = { "authorization", "cookie" }, response_headers = { "x-auth-user" }, timeout_ms = 2000 }
  else
    r.url = { validity_seconds = 1800, skew_seconds = 300, sign_param = "sign", time_param = "t" }
    r.keys = { KEY, BACKUP }
  end
  for k, v in pairs(extra or {}) do r[k] = v end
  return r
end

local function site(rules, extra)
  local s = {
    id = "s1", cache_zone = "edgeweir_default", load_balance = "weighted_random",
    domains = { { name = "a.test" }, { name = "cdn.test", wildcard = true } },
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
    auth_rules = rules,
  }
  for k, v in pairs(extra or {}) do s[k] = v end
  return store.prepare(s, policy.prepare_config({}))
end

-- with_request runs fn with a fake ngx for one request; it returns fn's
-- result, the request state and the fake ngx.
local function with_request(req, fn)
  local real = ngx
  local raw = req.raw or req.uri or "/"
  local state = { uri = req.uri or "/", args = req.args, headers = req.headers or {}, captures = 0 }
  local vars = {
    host = req.host or "a.test", scheme = req.scheme or "https", remote_addr = req.addr or "192.0.2.1",
    request_uri = raw .. (req.args and ("?" .. req.args) or ""), edgeweir_local = req["local"] and "1" or "",
    http_authorization = req.headers and req.headers.authorization, server_port = "443",
  }
  local var = setmetatable({}, { __index = function(_, k)
    if k == "uri" then return state.uri end
    if k == "args" then return state.args end
    return vars[k]
  end })
  local fake = setmetatable({
    ctx = req.ctx or {}, var = var, header = {}, status = 200,
    req = {
      get_method = function() return req.method or "GET" end,
      set_uri = function(u, jump) assert(jump == false); state.uri = u end,
      set_uri_args = function(a) state.args = a end,
      set_header = function(k, v) state.headers[k:lower()] = v end,
      clear_header = function(k) state.headers[k:lower()] = nil end,
      get_headers = function() return state.headers end,
    },
    location = { capture = function(uri, opts)
      state.captures = state.captures + 1
      state.capture = { uri = uri, opts = opts }
      return req.answer
    end },
    exit = function(code) state.exited = code; return code end,
    print = function(body) state.body = (state.body or "") .. body end,
  }, { __index = real })
  _G.ngx = fake
  local ok, a = pcall(fn, fake, state)
  _G.ngx = real
  if not ok then error(a, 0) end
  return a, state, fake
end

-- sign returns the signature of the vectors' cases for a path signed now.
local function signed(kind, path, ts, key)
  key = key or KEY
  if kind == "url_a" then
    return path .. "?sign=" .. ts .. "-r1-" .. ngx.md5(path .. "@" .. ts .. "@r1@" .. key)
  elseif kind == "url_d" then
    return path .. "?sign=" .. ngx.md5(path .. "@" .. ts .. "@" .. key) .. "&t=" .. ts
  end
  local h = ngx.md5(path .. "@" .. ts .. "@" .. key)
  return kind == "url_b" and ("/" .. ts .. "/" .. h .. path) or ("/" .. h .. "/" .. ts .. path)
end

-- outcome checks a raw request URI as the console's checkSignedUri does.
local function outcome(v)
  local q = v.uri:find("?", 1, true)
  local raw_path = q and v.uri:sub(1, q - 1) or v.uri
  local query = q and v.uri:sub(q + 1) or nil
  local sig, stripped
  local names = { sign_param = v.signParam, time_param = v.timeParam }
  if v.kind == "url_b" or v.kind == "url_c" then
    sig = auth.parse_segments(v.kind, raw_path)
    if sig then
      sig.path = sig.rest
      stripped = sig.rest .. (query and ("?" .. query) or "")
    end
  else
    sig = auth.parse_query(v.kind, names, query)
    if sig then
      sig.path = raw_path
      stripped = sig.args ~= "" and (raw_path .. "?" .. sig.args) or raw_path
    end
  end
  local r = { kind = v.kind, keys = v.keys, url = { validity_seconds = v.validitySeconds, skew_seconds = v.skewSeconds } }
  local code = auth.check_signature(r, sig, v.now)
  local result = code == nil and "ok" or (code == "auth-expired" and "expired" or "denied")
  return result, stripped or v.uri
end

test("signed URLs: every shared vector of the console", function()
  local n = 0
  for _, v in ipairs(vectors.check) do
    local got, stripped = outcome(v)
    eq(got, v.outcome, v.kind .. " " .. v.uri .. " (" .. v.note .. ")")
    eq(stripped, v.stripped, v.kind .. " " .. v.uri .. " stripped")
    n = n + 1
  end
  assert(n >= 83, "vectors read")
  -- And what the console signs checks out here.
  for _, v in ipairs(vectors.sign) do
    local check = { kind = v.kind, uri = v.expected:gsub("#.*$", ""), now = v.ts, keys = { v.key }, validitySeconds = 60,
      skewSeconds = 0, signParam = v.signParam, timeParam = v.timeParam }
    eq((outcome(check)), "ok", "signed " .. v.kind .. " " .. v.uri)
  end
end)

test("constant-time comparison compares every byte", function()
  assert(auth.same("abc", "abc"))
  assert(not auth.same("abc", "abd"))
  assert(not auth.same("abc", "ab"))
  assert(not auth.same(nil, "a"))
  assert(auth.same("", ""))
  assert(not auth.same(string.rep("a", 31) .. "b", string.rep("a", 32)))
end)

test("selection removes the signature before anything reads the path", function()
  local now = ngx.time()
  for _, kind in ipairs({ "url_a", "url_b", "url_c", "url_d" }) do
    local s = site({ rule(kind) })
    local uri = signed(kind, "/v/a.mp4", now)
    local raw, args = uri:match("^([^?]*)%??(.*)$")
    local qs = args ~= "" and (args .. "&w=1") or "w=1"
    local result, state, fake = with_request({ raw = raw, uri = raw, args = qs }, function(f)
      auth.select(s, false)
      return auth.check(s, policy.site_https_redirect)
    end)
    eq(result, nil, kind .. " passes")
    eq(state.uri, "/v/a.mp4", kind .. " path")
    eq(state.args, "w=1", kind .. " other parameters stay")
    eq(fake.ctx.edgeweir_auth.stripped, "/v/a.mp4?w=1", kind .. " request URI for the rules")
  end
end)

test("rules read the URI without the signature (http.request.uri, full_uri)", function()
  local now = ngx.time()
  local s = site({ rule("url_b") })
  local uri = signed("url_b", "/v/a.mp4", now)
  local values = with_request({ raw = uri, uri = uri, args = "x=1" }, function()
    auth.select(s, false)
    return policy.request(s, {})
  end)
  eq(values["http.request.uri"], "/v/a.mp4?x=1")
  eq(values["http.request.uri.path"], "/v/a.mp4")
end)

test("signed URLs: expired, wrong, missing, another key", function()
  local now = ngx.time()
  local s = site({ rule("url_d") })
  local cases = {
    { signed("url_d", "/a", now - 1800 - 301), "auth-expired" },
    { signed("url_d", "/a", now + 301), "auth-expired" },
    { signed("url_d", "/a", now, "not-the-key-0000"), "auth-denied" },
    { "/a", "auth-denied" },
    { signed("url_d", "/a", now, BACKUP), nil },
  }
  for _, c in ipairs(cases) do
    local raw, args = c[1]:match("^([^?]*)%??(.*)$")
    local result = with_request({ raw = raw, uri = raw, args = args ~= "" and args or nil }, function()
      auth.select(s, false)
      return auth.check(s, policy.site_https_redirect)
    end)
    if c[2] == nil then
      eq(result, nil, c[1])
    else
      eq(result and result.status, 403, c[1])
      eq(result.code, c[2], c[1])
    end
  end
  -- A rule without keys (secret unavailable) refuses everything.
  local keyless = site({ rule("url_d", { keys = {} }) })
  local raw, args = signed("url_d", "/a", now):match("^([^?]*)%??(.*)$")
  local result = with_request({ raw = raw, uri = raw, args = args }, function()
    auth.select(keyless, false)
    return auth.check(keyless, policy.site_https_redirect)
  end)
  eq(result and result.code, "auth-denied", "no keys")
end)

test("B and C: the normalized path must carry the same two segments", function()
  local now = ngx.time()
  local s = site({ rule("url_b") })
  local good = signed("url_b", "/x/../etc", now)
  -- nginx normalized /ts/hash/x/../etc to /ts/hash/etc: the segments stay.
  local result, state = with_request({ raw = good, uri = good:gsub("/x/%.%./", "/") }, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
  eq(result, nil, "signature over the raw path")
  eq(state.uri, "/etc")
  -- /ts/hash/../../etc normalizes to /etc: the segments are gone, nothing is removed.
  local escape = signed("url_b", "/../../etc", now)
  result, state = with_request({ raw = escape, uri = "/etc" }, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
  eq(result and result.code, "auth-denied")
  eq(state.uri, "/etc")
end)

test("scope: domains of every form, prefixes, extensions, exclusions, first rule wins", function()
  local s = site({
    rule("url_b", { id = "img", domains = { "*.cdn.test", ".deep.test", "~v[0-9]+\\.a\\.test" }, extensions = { "jpg" } }),
    rule("url_a", { id = "admin", domains = { "a.test" }, path_prefixes = { "/admin/" }, exclude_path_prefixes = { "/admin/public/" } }),
  })
  local function chosen(host, uri)
    local _, _, fake = with_request({ host = host, uri = uri }, function() auth.select(s, false) end)
    return fake.ctx.edgeweir_auth and fake.ctx.edgeweir_auth.rule.id or nil
  end
  eq(chosen("x.cdn.test", "/p.jpg"), "img")
  eq(chosen("y.x.cdn.test", "/p.jpg"), nil, "wildcards take one label")
  eq(chosen("cdn.test", "/p.jpg"), nil)
  eq(chosen("a.b.deep.test", "/p.JPG"), "img", "extensions compare lowercase: .JPG is jpg")
  eq(chosen("a.b.deep.test", "/p.png"), nil, "another extension")
  eq(chosen("a.b.deep.test", "/p.jpg"), "img")
  eq(chosen("v12.a.test", "/p.jpg"), "img", "pattern")
  eq(chosen("a.test", "/p.jpg"), nil, "neither")
  eq(chosen("a.test", "/admin/x"), "admin")
  eq(chosen("a.test", "/admin/public/x"), nil, "excluded")
  eq(chosen("a.test", "/.edgeweir/challenge"), nil, "reserved prefix")
  local _, _, fake = with_request({ host = "a.test", uri = "/admin/x" }, function() auth.select(s, true) end)
  eq(fake.ctx.edgeweir_auth, nil, "HTTP-01")
end)

test("scope of B and C uses the path without the signature", function()
  local now = ngx.time()
  local s = site({ rule("url_c", { path_prefixes = { "/video/" } }) })
  local uri = signed("url_c", "/video/a.mp4", now)
  local result, state = with_request({ raw = uri, uri = uri }, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
  eq(result, nil)
  eq(state.uri, "/video/a.mp4")
  -- Unsigned paths under the prefix are still in scope, and refused.
  result = with_request({ uri = "/video/a.mp4" }, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
  eq(result and result.status, 403)
end)

test("Basic: parse the header", function()
  local function b64(s) return ngx.encode_base64(s) end
  local u, p = auth.parse_basic("Basic " .. b64("alice:pa:ss"))
  eq(u, "alice")
  eq(p, "pa:ss", "the first colon splits")
  u = auth.parse_basic("basic  " .. b64("a:b") .. "  ")
  eq(u, "a", "scheme case and spaces")
  eq(auth.parse_basic("Bearer " .. b64("a:b")), nil)
  eq(auth.parse_basic("Basic " .. b64("nocolon")), nil)
  eq(auth.parse_basic("Basic !!!"), nil)
  eq(auth.parse_basic(nil), nil)
  u, p = auth.parse_basic("Basic " .. b64(":"))
  eq(u, "")
  eq(p, "")
end)

test("Basic: PBKDF2-HMAC-SHA256 as the console hashes", function()
  -- The console's hashBasicPassword("password") with salt "salt" and 100000 iterations.
  eq(hash_of("password", "salt", 100000), "0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5")
  local user = { iterations = 1000, salt = "0123456789abcdef", hash = assert(kdf.derive({ type = kdf.PBKDF2, md = "sha256", outlen = 32, pass = "pw", salt = "0123456789abcdef", pbkdf2_iter = 1000 })) }
  assert(auth.verify_password(user, "pw"))
  assert(not auth.verify_password(user, "pw "))
  assert(not auth.verify_password(nil, "pw"), "unknown users never pass")
end)

local function basic_request(s, headers, extra)
  local req = { headers = headers, addr = "198.51.100.7" }
  for k, v in pairs(extra or {}) do req[k] = v end
  return with_request(req, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
end

test("Basic: 401 with the challenge, credentials removed, user header, caches", function()
  ngx.shared.edgeweir_auth:flush_all()
  local s = site({ rule("basic", { basic = { realm = "Admin", user_header = true } }) })
  -- Without credentials: 401 with WWW-Authenticate and the 401 page.
  local result = basic_request(s, {})
  assert(result and result.respond, "answered")
  local _, state, fake = with_request({}, function() return result.respond() end)
  eq(fake.status, 401)
  eq(fake.header["WWW-Authenticate"], 'Basic realm="Admin", charset="UTF-8"')
  eq(fake.header["X-Edgeweir-Error"], "auth-required")
  eq(fake.header["Cache-Control"], "no-store")
  assert(state.body and state.body:find("401", 1, true), "page")
  -- Right password: through, Authorization removed, X-Auth-User set (also over the visitor's own).
  local good = "Basic " .. ngx.encode_base64("alice:correct horse")
  local headers = { authorization = good, ["x-auth-user"] = "mallory" }
  result, state = basic_request(s, headers)
  eq(result, nil)
  eq(state.headers.authorization, nil)
  eq(state.headers["x-auth-user"], "alice")
  -- Cached: no second derivation.
  local derive = auth.verify_password
  local calls = 0
  auth.verify_password = function(...) calls = calls + 1; return derive(...) end
  result = basic_request(s, { authorization = good })
  eq(result, nil)
  eq(calls, 0, "success cached")
  -- Wrong password: 401; repeated, cached too.
  local bad = "Basic " .. ngx.encode_base64("alice:wrong horse")
  result = basic_request(s, { authorization = bad })
  assert(result and result.respond)
  eq(calls, 1)
  basic_request(s, { authorization = bad })
  eq(calls, 1, "failure cached")
  -- Unknown users cost a derivation too.
  basic_request(s, { authorization = "Basic " .. ngx.encode_base64("eve:x") })
  eq(calls, 2)
  auth.verify_password = derive
  -- keep_authorization keeps it.
  local keep = site({ rule("basic", { id = "keep", basic = { realm = "R", keep_authorization = true } }) })
  _, state = basic_request(keep, { authorization = good })
  eq(state.headers.authorization, good)
  eq(state.headers["x-auth-user"], nil)
end)

test("Basic: a client network gets 10 failed verifications per window, then 429 without hashing", function()
  ngx.shared.edgeweir_auth:flush_all()
  local s = site({ rule("basic", { id = "limited" }) })
  local derive = auth.verify_password
  local calls = 0
  auth.verify_password = function(...) calls = calls + 1; return derive(...) end
  local limited
  for i = 1, 12 do
    local result = basic_request(s, { authorization = "Basic " .. ngx.encode_base64("alice:guess" .. i) }, { addr = "203.0.113.9" })
    if result.status == 429 then limited = limited or i end
  end
  auth.verify_password = derive
  -- A window boundary may fall inside the loop: at least 10 verifications, at most 20.
  assert(calls >= 10 and calls <= 11, "verifications " .. calls)
  assert(limited == nil or limited >= 11, "limited after " .. tostring(limited))
  local result = basic_request(s, { authorization = "Basic " .. ngx.encode_base64("alice:guess-again") }, { addr = "203.0.113.9" })
  if result.status == 429 then
    eq(result.code, "auth-rate-limited")
    assert(result.retry_after >= 1 and result.retry_after <= 10)
  end
  -- Another network is not limited.
  result = basic_request(s, { authorization = "Basic " .. ngx.encode_base64("alice:correct horse") }, { addr = "203.0.113.200" })
  eq(result, nil)
end)

test("HTTPS first: a plain HTTP request the site redirects is redirected before any check", function()
  local s = site({ rule("basic") }, { certificate_id = "c", tls = { force_https = true }, certificate = { dns_names = { "a.test" } } })
  local result = basic_request(s, {}, { scheme = "http", raw = "/admin", uri = "/admin", args = "a=1" })
  eq(result and result.status, 301)
  eq(result.location, "https://a.test/admin?a=1")
  -- The signature survives the redirect.
  local now = ngx.time()
  local u = site({ rule("url_a") }, { certificate_id = "c", tls = { force_https = true }, certificate = { dns_names = { "a.test" } } })
  local uri = signed("url_a", "/a", now)
  local raw, args = uri:match("^([^?]*)%?(.*)$")
  result = with_request({ scheme = "http", raw = raw, uri = raw, args = args }, function()
    auth.select(u, false)
    return auth.check(u, policy.site_https_redirect)
  end)
  eq(result and result.location, "https://a.test" .. uri)
end)

test("local listeners (the agent's prefetches) are not checked", function()
  local s = site({ rule("basic") })
  local result = basic_request(s, {}, { ["local"] = true })
  eq(result, nil)
end)

local function forward_request(s, answer, headers)
  return with_request({ headers = headers or { cookie = "sid=1" }, answer = answer, raw = "/app/x", uri = "/app/x", args = "q=1" }, function()
    auth.select(s, false)
    return auth.check(s, policy.site_https_redirect)
  end)
end

test("forward authentication: subrequest, 2xx copies headers, 401/403/3xx answers, unavailable", function()
  ngx.shared.edgeweir_auth:flush_all()
  local s = site({ rule("forward") })
  -- 2xx: the service's X-Auth-User reaches the origin; the visitor's own is replaced.
  local result, state = forward_request(s, { status = 204, header = { ["X-Auth-User"] = "alice" }, body = "" },
    { cookie = "sid=1", ["x-auth-user"] = "mallory" })
  eq(result, nil)
  eq(state.headers["x-auth-user"], "alice")
  eq(state.capture.uri, auth.LOCATION)
  eq(state.capture.opts.method, ngx.HTTP_GET)
  eq(state.capture.opts.vars.edgeweir_auth_rule, "r-forward")
  eq(state.capture.opts.vars.edgeweir_auth_uri, "/app/x?q=1", "the original request URI")
  -- 2xx without the header: the visitor's own is removed.
  result, state = forward_request(s, { status = 200, header = {}, body = "" }, { cookie = "sid=1", ["x-auth-user"] = "mallory" })
  eq(result, nil)
  eq(state.headers["x-auth-user"], nil)
  -- 401 passed on with its challenge and body.
  result = forward_request(s, { status = 401, header = { ["WWW-Authenticate"] = "Bearer", ["Content-Type"] = "application/json" }, body = '{"e":1}' })
  local _, out, fake = with_request({}, function() return result.respond() end)
  eq(fake.status, 401)
  eq(fake.header["WWW-Authenticate"], "Bearer")
  eq(fake.header["Content-Type"], "application/json")
  eq(fake.header["X-Edgeweir-Error"], "auth-denied")
  eq(out.body, '{"e":1}')
  -- 302 without pass_redirects: refused with 403.
  result = forward_request(s, { status = 302, header = { Location = "https://login.test/" }, body = "" })
  eq(result and result.status, 403)
  -- 5xx: 503, or through when the rule allows it.
  result = forward_request(s, { status = 502, header = {}, body = "" })
  eq(result and result.status, 503)
  eq(result.code, "auth-unavailable")
  local open = site({ rule("forward", { id = "open", forward = { url = "https://auth.test/v", request_headers = {}, timeout_ms = 100, allow_unavailable = true } }) })
  result = forward_request(open, { status = 504, header = {}, body = "" })
  eq(result, nil)
  -- 3xx passed on when the rule says so.
  local redirects = site({ rule("forward", { id = "login", forward = { url = "https://auth.test/v", request_headers = {}, timeout_ms = 100, pass_redirects = true } }) })
  result = forward_request(redirects, { status = 302, header = { Location = "https://login.test/?rd=x" }, body = "" })
  _, _, fake = with_request({}, function() return result.respond() end)
  eq(fake.status, 302)
  eq(fake.header["Location"], "https://login.test/?rd=x")
  -- A 403 body over 64 KiB gets the error page instead.
  result = forward_request(s, { status = 403, header = {}, body = string.rep("x", 65537) })
  _, out, fake = with_request({}, function() return result.respond() end)
  eq(fake.status, 403)
  assert(#out.body < 65537, "error page")
end)

test("forward authentication: answers cached by the forwarded headers only", function()
  ngx.shared.edgeweir_auth:flush_all()
  local s = site({ rule("forward", { id = "cached", forward = { url = "https://auth.test/v", request_headers = { "cookie" }, response_headers = { "x-auth-user" }, timeout_ms = 100, cache_seconds = 30 } }) })
  local ok = { status = 200, header = { ["X-Auth-User"] = "alice" }, body = "" }
  local _, state = forward_request(s, ok, { cookie = "sid=1" })
  eq(state.captures, 1)
  local result
  result, state = forward_request(s, { status = 500, header = {}, body = "" }, { cookie = "sid=1" })
  eq(result, nil, "cached 2xx")
  eq(state.captures, 0)
  eq(state.headers["x-auth-user"], "alice", "copied header cached")
  -- Another cookie: asked again; a 401 is cached as well, a 5xx is not.
  result, state = forward_request(s, { status = 401, header = {}, body = "no" }, { cookie = "sid=2" })
  eq(state.captures, 1)
  result, state = forward_request(s, ok, { cookie = "sid=2" })
  eq(state.captures, 0)
  assert(result and result.respond, "cached 401")
  forward_request(s, { status = 503, header = {}, body = "" }, { cookie = "sid=3" })
  _, state = forward_request(s, ok, { cookie = "sid=3" })
  eq(state.captures, 1, "5xx not cached")
end)

test("refusals are counted per site and minute (MinuteStats.auth_failures)", function()
  ngx.shared.edgeweir_stats:flush_all()
  local s = site({ rule("url_b") })
  for _ = 1, 3 do
    with_request({ uri = "/a" }, function()
      auth.select(s, false)
      return auth.check(s, policy.site_https_redirect)
    end)
  end
  local drained = stats.drain(ngx.time() + 120)
  local total = 0
  for _, b in ipairs(drained) do
    if b.site_id == "s1" then total = total + (b.auth_failures or 0) end
  end
  eq(total, 3)
end)

test("the 401 page is a built-in page of its own", function()
  local function text(parts)
    local out = {}
    for _, p in ipairs(type(parts) == "table" and parts or { parts }) do
      if type(p) == "string" then out[#out + 1] = p end
    end
    return table.concat(out)
  end
  assert(text(errorpages.builtin("zh", 401)):find("需要认证", 1, true), "zh title")
  assert(text(errorpages.builtin("en", 401)):find("Authentication required", 1, true), "en title")
  assert(errorpages.STATUSES[401])
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
