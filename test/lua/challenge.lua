-- Lua unit tests for edgeweir.challenge (see `make lua-test`):
--
--   resty -I lua --shdict 'edgeweir_challenge 4m' test/lua/challenge.lua
local cjson = require("cjson.safe")
local challenge = require("edgeweir.challenge")

local dict = ngx.shared.edgeweir_challenge
local real_ngx = ngx
local passed, failed = 0, 0

local NOW = 1790000000

local function reset()
  dict:flush_all()
  dict:flush_expired()
  challenge.forget()
  challenge.clock = function() return NOW end
end

local function test(name, fn)
  reset()
  local ok, err = pcall(fn)
  _G.ngx = real_ngx
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

local SECRET_A = ngx.encode_base64(string.rep("a", 32))
local SECRET_B = ngx.encode_base64(string.rep("b", 32))
local SECRET_C = ngx.encode_base64(string.rep("c", 32))

local function install(current, keys)
  local list = {}
  for id, secret in pairs(keys) do list[#list + 1] = { id = id, secret = secret } end
  table.sort(list, function(a, b) return a.id < b.id end)
  local st, err, code = challenge.replace_keys({ id = "set-" .. current, current = current, keys = list })
  assert(st, "replace_keys: " .. tostring(err) .. " " .. tostring(code))
  return challenge.keys()
end

local PREFIX, UA = "4:198.51.100", challenge.ua_hash("Mozilla/5.0 test")

test("HMAC-SHA256 matches RFC 4231 test case 2", function()
  local key = { id = "k", secret = "Jefe" }
  local mac = challenge.captcha_answer(key, "n", "X") -- exercises the cached HMAC twice
  eq(#mac, 32)
  eq(challenge.captcha_answer(key, "n", "X"), mac, "reused HMAC context")
  -- The same primitive signs passes: check it against the RFC vector.
  local hmac = require("resty.openssl.hmac")
  local h = assert(hmac.new("Jefe", "sha256"))
  eq(require("resty.string").to_hex(h:final("what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
end)

test("keys are validated and cached per version", function()
  for _, bad in ipairs({
    { current = "a", keys = { { id = "a", secret = "short" } } },
    { current = "x", keys = { { id = "a", secret = SECRET_A } } },
    { current = "a", keys = { { id = "a.b", secret = SECRET_A } } },
    { current = "a", keys = { { id = "a", secret = SECRET_A }, { id = "a", secret = SECRET_B } } },
    { current = "a" },
  }) do
    local st, _, code = challenge.replace_keys(bad)
    assert(not st and code == 400, "accepted " .. cjson.encode(bad))
  end
  eq(challenge.keys(), nil, "no keys before the first push")
  local keys = install("a", { a = SECRET_A, b = SECRET_B })
  eq(keys.current.id, "a")
  assert(keys.by_id.b, "accepted key b")
  eq(challenge.keys(), keys, "cached")
  keys = install("b", { a = SECRET_A, b = SECRET_B })
  eq(keys.current.id, "b", "a new version replaces the cache")
  local st = challenge.status()
  eq(st.keys_id, "set-b")
  eq(st.current, "b")
  eq(#st.keys, 2)
end)

test("passes verify only for their site, prefix, user agent and lifetime", function()
  local keys = install("a", { a = SECRET_A })
  local value = challenge.sign_pass(keys.current, "site-a", 2, PREFIX, UA, NOW, NOW + 1800)
  assert(value:match("^v1%.a%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+$"), value)
  local p = assert(challenge.parse_pass(keys, value))
  eq(p.level, 2)
  assert(challenge.check_pass(p, "site-a", PREFIX, UA, NOW), "valid pass")
  eq(select(2, challenge.check_pass(p, "site-b", PREFIX, UA, NOW)), "site")
  eq(select(2, challenge.check_pass(p, "site-a", "4:198.51.101", UA, NOW)), "prefix")
  eq(select(2, challenge.check_pass(p, "site-a", PREFIX, challenge.ua_hash("curl/8"), NOW)), "user agent")
  eq(select(2, challenge.check_pass(p, "site-a", PREFIX, UA, NOW + 1800)), "expired")
  -- Tampering with any part breaks the signature.
  local head, sig = value:match("^(.*)%.([^.]+)$")
  local forged = challenge.sign_pass({ id = "a", secret = "not the key at all" }, "site-a", 4, PREFIX, UA, NOW, NOW + 86400)
  eq(select(2, challenge.parse_pass(keys, forged)), "bad signature")
  local b64 = require("ngx.base64")
  local payload = head:match("^v1%.a%.(.*)$")
  local raised = b64.encode_base64url((b64.decode_base64url(payload):gsub("|2|", "|4|")))
  assert(raised ~= payload, "payload changed")
  eq(select(2, challenge.parse_pass(keys, "v1.a." .. raised .. "." .. sig)), "bad signature", "raised level")
  eq(select(2, challenge.parse_pass(keys, value:sub(1, -2) .. (value:sub(-1) == "A" and "B" or "A"))), "bad signature")
  eq(select(2, challenge.parse_pass(keys, "v1.zz." .. value:match("^v1%.a%.(.*)$"))), "unknown key")
  eq(select(2, challenge.parse_pass(keys, "garbage")), "malformed")
end)

test("key rotation: previous and next keys verify, a dropped key does not", function()
  local keys = install("a", { a = SECRET_A, b = SECRET_B })
  local old = challenge.sign_pass(keys.current, "site-a", 1, PREFIX, UA, NOW, NOW + 60)
  -- Another node already signs with b (canary): a pass from it verifies here.
  local ahead = challenge.sign_pass(keys.by_id.b, "site-a", 1, PREFIX, UA, NOW, NOW + 60)
  assert(challenge.parse_pass(keys, ahead), "pass signed with next")
  keys = install("b", { a = SECRET_A, b = SECRET_B, c = SECRET_C })
  assert(challenge.parse_pass(keys, old), "pass signed with previous")
  keys = install("c", { b = SECRET_B, c = SECRET_C })
  eq(select(2, challenge.parse_pass(keys, old)), "unknown key")
end)

test("challenge tokens: signature, binding, expiry and single redemption", function()
  local keys = install("a", { a = SECRET_A })
  local f = { site = "site-a", type = "pow", level = 3, prefix = PREFIX, ua = UA, iat = NOW, exp = NOW + 300, nonce = "n0nce", difficulty = 16 }
  local token = challenge.sign_token(keys.current, f)
  local got = assert(challenge.parse_token(keys, token))
  eq(got.type, "pow")
  eq(got.level, 3)
  eq(got.difficulty, 16)
  assert(challenge.check_token(got, "site-a", PREFIX, UA, NOW + 299), "valid token")
  eq(select(2, challenge.check_token(got, "site-a", PREFIX, UA, NOW + 300)), "expired")
  eq(select(2, challenge.check_token(got, "site-a", "6:20010db800000000", UA, NOW)), "prefix")
  eq(select(2, challenge.check_token(got, "site-b", PREFIX, UA, NOW)), "site")
  -- A pass never works as a token and a token never as a pass.
  eq(select(2, challenge.parse_pass(keys, "v1." .. token)), "bad signature")
  eq(select(2, challenge.parse_token(keys, token .. "x")), "bad signature")
  assert(challenge.consume(got.nonce, got.exp, NOW), "first redemption")
  assert(not challenge.consume(got.nonce, got.exp, NOW), "replay refused")
  assert(challenge.consume("other", got.exp, NOW), "another nonce")
end)

test("proof of work at the token's difficulty", function()
  eq(challenge.leading_zero_bits("\0\0\1"), 23)
  eq(challenge.leading_zero_bits("\128"), 0)
  eq(challenge.leading_zero_bits("\15\255"), 4)
  eq(challenge.leading_zero_bits("\0\0"), 16)
  local token = "k.payload.sig"
  local n = 0
  while challenge.leading_zero_bits(challenge.sha256(token .. ":" .. n)) < 10 do n = n + 1 end
  assert(challenge.pow_ok(token, tostring(n), 10), "solution at 10 bits")
  assert(challenge.pow_ok(token, tostring(n), 8), "solution at lower difficulty")
  local bits = challenge.leading_zero_bits(challenge.sha256(token .. ":" .. n))
  assert(not challenge.pow_ok(token, tostring(n), bits + 1), "above its bits")
  assert(not challenge.pow_ok(token, "-1", 0), "negative")
  assert(not challenge.pow_ok(token, "1e3", 0), "not decimal")
  assert(not challenge.pow_ok(token, string.rep("1", 17), 0), "too long")
  assert(not challenge.pow_ok(token, nil, 0), "missing")
  -- js: the answer is the token's SHA-256 in hex.
  eq(challenge.sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
end)

test("captcha answers are checked case-insensitively against the signed answer", function()
  local keys = install("a", { a = SECRET_A })
  local f = { nonce = "abc", answer = challenge.captcha_answer(keys.current, "abc", "K7PXQ") }
  assert(challenge.captcha_ok(keys.current, f, "K7PXQ"), "exact")
  assert(challenge.captcha_ok(keys.current, f, "k7pxq"), "lower case")
  assert(challenge.captcha_ok(keys.current, f, " k7 pxq "), "blanks")
  assert(not challenge.captcha_ok(keys.current, f, "K7PXR"), "wrong")
  assert(not challenge.captcha_ok(keys.current, f, "K7PX"), "short")
  assert(not challenge.captcha_ok(keys.current, { nonce = "abd", answer = f.answer }, "K7PXQ"), "other nonce")
  assert(not challenge.captcha_ok(keys.current, f, nil), "missing")
end)

test("captcha pool", function()
  eq(challenge.pick_captcha(), nil, "empty pool")
  for _, bad in ipairs({
    { id = "p", images = { { answer = "ABCDI", png = "AAAA" } } }, -- I is not in the alphabet
    { id = "p", images = { { answer = "ABCD", png = "AAAA" } } },
    { id = "p", images = { { answer = "ABCDE", png = "<svg>" } } },
    { images = {} },
  }) do
    local st, _, code = challenge.replace_captchas(bad)
    assert(not st and code == 400, "accepted " .. cjson.encode(bad))
  end
  local st = assert(challenge.replace_captchas({ id = "p1", images = {
    { answer = "ABCDE", png = "iVBORw0KGgo=" }, { answer = "23456", png = "iVBORw0KGgo=" },
  } }))
  eq(st.captchas, 2)
  eq(st.captchas_id, "p1")
  local answer, png = challenge.pick_captcha()
  assert(answer == "ABCDE" or answer == "23456", tostring(answer))
  eq(png, "iVBORw0KGgo=")
  assert(challenge.replace_captchas({ id = "p2", images = { { answer = "XYZ23", png = "AAAA" } } }))
  eq(dict:get("c|2"), nil, "shrunk pool drops old images")
  eq(challenge.pick_captcha(), "XYZ23")
end)

test("return paths stay on this site", function()
  for _, ok in ipairs({ "/", "/a/b?c=d&e", "/%2F%2Fevil", "/a//b" }) do
    eq(challenge.return_url(ok), ok, ok)
  end
  for _, bad in ipairs({ "//evil.example", "/\\evil.example", "https://evil.example/", "", "a", "/a b", "/a\nb",
    "/.edgeweir/challenge/verify", string.rep("/a", 1025) }) do
    eq(challenge.return_url(bad), nil, bad)
  end
  eq(challenge.return_url(nil), nil)
end)

test("Accept-Language picks Chinese or English", function()
  eq(challenge.language("zh-CN,zh;q=0.9,en;q=0.8"), "zh")
  eq(challenge.language("en-US,en;q=0.9,zh-CN;q=0.8"), "en")
  eq(challenge.language("fr-FR,fr;q=0.9"), "en")
  eq(challenge.language("fr-FR,zh-TW;q=0.5"), "zh")
  eq(challenge.language("en;q=0.5, zh-Hans;q=0.6"), "zh")
  eq(challenge.language("zh;q=0, en;q=0.1"), "en")
  eq(challenge.language("ZH-cn"), "zh")
  eq(challenge.language(nil), "en")
  eq(challenge.language({ "zh-CN", "en" }), "zh")
end)

test("client prefixes and user agent hashes", function()
  eq(challenge.client_prefix("198.51.100.23"), "4:198.51.100")
  eq(challenge.client_prefix("::ffff:198.51.100.23"), "4:198.51.100")
  eq(challenge.client_prefix("2001:db8:1:2:3:4:5:6"), "6:20010db800010002")
  eq(challenge.client_prefix("2001:db8:1:2::9"), "6:20010db800010002")
  eq(challenge.client_prefix("unix:"), nil)
  eq(challenge.ua_hash("curl/8.0"), challenge.sha256_hex("curl/8.0"):sub(1, 16))
  eq(challenge.ua_hash(nil), challenge.sha256_hex(""):sub(1, 16))
end)

test("challenge pages: CSP with a per-response nonce, languages, escaping", function()
  eq(challenge.csp("N0nce=="), "default-src 'none'; script-src 'nonce-N0nce=='; style-src 'nonce-N0nce=='; img-src data:; "
    .. "connect-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
  local page = challenge.page({ lang = "zh", kind = "pow", token = "k.p.s", ret = '/a?"x"<y>&z', difficulty = 16, nonce = "N1", id = "req1" })
  assert(page:find('<html lang="zh-CN">', 1, true), "Chinese page")
  assert(page:find("正在验证浏览器", 1, true), "Chinese text")
  assert(page:find('<style nonce="N1">', 1, true) and page:find('<script nonce="N1">', 1, true), "nonces")
  assert(page:find('data-d="16"', 1, true), "difficulty")
  assert(page:find("/.edgeweir/challenge/worker.js", 1, true), "worker")
  assert(page:find('value="/a?&quot;x&quot;&lt;y&gt;&amp;z"', 1, true), "escaped return path")
  assert(not page:find('"x"<y>', 1, true), "unescaped return path")
  assert(page:find("prefers-reduced-motion", 1, true), "reduced motion")
  assert(not page:find("https?://"), "no external URL")
  local js = challenge.page({ lang = "en", kind = "js", token = "k.p.s", ret = "/", nonce = "N2" })
  assert(js:find("Verifying your browser", 1, true) and js:find("crypto.subtle", 1, true), "js page")
  assert(js:find("<noscript>", 1, true), "noscript note")
  local captcha = challenge.page({ lang = "en", kind = "captcha", token = "k.p.s", ret = "/", image = "iVBORw0KGgo=", nonce = "N3", error = true })
  assert(captcha:find('src="data:image/png;base64,iVBORw0KGgo="', 1, true), "image")
  assert(captcha:find('name="alt" value="pow"', 1, true), "accessible alternative")
  assert(captcha:find('role="alert"', 1, true), "error message")
  assert(not captcha:find("<script", 1, true), "captcha works without scripts")
  assert(not challenge.WORKER_JS:find("https?://"), "worker without external URL")
end)

-- A fake ngx for the request-level functions.
local function request(opts)
  local sent = { header = {} }
  local fake = setmetatable({
    var = setmetatable(opts.var or {}, { __index = function() return nil end }),
    ctx = {},
    header = sent.header,
    status = 0,
    req = {
      get_method = function() return opts.method or "GET" end,
      read_body = function() end,
      get_post_args = function() return opts.args or {} end,
    },
    print = function(...) sent.body = (sent.body or "") .. table.concat({ ... }) end,
    exit = function(code) sent.exit = code end,
    redirect = function(loc, status) sent.location, sent.status = loc, status end,
  }, { __index = real_ngx })
  _G.ngx = fake
  return sent, fake
end

local SITE = { id = "site-a", protection = { pass_ttl = 900, pow = 12, pow_high = 20 } }

test("cookie302 redirects back with a pass that then satisfies level 1", function()
  install("a", { a = SECRET_A })
  local var = { request_uri = "/x?y=1", remote_addr = "198.51.100.7", http_user_agent = "Mozilla/5.0 test", scheme = "http", http_host = "demo.test:28080" }
  local sent, fake = request({ var = var })
  challenge.respond(SITE, "cookie302", 1)
  eq(sent.status, 302)
  eq(sent.location, "http://demo.test:28080/x?y=1")
  eq(sent.header["X-Edgeweir-Challenge"], "cookie302")
  local cookie = sent.header["Set-Cookie"]
  assert(cookie:match("^__ew_pass=v1%.a%.[^;]+; Path=/; Max%-Age=900; HttpOnly; SameSite=Lax$"), cookie)
  var.cookie___ew_pass = cookie:match("^__ew_pass=([^;]+)")
  fake.ctx = {}
  eq(challenge.pass_level(SITE), 1, "pass level")
  fake.ctx = {}
  var.remote_addr = "198.51.100.200"
  eq(challenge.pass_level(SITE), 1, "same /24")
  fake.ctx = {}
  var.remote_addr = "198.51.101.7"
  eq(challenge.pass_level(SITE), 0, "other prefix")
  fake.ctx = {}
  var.remote_addr, var.http_user_agent = "198.51.100.7", "curl/8"
  eq(challenge.pass_level(SITE), 0, "other user agent")
  fake.ctx = {}
  var.http_user_agent = "Mozilla/5.0 test"
  eq(challenge.pass_level({ id = "site-b" }), 0, "other site")
end)

test("HTTPS passes are Secure", function()
  install("a", { a = SECRET_A })
  local sent = request({ var = { request_uri = "/", remote_addr = "198.51.100.7", scheme = "https", http_host = "demo.test" } })
  challenge.respond(SITE, "cookie302", 1)
  assert(sent.header["Set-Cookie"]:find("; Secure$"), sent.header["Set-Cookie"])
end)

test("requests other than GET and HEAD are refused in plain text, without keys 503", function()
  install("a", { a = SECRET_A })
  local sent = request({ method = "POST", var = { request_uri = "/form", remote_addr = "198.51.100.7" } })
  challenge.respond(SITE, "js", 2)
  eq(sent.header["X-Edgeweir-Challenge"], "required")
  eq(_G.ngx.status, 403)
  eq(sent.header["Set-Cookie"], nil)
  -- No error page and no error code, also for a site with a 403 page.
  eq(sent.header["Content-Type"], "text/plain; charset=utf-8")
  eq(sent.header["X-Edgeweir-Error"], nil)
  eq(sent.body, "challenge required\n")
  sent = request({ method = "POST", var = { request_uri = "/form", remote_addr = "198.51.100.7" } })
  challenge.respond({ id = "site-a", protection = SITE.protection, error_pages = { pages = { ["403"] = "<h1>{{status}}</h1>" } } }, "js", 2)
  eq(sent.body, "challenge required\n")
  eq(sent.header["Content-Type"], "text/plain; charset=utf-8")
  _G.ngx = real_ngx
  dict:flush_all()
  challenge.forget()
  sent = request({ var = { request_uri = "/", remote_addr = "198.51.100.7" } })
  challenge.respond(SITE, "js", 2)
  eq(_G.ngx.status, 503)
  eq(sent.header["X-Edgeweir-Error"], "challenge-unavailable")
end)

test("challenge pages carry the token for the client and the site's difficulty", function()
  local keys = install("a", { a = SECRET_A })
  local var = { request_uri = "/p", remote_addr = "2001:db8:1:2::9", http_user_agent = "UA", scheme = "https",
    http_accept_language = "zh-CN", request_id = "abc123" }
  local sent = request({ var = var })
  challenge.respond(SITE, "pow", 3)
  eq(_G.ngx.status, 403)
  eq(sent.header["X-Edgeweir-Challenge"], "pow")
  local nonce = sent.header["Content-Security-Policy"]:match("script%-src 'nonce%-([^']+)'")
  assert(nonce and sent.body:find('<script nonce="' .. nonce .. '">', 1, true), "nonce of this response")
  eq(sent.header["Cache-Control"], "no-store, private")
  local token = sent.body:match('name="t" value="([^"]+)"')
  local f = assert(challenge.parse_token(keys, token))
  eq(f.level, 3)
  eq(f.difficulty, 12, "site difficulty")
  eq(f.prefix, "6:20010db800010002")
  eq(f.ua, challenge.ua_hash("UA"))
  -- Captcha without a pool falls back to the high-difficulty proof of work.
  sent = request({ var = var })
  challenge.respond(SITE, "captcha", 4)
  eq(sent.header["X-Edgeweir-Challenge"], "pow")
  f = assert(challenge.parse_token(keys, sent.body:match('name="t" value="([^"]+)"')))
  eq(f.level, 4)
  eq(f.difficulty, 20)
  -- With a pool: an image and the signed answer.
  assert(challenge.replace_captchas({ id = "p", images = { { answer = "K7PXQ", png = "iVBORw0KGgo=" } } }))
  sent = request({ var = var })
  challenge.respond(SITE, "captcha", 4)
  eq(sent.header["X-Edgeweir-Challenge"], "captcha")
  f = assert(challenge.parse_token(keys, sent.body:match('name="t" value="([^"]+)"')))
  assert(challenge.captcha_ok(keys.current, f, "k7pxq"), "answer of the picked image")
  -- HEAD: headers only.
  sent = request({ method = "HEAD", var = var })
  challenge.respond(SITE, "js", 2)
  eq(_G.ngx.status, 403)
  eq(sent.body, nil)
end)

test("required level: the strongest of platform, site and CC", function()
  local site = { id = "s", _config = {}, protection = { under_attack = true, under_attack_challenge = "js", cc = { high_pow = true } } }
  local level, kind = challenge.required(site, 0)
  eq(level, 2); eq(kind, "js")
  site._config.platform_protection = { under_attack = true, challenge = "pow" }
  level, kind = challenge.required(site, 1)
  eq(level, 3); eq(kind, "pow")
  level, kind = challenge.required(site, 4)
  eq(level, 4); eq(kind, "pow_high", "captcha level with the high proof of work")
  site.protection.cc.high_pow = false
  level, kind = challenge.required(site, 4)
  eq(kind, "captcha")
  eq(challenge.required({ id = "t", _config = {} }, 0), 0)
end)

test("verify redeems a token once and sets the pass", function()
  local keys = install("a", { a = SECRET_A })
  local var = { request_uri = "/page?q=1", remote_addr = "198.51.100.7", http_user_agent = "UA", scheme = "http", http_host = "demo.test" }
  local sent = request({ var = var })
  challenge.respond(SITE, "js", 2)
  local token = sent.body:match('name="t" value="([^"]+)"')
  local post = { uri = "/.edgeweir/challenge/verify", remote_addr = "198.51.100.9", http_user_agent = "UA", scheme = "http", http_host = "demo.test" }
  -- Wrong answer: a new page with an error, the token is used up.
  sent = request({ method = "POST", var = post, args = { t = token, a = "00", r = "/page?q=1" } })
  challenge.reserved(SITE)
  eq(_G.ngx.status, 403)
  assert(sent.body:find('role="alert"', 1, true), "error shown")
  sent = request({ method = "POST", var = post, args = { t = token, a = challenge.sha256_hex(token), r = "/page?q=1" } })
  challenge.reserved(SITE)
  eq(sent.status, 303, "replayed token: back to a new challenge")
  eq(sent.header["Set-Cookie"], nil)
  -- A fresh token with the right answer: 303 to the return path with a pass.
  sent = request({ var = var })
  challenge.respond(SITE, "js", 2)
  token = sent.body:match('name="t" value="([^"]+)"')
  sent = request({ method = "POST", var = post, args = { t = token, a = challenge.sha256_hex(token), r = "/page?q=1" } })
  challenge.reserved(SITE)
  eq(sent.status, 303)
  eq(sent.location, "http://demo.test/page?q=1")
  local pass = assert(challenge.parse_pass(keys, sent.header["Set-Cookie"]:match("^__ew_pass=([^;]+)")))
  eq(pass.level, 2)
  eq(pass.exp - pass.iat, 900, "site pass lifetime")
  -- An open redirect is not possible.
  sent = request({ var = var })
  challenge.respond(SITE, "js", 2)
  token = sent.body:match('name="t" value="([^"]+)"')
  sent = request({ method = "POST", var = post, args = { t = token, a = challenge.sha256_hex(token), r = "//evil.example/" } })
  challenge.reserved(SITE)
  eq(sent.location, "http://demo.test/")
  -- Another client (prefix) cannot redeem the token.
  sent = request({ var = var })
  challenge.respond(SITE, "js", 2)
  token = sent.body:match('name="t" value="([^"]+)"')
  post.remote_addr = "203.0.113.9"
  sent = request({ method = "POST", var = post, args = { t = token, a = challenge.sha256_hex(token), r = "/" } })
  challenge.reserved(SITE)
  eq(sent.status, 303)
  eq(sent.header["Set-Cookie"], nil, "no pass for another prefix")
end)

test("captcha alternative and proof-of-work redemption", function()
  local keys = install("a", { a = SECRET_A })
  assert(challenge.replace_captchas({ id = "p", images = { { answer = "K7PXQ", png = "iVBORw0KGgo=" } } }))
  local var = { request_uri = "/", remote_addr = "198.51.100.7", http_user_agent = "UA", scheme = "http", http_host = "demo.test" }
  local site = { id = "site-a", protection = { pass_ttl = 900, pow = 8, pow_high = 8 } }
  local sent = request({ var = var })
  challenge.respond(site, "captcha", 4)
  local token = sent.body:match('name="t" value="([^"]+)"')
  local post = { uri = "/.edgeweir/challenge/verify", remote_addr = "198.51.100.7", http_user_agent = "UA", scheme = "http", http_host = "demo.test" }
  sent = request({ method = "POST", var = post, args = { t = token, alt = "pow", r = "/" } })
  challenge.reserved(site)
  eq(sent.header["X-Edgeweir-Challenge"], "pow")
  local pow = sent.body:match('name="t" value="([^"]+)"')
  local f = assert(challenge.parse_token(keys, pow))
  eq(f.level, 4)
  local n = 0
  while not challenge.pow_ok(pow, tostring(n), f.difficulty) do n = n + 1 end
  sent = request({ method = "POST", var = post, args = { t = pow, a = tostring(n), r = "/" } })
  challenge.reserved(site)
  eq(sent.status, 303)
  eq(assert(challenge.parse_pass(keys, sent.header["Set-Cookie"]:match("^__ew_pass=([^;]+)"))).level, 4)
  -- The captcha itself still works once.
  sent = request({ method = "POST", var = post, args = { t = token, a = "k7pxq", r = "/" } })
  challenge.reserved(site)
  eq(sent.status, 303)
  eq(assert(challenge.parse_pass(keys, sent.header["Set-Cookie"]:match("^__ew_pass=([^;]+)"))).level, 4)
end)

test("reserved prefix: worker script, 405 and 404", function()
  install("a", { a = SECRET_A })
  local sent = request({ var = { uri = "/.edgeweir/challenge/worker.js" } })
  challenge.reserved(SITE)
  eq(sent.header["Content-Type"], "application/javascript; charset=utf-8")
  assert(sent.body:find("onmessage", 1, true), "worker body")
  sent = request({ var = { uri = "/.edgeweir/challenge/verify" } })
  challenge.reserved(SITE)
  eq(_G.ngx.status, 405)
  sent = request({ var = { uri = "/.edgeweir/other" } })
  challenge.reserved(SITE)
  eq(_G.ngx.status, 404)
  eq(sent.header["X-Edgeweir-Error"], "not-found")
end)

-- challenge-v2 (proto v0.29.0): the site's title and hint per language.
test("challenge pages: the site's title and hint, escaped, per language; built-in text without them", function()
  local site = { id = "site-a", protection = { challenge_text = { title_zh = "访问验证", hint_zh = "请稍候 <b>&</b>",
    title_en = "Checking <you>" } } }
  eq(select(1, challenge.custom_text(site, "zh")), "访问验证")
  eq(select(2, challenge.custom_text(site, "en")), "", "no English hint")
  eq(select(1, challenge.custom_text({ id = "x" }, "en")), "")
  local page = challenge.page({ lang = "zh", kind = "js", token = "k.p.s", ret = "/", nonce = "N", title = "访问验证", hint = "请稍候 <b>&</b>" })
  assert(page:find("<title>访问验证</title>", 1, true), "title")
  assert(page:find("<h1>访问验证</h1>", 1, true), "heading")
  assert(page:find('<p class="hint">请稍候 &lt;b&gt;&amp;&lt;/b&gt;</p>', 1, true), "escaped hint under the heading")
  assert(not page:find("正在验证浏览器</h1>", 1, true), "the built-in heading is replaced")
  page = challenge.page({ lang = "en", kind = "captcha", token = "k.p.s", ret = "/", image = "iVBORw0KGgo=", nonce = "N", title = "Checking <you>" })
  assert(page:find("<title>Checking &lt;you&gt;</title>", 1, true) and page:find("<h1>Checking &lt;you&gt;</h1>", 1, true), "captcha title")
  assert(not page:find('class="hint"', 1, true), "no hint")
  page = challenge.page({ lang = "en", kind = "pow", token = "k.p.s", ret = "/", nonce = "N", difficulty = 8, title = "", hint = "" })
  assert(page:find("<title>Security check</title>", 1, true) and page:find("<h1>Verifying your browser</h1>", 1, true), "built-in texts")
  -- Through respond: the language of the request picks the texts.
  install("a", { a = SECRET_A })
  local sent = request({ var = { request_uri = "/", remote_addr = "198.51.100.7", http_user_agent = "UA", http_accept_language = "zh-CN,zh;q=0.9" } })
  challenge.respond(site, "js", 2)
  assert(sent.body:find("<h1>访问验证</h1>", 1, true), "Chinese title")
  sent = request({ var = { request_uri = "/", remote_addr = "198.51.100.7", http_user_agent = "UA", http_accept_language = "en" } })
  challenge.respond(site, "js", 2)
  assert(sent.body:find("<h1>Checking &lt;you&gt;</h1>", 1, true), "English title")
end)

-- challenge-v2: failed answers ban the client network at the threshold.
test("failed answers count per site and client network and ban at the threshold", function()
  local bans = require("edgeweir.bans")
  ngx.shared.edgeweir_bans:flush_all()
  bans.forget()
  install("a", { a = SECRET_A })
  local site = { id = "site-f", protection = { pass_ttl = 900, failure_threshold = 3, failure_ban_seconds = 900 } }
  local function token_for(addr)
    local sent = request({ var = { request_uri = "/", remote_addr = addr, http_user_agent = "UA" } })
    challenge.respond(site, "js", 2)
    return sent.body:match('name="t" value="([^"]+)"')
  end
  local function post(addr, args, uncounted)
    local sent = request({ method = "POST", var = { uri = "/.edgeweir/challenge/verify", remote_addr = addr, http_user_agent = "UA",
      scheme = "http", http_host = "f.test" }, args = args })
    challenge.reserved(site, uncounted)
    return sent
  end
  local d = ngx.shared.edgeweir_challenge
  -- A wrong answer, an invalid token and a used token each count.
  post("198.51.100.7", { t = token_for("198.51.100.7"), a = "00", r = "/" })
  eq(d:get("f|site-f|198.51.100.7"), 1, "wrong answer")
  post("198.51.100.7", { t = "nonsense", a = "00", r = "/" })
  eq(d:get("f|site-f|198.51.100.7"), 2, "invalid token")
  eq(bans.match("site-f", "198.51.100.7"), nil, "below the threshold")
  local token = token_for("198.51.100.7")
  local sent = post("198.51.100.7", { t = token, a = challenge.sha256_hex(token), r = "/" })
  eq(sent.status, 303); assert(sent.header["Set-Cookie"], "a right answer passes and does not count")
  eq(d:get("f|site-f|198.51.100.7"), 2)
  post("198.51.100.7", { t = token, a = challenge.sha256_hex(token), r = "/" })
  eq(d:get("f|site-f|198.51.100.7"), nil, "the used token was the third failure: the count starts over")
  eq(bans.match("site-f", "198.51.100.7"), "a", "banned at site scope")
  eq(bans.match("other", "198.51.100.7"), nil)
  local list = bans.drain()
  eq(#list, 1)
  eq(list[1].reason, "challenge_failures"); eq(list[1].metric, "challenge_failures"); eq(list[1].observed, 3)
  eq(list[1].threshold, 3); eq(list[1].window_seconds, 600); eq(list[1].expires_at - list[1].created_at, 900)
  -- IPv6 clients count by their /64.
  post("2001:db8:1:2::1", { t = "x", r = "/" })
  post("2001:db8:1:2::99", { t = "x", r = "/" })
  eq(d:get("f|site-f|2001:db8:1:2::/64"), 2)
  -- Exempt clients (platform and site allow lists, trusted proxies, the
  -- local listeners) and sites without a threshold do not count.
  post("198.51.100.8", { t = "x", r = "/" }, true)
  eq(d:get("f|site-f|198.51.100.8"), nil, "uncounted")
  site.protection.failure_threshold = 0
  post("198.51.100.9", { t = "x", r = "/" })
  eq(d:get("f|site-f|198.51.100.9"), nil, "off")
  eq(d:ttl("f|site-f|2001:db8:1:2::/64") <= 600, true, "the window runs from the first failure")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
