-- Site settings of proto v0.24.0 (feature site-content-v1): cache keys that
-- drop parameters, responses cached with Set-Cookie, charsets, the largest
-- compressed response, body limits, maintenance, error page classes and
-- redirects, origin tries and the PURGE method's rate.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_challenge 1m' test/lua/content.lua
local cachekey = require("edgeweir.cachekey")
local setcookie = require("edgeweir.setcookie")
local charset = require("edgeweir.charset")
local compress = require("edgeweir.compress")
local errorpages = require("edgeweir.errorpages")
local origin = require("edgeweir.origin")
local router = require("edgeweir.router")
local store = require("edgeweir.store")
local purgemethod = require("edgeweir.purgemethod")
local policy = require("edgeweir.policy")

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

local function site(extra)
  local s = { id = "s", cache_zone = "z", domains = { { name = "s.test" } },
    origins = { { id = "o1", scheme = "http", address = "o.test", port = 80 } } }
  for k, v in pairs(extra or {}) do
    s[k] = v
  end
  return store.prepare(s)
end

test("cache key: exclude drops listed names and prefixes, raw or decoded", function()
  local key = cachekey.prepare({ query = "exclude", query_params = { "fbclid", "utm_*" }, sort_query = false })
  eq(cachekey.normalize_query("id=1&utm_source=x&fbclid=y&utm_medium=z&page=2", key), "id=1&page=2")
  eq(cachekey.normalize_query("%75tm_source=x&id=1", key), "id=1", "percent-encoded name")
  eq(cachekey.normalize_query("utm=1&utm_=2", key), "utm=1", "the prefix is utm_")
  eq(cachekey.normalize_query("fbclidx=1", key), "fbclidx=1", "exact names stay exact")
  eq(cachekey.normalize_query("utm_a=1", key), "", "everything dropped")
  key = cachekey.prepare({ query = "exclude", query_params = { "utm_*" }, sort_query = true })
  eq(cachekey.normalize_query("b=2&utm_x=1&a=1", key), "a=1&b=2", "sorted after dropping")
  -- URL purges compare queries the same way, percent-decoded.
  eq(cachekey.purge_query("q=%3Cb%3E&utm_source=x", key), "q=<b>")
  -- Two URLs that differ only in excluded parameters share one key.
  local s = site({ cache_key = { query = "exclude", query_params = { "utm_*" } } })
  local a = cachekey.build(s, { scheme = "https", host = "s.test", path = "/p", args = "id=1&utm_source=a" }, 0)
  local b = cachekey.build(s, { scheme = "https", host = "s.test", path = "/p", args = "utm_campaign=b&id=1" }, 0)
  eq(a, b)
  -- Patterns only mean something under exclude.
  key = cachekey.prepare({ query = "include", query_params = { "id" } })
  eq(cachekey.normalize_query("id=1&utm_a=2", key), "id=1")
end)

test("Set-Cookie: carried lines survive commas and percent signs", function()
  local lines = { "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/", "b=%2C,x; HttpOnly", "c=100%" }
  local carried = setcookie.encode(lines)
  assert(not carried:find("Expires=Wed, "), "commas are escaped")
  local back = setcookie.decode(carried)
  eq(#back, 3)
  for i = 1, 3 do
    eq(back[i], lines[i], "line " .. i)
  end
  eq(setcookie.encode("one=1"), "one=1")
  eq(#setcookie.decode(""), 0)
  eq(#setcookie.decode(nil), 0)
end)

test("Set-Cookie: only the response fetched for the request gets the cookies", function()
  local carried = setcookie.encode({ "sid=visitor-1; Path=/" })
  for _, status in ipairs({ "HIT", "STALE", "UPDATING", "REVALIDATED", "", nil }) do
    local h = {}
    eq(setcookie.restore(h, carried, status, false), false, tostring(status))
    eq(h["Set-Cookie"], nil, tostring(status) .. ": no cookie for another visitor")
  end
  for _, status in ipairs({ "MISS", "EXPIRED", "BYPASS" }) do
    local h = {}
    eq(setcookie.restore(h, carried, status, false), true, status)
    eq(h["Set-Cookie"][1], "sid=visitor-1; Path=/", status)
  end
  local h = {}
  eq(setcookie.restore(h, carried, "MISS", true), false, "subrequests (slices, background updates)")
  -- Appended to cookies already on the response (session affinity comes later).
  h = { ["Set-Cookie"] = "own=1" }
  setcookie.restore(h, setcookie.encode({ "a=1", "b=2" }), "MISS", false)
  eq(#h["Set-Cookie"], 3)
  eq(h["Set-Cookie"][1], "own=1")
  eq(h["Set-Cookie"][3], "b=2")
  -- The origin layer moves them into the carrier.
  h = { ["Set-Cookie"] = { "a=1", "b=2, 3" } }
  setcookie.carry(h)
  eq(h["Set-Cookie"], nil)
  eq(h[setcookie.HEADER], "a=1,b=2%2C 3")
  h = {}
  setcookie.carry(h)
  eq(h[setcookie.HEADER], nil, "nothing to carry")
end)

test("Set-Cookie: the deciding rule says whether to carry the cookies", function()
  local s = site({ cache_rules = {
    { id = "cookies", action = "cache", ttl = 60, mode = "override", set_cookie = true, path_prefixes = { "/c/" } },
    { id = "plain", action = "cache", ttl = 60, mode = "override" },
    { id = "bypass", action = "bypass", ttl = 0, mode = "override", set_cookie = true },
  } })
  local d = origin.decide({ s.cache_rules[1] }, 200, 10, nil, nil, false)
  eq(d.set_cookie, true)
  eq(d.accel_expires, 60)
  d = origin.decide({ s.cache_rules[2] }, 200, 10, nil, nil, false)
  eq(d.set_cookie, false)
  d = origin.decide({ s.cache_rules[3] }, 200, 10, nil, nil, false)
  eq(d.set_cookie, nil, "a bypass rule caches nothing")
end)

test("charset: added, kept or replaced on text types only", function()
  local gbk = { name = "gbk" }
  eq(charset.value("text/html", gbk), "text/html; charset=gbk")
  eq(charset.value("text/plain ", gbk), "text/plain; charset=gbk")
  eq(charset.value("application/json", { name = "utf-8", uppercase = true }), "application/json; charset=UTF-8")
  eq(charset.value("application/javascript", gbk), "application/javascript; charset=gbk")
  eq(charset.value("application/xml", gbk), "application/xml; charset=gbk")
  eq(charset.value("TEXT/CSS", gbk), "TEXT/CSS; charset=gbk", "types compare in any case")
  eq(charset.value("text/html; charset=utf-8", gbk), nil, "kept without force")
  eq(charset.value("text/html; charset=utf-8", { name = "gbk", force = true }), "text/html; charset=gbk")
  eq(charset.value('text/html; Charset="iso-8859-1"; q=1', { name = "big5", force = true, uppercase = true }),
    "text/html; Charset=BIG5; q=1", "quoted value, later parameters kept")
  eq(charset.value("text/html;charset=utf-8;x=y", { name = "euc-kr", force = true }), "text/html;charset=euc-kr;x=y")
  for _, ct in ipairs({ "image/png", "application/octet-stream", "application/xhtml+xml", "", false }) do
    eq(charset.value(ct or nil, gbk), nil, tostring(ct))
  end
  local h = { ["Content-Type"] = "text/html" }
  charset.apply(h, { name = "shift_jis" })
  eq(h["Content-Type"], "text/html; charset=shift_jis")
end)

test("compression: responses over the largest length stay identity", function()
  local tls = { gzip = true, gzip_min_length = 20, gzip_types = {}, brotli = true, brotli_min_length = 20, brotli_types = {},
    compress_max_length = 1000 }
  local function codings(length)
    return table.concat(compress.applicable(tls, { status = 200, content_type = "text/html", content_length = length }), ",")
  end
  eq(codings(500), "br,gzip")
  eq(codings(1000), "br,gzip", "the limit itself is compressed")
  eq(codings(1001), "", "over the limit")
  eq(codings(nil), "br,gzip", "unknown length")
  tls.compress_max_length = 0
  eq(codings(10 ^ 9), "br,gzip", "0: no limit")
end)

test("body limit: the rule's, else the site's, by Content-Length", function()
  eq(router.body_too_large(nil, 100, "101"), true)
  eq(router.body_too_large(nil, 100, "100"), false)
  eq(router.body_too_large(nil, 100, nil), false, "chunked bodies: nginx's limit only")
  eq(router.body_too_large(nil, 0, "999999999999"), false, "0: no limit")
  eq(router.body_too_large(1000, 100, "500"), false, "a rule raises the limit")
  eq(router.body_too_large(10, 100, "50"), true, "a rule lowers it")
  eq(router.body_too_large(0, 100, "500"), false, "a rule lifts it")
  eq(router.body_too_large(nil, nil, "500"), false, "site tables without the field")
  local ctx = { allowed = false }
  policy.config_action({ kind = "config", request_body_limit = 2048 }, ctx)
  eq(ctx.body_limit, 2048)
  local s = site({ body_limit = 104857600 })
  eq(s.body_limit, 104857600)
end)

test("maintenance: allowed addresses and paths, the page and Retry-After", function()
  local s = site({ maintenance = { template = "<p>{{status}} {{host}}</p>", retry_after = 120,
    allow_cidrs = { "192.0.2.0/24", "2001:db8::/32" }, allow_prefixes = { "/health", "/api/status" } } })
  eq(router.maintenance_allowed(s, "192.0.2.7", "/"), true)
  eq(router.maintenance_allowed(s, "2001:db8::1", "/x"), true)
  eq(router.maintenance_allowed(s, "198.51.100.1", "/healthz"), true, "prefix, not segment")
  eq(router.maintenance_allowed(s, "198.51.100.1", "/api/status/1"), true)
  eq(router.maintenance_allowed(s, "198.51.100.1", "/api/"), false)
  eq(router.maintenance_allowed(s, "198.51.100.1", "/"), false)
  eq(errorpages.render(s._maintenance_page, { status = "503", host = "s.test" }), "<p>503 s.test</p>")
  local bare = site({ maintenance = {} })
  eq(bare._maintenance_allow, nil)
  eq(bare._maintenance_page, nil, "built-in page")
  eq(router.maintenance_allowed(bare, "192.0.2.7", "/"), false)
  local zh = errorpages.render(errorpages.builtin("zh", "maintenance"), { status = "503" })
  assert(zh:find("维护中", 1, true), "built-in maintenance page in Chinese")
  local en = errorpages.render(errorpages.builtin("en", "maintenance"), { status = "503" })
  assert(en:find("Under maintenance", 1, true), "built-in maintenance page in English")
  eq(site({})._maintenance_page, nil)
  eq(site({}).maintenance, nil)
end)

test("error pages: the status's page, else its class's, redirects and status replacement", function()
  local s = site({ error_pages = { pages = {
    ["4"] = { template = "<p>4xx {{status}}</p>" },
    ["5"] = { redirect = "https://status.example.com/?s={{status}}&id={{request_id}}&h={{host}}" },
    ["404"] = { template = "<p>gone</p>", status = 200 },
    ["503"] = { template = "<p>busy</p>", status = 99 },
  }, intercept = true } })
  eq(errorpages.page_for(s, 404).status, 200)
  eq(errorpages.render(errorpages.page_for(s, 418).parts, { status = "418" }), "<p>4xx 418</p>", "class page")
  eq(errorpages.render(errorpages.page_for(s, 413).parts, { status = "413" }), "<p>4xx 413</p>")
  eq(errorpages.page_for(s, 503).status, nil, "an invalid replacement status is ignored")
  local redirect = errorpages.page_for(s, 502).redirect
  assert(redirect, "5xx redirects")
  eq(errorpages.render_url(redirect, { status = "502", request_id = "a b:c&d" }),
    "https://status.example.com/?s=502&id=a%20b%3Ac%26d&h={{host}}", "values percent-encoded, other text kept")
  eq(errorpages.page_for(site({}), 404), nil)
  -- The origin layer intercepts any 4xx or 5xx with a page of its status or class.
  eq(origin.page_code(s, 418, "0.010"), "origin-error")
  eq(origin.page_code(s, 599, "0.010"), "origin-error")
  eq(origin.page_code(s, 302, "0.010"), nil)
  local exact = site({ error_pages = { pages = { ["404"] = { template = "x" } }, intercept = true } })
  eq(origin.page_code(exact, 404, "0.010"), "origin-error")
  eq(origin.page_code(exact, 410, "0.010"), nil, "no page of its status or class")
  eq(origin.page_code(exact, 502, "-"), "origin-unreachable", "nginx's own failures always")
  -- 405 has a built-in page now (S3 origins refusing a method).
  assert(errorpages.render(errorpages.builtin("en", 405), { status = "405" }):find("Method not allowed", 1, true))
end)

test("origin tries and status retries come from the site table", function()
  local s = site({ tries = 5, no_status_retry = true })
  eq(s.tries, 5)
  eq(s.no_status_retry, true)
  s = site({})
  eq(s.tries, 3, "default")
  eq(s.no_status_retry, false)
end)

test("PURGE: at most RATE requests per site and second on a node", function()
  for i = 1, purgemethod.RATE do
    eq(purgemethod.limited("site-a", 1000), false, "request " .. i)
  end
  eq(purgemethod.limited("site-a", 1000), true, "over the rate")
  eq(purgemethod.limited("site-b", 1000), false, "per site")
  eq(purgemethod.limited("site-a", 1001), false, "per second")
  local s = site({ purge = true })
  eq(s.purge, true)
  eq(site({}).purge, false)
end)

test("X-Cache: hidden per site", function()
  eq(site({ hide_x_cache = true }).hide_x_cache, true)
  eq(site({}).hide_x_cache, false)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
