-- Verified search engine crawlers (proto v0.29.0, feature challenge-v2,
-- ADR-0040): the User-Agent claims, reverse and forward DNS through a fake
-- resolver, the cache, lookups in flight and the request's fields.
--
--   resty -I lua --shdict 'edgeweir_bots 1m' test/lua/bots.lua
local bots = require("edgeweir.bots")
local resolver = require("resty.dns.resolver")

local dict = ngx.shared.edgeweir_bots
local passed, failed = 0, 0
local real_resolver = bots.new_resolver

local function test(name, fn)
  dict:flush_all()
  dict:flush_expired()
  local ok, err = pcall(fn)
  bots.new_resolver = real_resolver
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

-- fake installs a resolver answering from ptr (address -> answers) and
-- fwd ("<name> <qtype>" -> answers); a string answer is an error. It
-- returns the list of queries made.
local function fake(ptr, fwd)
  local queries = {}
  bots.new_resolver = function()
    return {
      reverse_query = function(_, addr)
        queries[#queries + 1] = "PTR " .. addr
        local a = ptr[addr]
        if type(a) == "string" then return nil, a end
        return a or { errcode = 3, errstr = "name error" }
      end,
      query = function(_, name, opts)
        queries[#queries + 1] = name .. " " .. opts.qtype
        local a = fwd[name .. " " .. opts.qtype]
        if type(a) == "string" then return nil, a end
        return a or { errcode = 3, errstr = "name error" }
      end,
    }
  end
  return queries
end

local function ptr(...)
  local out = {}
  for _, name in ipairs({ ... }) do out[#out + 1] = { type = resolver.TYPE_PTR, ptrdname = name } end
  return out
end
local function a(addr) return { { type = resolver.TYPE_A, address = addr } } end
local function aaaa(addr) return { { type = resolver.TYPE_AAAA, address = addr } } end
local A, AAAA = resolver.TYPE_A, resolver.TYPE_AAAA

test("User-Agent claims: tokens case-insensitively, the first crawler that matches", function()
  eq(bots.claimed("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").name, "googlebot")
  eq(bots.claimed("Mozilla/5.0 (Linux; Android 6.0.1) Chrome/41 (compatible; GoogleOther)").name, "googlebot")
  eq(bots.claimed("Storebot-Google/1.0").name, "googlebot")
  eq(bots.claimed("Google-InspectionTool/1.0").name, "googlebot")
  eq(bots.claimed("Google-CloudVertexBot").name, "googlebot")
  eq(bots.claimed("Mozilla/5.0 (compatible; bingbot/2.0)").name, "bingbot")
  eq(bots.claimed("Mozilla/5.0 (compatible; Baiduspider/2.0)").name, "baiduspider")
  eq(bots.claimed("Mozilla/5.0 (compatible; YandexBot/3.0)").name, "yandexbot")
  eq(bots.claimed("Mozilla/5.0 (compatible; YandexImages/3.0)").name, "yandexbot")
  eq(bots.claimed("Mozilla/5.0 (Macintosh) Applebot/0.1").name, "applebot")
  eq(bots.claimed("Mozilla/5.0 Firefox/120.0"), nil)
  eq(bots.claimed(""), nil)
  eq(bots.claimed(nil), nil)
  eq(bots.claimed({ "Googlebot", "x" }).name, "googlebot", "several headers: the first")
end)

test("domains: the domain itself or a name under it", function()
  local d = { "googlebot.com", "google.com" }
  eq(bots.in_domains("crawl-66-249-66-1.googlebot.com", d), true)
  eq(bots.in_domains("google.com", d), true)
  eq(bots.in_domains("evilgooglebot.com", d), false)
  eq(bots.in_domains("googlebot.com.evil.test", d), false)
  eq(bots.in_domains(".googlebot.com", d), false)
end)

test("verified: PTR name under the crawler's domain whose A record holds the address", function()
  local q = fake({ ["66.249.66.1"] = ptr("crawl-66-249-66-1.GoogleBot.com.") },
    { ["crawl-66-249-66-1.googlebot.com " .. A] = a("66.249.66.1") })
  eq(bots.verify("googlebot", "66.249.66.1"), true)
  eq(#q, 2, "PTR and A")
  eq(q[2], "crawl-66-249-66-1.googlebot.com " .. A, "lowercased, trailing dot removed")
  eq(bots.verify("googlebot", "66.249.66.1"), true, "cached")
  eq(#q, 2, "no lookup while cached")
  local ttl = dict:ttl("v|66.249.66.1|googlebot")
  assert(ttl > 86000 and ttl <= 86400, "cached for a day: " .. tostring(ttl))
end)

test("IPv6 clients: AAAA records, compared as addresses", function()
  local q = fake({ ["2001:4860:4801:10::1"] = ptr("rate-limited-proxy.google.com") },
    { ["rate-limited-proxy.google.com " .. AAAA] = aaaa("2001:4860:4801:0010:0:0:0:1") })
  eq(bots.verify("googlebot", "2001:4860:4801:10::1"), true)
  eq(q[2], "rate-limited-proxy.google.com " .. AAAA)
end)

test("not verified: PTR outside the domains, forward record without the address, no PTR", function()
  local q = fake({
    ["192.0.2.1"] = ptr("crawl.googlebot.com.evil.test"),
    ["192.0.2.2"] = ptr("crawl.googlebot.com"),
  }, { ["crawl.googlebot.com " .. A] = a("192.0.2.99") })
  eq(bots.verify("googlebot", "192.0.2.1"), false, "PTR mismatch")
  eq(#q, 1, "no forward lookup of a foreign name")
  eq(bots.verify("googlebot", "192.0.2.2"), false, "forward mismatch")
  eq(bots.verify("googlebot", "192.0.2.3"), false, "no PTR (NXDOMAIN)")
  eq(bots.verify("bingbot", "192.0.2.2"), false, "a name of another crawler")
  local ttl = dict:ttl("v|192.0.2.2|googlebot")
  assert(ttl > 3500 and ttl <= 3600, "not verified: an hour: " .. tostring(ttl))
  local n = #q
  eq(bots.verify("googlebot", "192.0.2.2"), false, "cached")
  eq(#q, n)
end)

test("at most three PTR names; any of them may verify", function()
  local q = fake({ ["192.0.2.5"] = ptr("a.example", "b.example", "c.search.msn.com", "d.search.msn.com") },
    { ["d.search.msn.com " .. A] = a("192.0.2.5"), ["c.search.msn.com " .. A] = a("192.0.2.5") })
  eq(bots.verify("bingbot", "192.0.2.5"), true)
  eq(q[2], "c.search.msn.com " .. A)
  fake({ ["192.0.2.6"] = ptr("a.example", "b.example", "c.example", "d.search.msn.com") },
    { ["d.search.msn.com " .. A] = a("192.0.2.6") })
  eq(bots.verify("bingbot", "192.0.2.6"), false, "the fourth name is not looked at")
end)

test("a failed lookup: not verified, cached for 60 seconds", function()
  fake({ ["192.0.2.7"] = "timeout", ["192.0.2.8"] = { errcode = 2, errstr = "server failure" },
    ["192.0.2.9"] = ptr("x.yandex.ru") }, { ["x.yandex.ru " .. A] = "timeout" })
  eq(bots.verify("googlebot", "192.0.2.7"), false, "PTR timeout")
  eq(bots.verify("googlebot", "192.0.2.8"), false, "SERVFAIL")
  eq(bots.verify("yandexbot", "192.0.2.9"), false, "forward timeout")
  for _, addr in ipairs({ "192.0.2.7", "192.0.2.8" }) do
    local ttl = dict:ttl("v|" .. addr .. "|googlebot")
    assert(ttl > 55 and ttl <= 60, addr .. ": " .. tostring(ttl))
  end
  eq(dict:get("v|192.0.2.9|yandexbot"), 2)
  -- A resolver that fails to start, or raises, counts the same.
  bots.new_resolver = function() return nil, "no nameservers" end
  eq(bots.verify("applebot", "192.0.2.10"), false)
  bots.new_resolver = function() error("boom") end
  eq(bots.verify("applebot", "192.0.2.11"), false)
  eq(dict:get("v|192.0.2.11|applebot"), 2)
end)

test("while an address is looked up, other requests count as not verified without waiting", function()
  local q = fake({ ["66.249.66.2"] = ptr("crawl.googlebot.com") }, { ["crawl.googlebot.com " .. A] = a("66.249.66.2") })
  dict:add("f|66.249.66.2", true, 10)
  eq(bots.verify("googlebot", "66.249.66.2"), false)
  eq(#q, 0, "no second lookup")
  dict:delete("f|66.249.66.2")
  eq(bots.verify("googlebot", "66.249.66.2"), true)
  eq(dict:get("f|66.249.66.2"), nil, "the mark goes when the lookup ends")
end)

test("request: the fields once per request, only for a claimed crawler", function()
  local q = fake({ ["66.249.66.3"] = ptr("crawl.googlebot.com") }, { ["crawl.googlebot.com " .. A] = a("66.249.66.3") })
  local runtime = ngx
  local function request(ua, addr)
    local fake_ngx = setmetatable({ ctx = {}, var = { http_user_agent = ua, remote_addr = addr } }, { __index = runtime })
    _G.ngx = fake_ngx
    local ok, v1, n1 = pcall(bots.request)
    local _, v2, n2 = pcall(bots.request)
    _G.ngx = runtime
    assert(ok, v1)
    eq(v1, v2); eq(n1, n2)
    return v1, n1
  end
  local verified, name = request("Googlebot/2.1", "66.249.66.3")
  eq(verified, true); eq(name, "googlebot")
  eq(#q, 2, "looked up once")
  verified, name = request("Mozilla/5.0", "66.249.66.3")
  eq(verified, false); eq(name, "")
  eq(#q, 2, "no lookup without a claim")
  verified, name = request("bingbot/2.0", "66.249.66.3")
  eq(verified, false); eq(name, "", "a claim the address does not back")
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
