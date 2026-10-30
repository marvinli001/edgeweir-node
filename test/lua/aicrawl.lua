-- AI crawl control (proto vNEXT, feature ai-crawlers-v1, ADR-0070): the
-- catalogue's claims (longest token first), verification by published
-- ranges and by reverse DNS through a fake resolver, the price headers, a
-- site's policy and the crawler counters of the minute summaries.
--
--   resty -I lua --shdict 'edgeweir_bots 1m' --shdict 'edgeweir_stats 1m' \
--     --shdict 'edgeweir_topstats 1m' test/lua/aicrawl.lua
local aicrawl = require("edgeweir.aicrawl")
local bots = require("edgeweir.bots")
local resolver = require("resty.dns.resolver")
local stats = require("edgeweir.stats")
local top = require("edgeweir.topstats")

local passed, failed = 0, 0
local real_resolver = bots.new_resolver

local function test(name, fn)
  ngx.shared.edgeweir_bots:flush_all()
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

local CATALOGUE = aicrawl.prepare_catalogue({
  { id = "gptbot", operator = "openai", tokens = { "gptbot" }, cidrs = { "192.0.2.0/24", "2001:db8::/48" } },
  { id = "chatgpt-user", operator = "openai", tokens = { "chatgpt-user" }, cidrs = { "198.51.100.0/24" } },
  { id = "claudebot", operator = "anthropic", tokens = { "claudebot" } },
  { id = "googlebot", operator = "google", tokens = { "googlebot", "googleother" },
    cidrs = { "203.0.113.0/25" }, domains = { "googlebot.com", "google.com" } },
  { id = "google-cloudvertexbot", operator = "google", tokens = { "google-cloudvertexbot" } },
  { id = "bingbot", operator = "microsoft", tokens = { "bingbot" }, domains = { "search.msn.com" } },
})

test("claims: tokens case-insensitively, the longest matching token wins", function()
  eq(aicrawl.claim(CATALOGUE, "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://example.com/gptbot)").id, "gptbot")
  eq(aicrawl.claim(CATALOGUE, "Mozilla/5.0 (compatible; ChatGPT-User/1.0)").id, "chatgpt-user")
  eq(aicrawl.claim(CATALOGUE, "ClaudeBot/1.0").id, "claudebot")
  eq(aicrawl.claim(CATALOGUE, "Google-CloudVertexBot Googlebot").id, "google-cloudvertexbot", "longest token")
  eq(aicrawl.claim(CATALOGUE, "Mozilla/5.0 (compatible; GoogleOther)").id, "googlebot")
  eq(aicrawl.claim(CATALOGUE, { "bingbot/2.0", "x" }).id, "bingbot", "several headers: the first")
  eq(aicrawl.claim(CATALOGUE, "Mozilla/5.0 Firefox/120.0"), nil)
  eq(aicrawl.claim(CATALOGUE, ""), nil)
  eq(aicrawl.claim(CATALOGUE, nil), nil)
  eq(aicrawl.claim(nil, "GPTBot"), nil)
  eq(aicrawl.prepare_catalogue({}), nil, "no crawlers: no catalogue")
end)

test("verification: published ranges, no way to verify, impersonators", function()
  local c = CATALOGUE.crawlers
  eq(aicrawl.verify(c.gptbot, "192.0.2.10"), "verified")
  eq(aicrawl.verify(c.gptbot, "2001:db8::1"), "verified")
  eq(aicrawl.verify(c.gptbot, "::ffff:192.0.2.10"), "verified", "IPv4-mapped")
  eq(aicrawl.verify(c.gptbot, "10.0.0.1"), "failed", "spoofed GPTBot")
  eq(aicrawl.verify(c.claudebot, "10.0.0.1"), "unverifiable")
  eq(aicrawl.verify(c.googlebot, "203.0.113.5"), "verified", "ranges before DNS")
  eq(aicrawl.verify(c.bingbot, "10.0.0.1", true), "pending", "no DNS in the log phase")
end)

test("verification: reverse DNS and the forward lookup", function()
  local queries = {}
  bots.new_resolver = function()
    return {
      reverse_query = function(_, addr)
        queries[#queries + 1] = "PTR " .. addr
        if addr == "157.55.39.1" then return { { type = resolver.TYPE_PTR, ptrdname = "msnbot-157-55-39-1.search.msn.com." } } end
        if addr == "10.9.9.9" then return { { type = resolver.TYPE_PTR, ptrdname = "evil.example." } } end
        return { errcode = 3, errstr = "name error" }
      end,
      query = function(_, name, opts)
        queries[#queries + 1] = name .. " " .. opts.qtype
        if name == "msnbot-157-55-39-1.search.msn.com" then return { { type = resolver.TYPE_A, address = "157.55.39.1" } } end
        return { errcode = 3, errstr = "name error" }
      end,
    }
  end
  local c = CATALOGUE.crawlers
  eq(aicrawl.verify(c.bingbot, "157.55.39.1"), "verified")
  eq(aicrawl.verify(c.bingbot, "10.9.9.9"), "failed", "name outside the operator's domains")
  local n = #queries
  eq(aicrawl.verify(c.bingbot, "157.55.39.1"), "verified", "cached")
  eq(#queries, n, "no lookup for a cached verdict")
end)

test("price headers: USD with at most six decimals", function()
  eq(aicrawl.parse_price("USD 0.01"), 10000)
  eq(aicrawl.parse_price("  USD 1.5 "), 1500000)
  eq(aicrawl.parse_price("USD 2"), 2000000)
  eq(aicrawl.parse_price("USD 0.000001"), 1)
  eq(aicrawl.parse_price("USD 0.0000001"), nil, "seven decimals")
  eq(aicrawl.parse_price("USD 1."), nil)
  eq(aicrawl.parse_price("EUR 1.00"), nil)
  eq(aicrawl.parse_price("usd 1.00"), nil)
  eq(aicrawl.parse_price("USD -1"), nil)
  eq(aicrawl.parse_price({ "USD 1", "USD 2" }), nil, "several headers")
  eq(aicrawl.parse_price(nil), nil)
  eq(aicrawl.format_price(10000), "USD 0.01")
  eq(aicrawl.format_price(1000000), "USD 1.00")
  eq(aicrawl.format_price(1234567), "USD 1.234567")
  eq(aicrawl.format_price(1500), "USD 0.0015")
end)

test("a site's policy: defaults and bounds", function()
  local s = { ai_crawl = { actions = { gptbot = "block" }, block_status = 402, price_micros = 10000, robots_txt = "x\n" } }
  aicrawl.prepare(s)
  eq(s._ai.actions.gptbot, "block")
  eq(s._ai.block_status, 402)
  eq(s._ai.challenge, "js")
  eq(s._ai.impersonators, nil)
  eq(s._ai.price, 10000)
  eq(s._ai.robots, "x\n")
  eq(s._ai.dynamic, false)
  local none = { ai_crawl = "x" }
  aicrawl.prepare(none)
  eq(none._ai, nil)
  local odd = { ai_crawl = { block_status = 500, impersonators = "drop" } }
  aicrawl.prepare(odd)
  eq(odd._ai.block_status, 403)
  eq(odd._ai.impersonators, nil)
end)

test("minute summaries count crawler pairs and their paths", function()
  ngx.shared.edgeweir_stats:flush_all()
  ngx.shared.edgeweir_topstats:flush_all()
  top.reset()
  local minute = math.floor(ngx.time() / 60) * 60 - 120
  for _ = 1, 3 do top.crawler("s1", minute, "gptbot", "verified", 200, 100, false, 10000, false, "/a") end
  top.crawler("s1", minute, "gptbot", "failed", 403, 20, true, nil, false, "/a")
  top.crawler("s1", minute, "gptbot", "verified", 302, 0, false, nil, true, "/robots.txt")
  top.crawler("s1", minute, "gptbot", "verified", 404, 5, false, nil, false, "/b?x=1")
  top.crawler("s1", minute, "claudebot", "unverifiable", 402, 10, true, nil, false, "/b")
  top.flush(ngx.time())
  local bucket
  for _, b in ipairs(stats.drain(ngx.time())) do
    if b.site_id == "s1" then bucket = b end
  end
  assert(bucket, "no bucket")
  local by = {}
  for _, c in ipairs(bucket.crawlers) do by[c.crawler .. "|" .. c.verification] = c end
  local v = by["gptbot|verified"]
  eq(v.requests, 5)
  eq(v.status_2xx, 3)
  eq(v.status_3xx, 1)
  eq(v.status_4xx, 1)
  eq(v.allowed, 4, "below 400 and not refused")
  eq(v.blocked, 0)
  eq(v.bytes, 305)
  eq(v.charged, 3)
  eq(v.charged_micros, 30000)
  eq(v.robots, 1)
  eq(by["gptbot|failed"].blocked, 1)
  eq(by["gptbot|failed"].allowed, 0)
  eq(by["claudebot|unverifiable"].status_4xx, 1)
  eq(bucket.crawlers[1].crawler, "gptbot", "heaviest first")
  local paths = {}
  for _, p in ipairs(bucket.crawler_paths) do paths[p.crawler .. " " .. p.path] = p.requests end
  eq(paths["gptbot /a"], 4)
  eq(paths["gptbot /robots.txt"], 1)
  eq(paths["claudebot /b"], 1)
  eq(paths["gptbot /b?x=1"], nil, "no query strings")
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then os.exit(1) end
