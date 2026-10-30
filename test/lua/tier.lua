-- The tiered cache's pure parts (edgeweir.tier): the URL and key the lower
-- tier sends, the upper tier's key (generation and epoch), client
-- certificate subjects, upper tier selection and the log values.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--         --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_purge 1m' --shdict 'edgeweir_tags 1m' test/lua/tier.lua
local tier = require("edgeweir.tier")

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

test("the purge URL survives the header round trip", function()
  for _, c in ipairs({
    { "example.com", "/a b/ü%2F", "x=1&y=a b" },
    { "example.com", "/", nil },
    { "[::1]", "/p", "" },
    { "h", "/-", "-" },
  }) do
    local v = tier.url_value(c[1], c[2], c[3])
    assert(not v:find("[\r\n]"), "no line breaks")
    local h, p, a = tier.parse_url(v)
    eq(h, c[1], "host"); eq(p, c[2], "path"); eq(a, c[3], "args")
  end
  eq(tier.parse_url("example.com nopath -"), nil, "a path starts with /")
  eq(tier.parse_url(nil), nil)
end)

test("split_key separates the epoch", function()
  local b, e = tier.split_key("s1:3:https://h/p")
  eq(b, "s1:3:https://h/p"); eq(e, 0)
  b, e = tier.split_key("s1:3:https://h/p?q#1730000000123")
  eq(b, "s1:3:https://h/p?q"); eq(e, 1730000000123)
  eq(tier.split_key("s1:3:h#x"), nil, "a non-numeric epoch")
end)

test("the upper tier keeps the higher generation and the higher epoch", function()
  local site = { id = "s1", cache_generation = "3" }
  local key = tier.upper_key(site, "s1:3:https://h/p#100", function() return 50 end)
  eq(key, "s1:3:https://h/p#100", "the lower tier purged later")
  key = tier.upper_key(site, "s1:3:https://h/p#100", function() return 200 end)
  eq(key, "s1:3:https://h/p#200", "this node purged later")
  key = tier.upper_key(site, "s1:3:https://h/p", function() return 0 end)
  eq(key, "s1:3:https://h/p", "no purge")
  key = tier.upper_key(site, "s1:2:https://h/p", function() return 0 end)
  eq(key, "s1:3:https://h/p", "the lower tier's older generation")
  key = tier.upper_key(site, "s1:4:https://h/p", function() return 0 end)
  eq(key, "s1:4:https://h/p", "the lower tier's newer generation")
  local big = { id = "s1", cache_generation = "18446744073709551615" }
  key = tier.upper_key(big, "s1:9:https://h/p", function() return 0 end)
  eq(key, "s1:18446744073709551615:https://h/p", "uint64 generations compare as decimals")
  eq(tier.upper_key(site, "s2:3:https://h/p", function() return 0 end), nil, "another site's key")
  eq(tier.upper_key(site, "s1:3:", function() return 0 end), nil, "an empty key")
  -- The local epoch sees the base with the generation it will use.
  local seen
  tier.upper_key(site, "s1:1:https://h/p#5", function(b) seen = b; return 0 end)
  eq(seen, "s1:3:https://h/p")
end)

test("only node certificates name a client", function()
  eq(tier.client_node("CN=6f1c2b9e-1111-4a5b-8c9d-0123456789ab,O=Edgeweir Node"), "6f1c2b9e-1111-4a5b-8c9d-0123456789ab")
  eq(tier.client_node("O=Edgeweir Node,CN=n1"), "n1", "any order")
  eq(tier.client_node("CN=p1,O=Edgeweir Probe"), nil, "a probe")
  eq(tier.client_node("CN=n1"), nil, "no organization")
  eq(tier.client_node("CN=n1,CN=n2,O=Edgeweir Node"), nil, "two names")
  eq(tier.client_node("CN=a b,O=Edgeweir Node"), nil, "not an id")
  eq(tier.client_node(nil), nil)
end)

test("the site table keeps the tier listener's clients", function()
  local store = require("edgeweir.store")
  assert(store.replace({ revision = "t1", sites = {}, tier_clients = { "n1", "n2" } }))
  local clients = store.config().tier_clients
  eq(type(clients), "table", "tier_clients")
  eq(clients[1], "n1")
  eq(clients[2], "n2")
  assert(store.replace({ revision = "t2", sites = {} }))
  eq(store.config().tier_clients, nil, "without a tier listener")
end)

test("upper tiers the request passed or that are down are skipped", function()
  local peers = {
    { id = "u1", cdn_id = "edgeweir-aaaa" },
    { id = "u2", cdn_id = "edgeweir-bbbb" },
    { id = "u3", cdn_id = "edgeweir-cccc" },
  }
  local c = tier.candidates(peers, function() return false end, function() return false end)
  eq(#c, 3); eq(c[1].id, "u1", "the plan's order")
  c = tier.candidates(peers, function(cdn) return cdn == "edgeweir-aaaa" end, function(id) return id == "u2" end)
  eq(#c, 1); eq(c[1].id, "u3")
end)

test("log values and counter keys", function()
  eq(tier.status_key("HIT"), "HIT"); eq(tier.status_key("weird"), "-"); eq(tier.status_key(nil), "-")
  eq(tier.log_value("u1 MISS"), "u1 MISS")
  eq(tier.log_value("u1 ODD"), "u1 -")
  eq(tier.log_value("origin"), "origin")
  eq(tier.log_value("u 1 HIT"), nil)
  eq(tier.log_value(nil), nil)
end)

test("a node is marked down after repeated failures and recovers", function()
  local d = ngx.shared.edgeweir_health
  d:flush_all()
  -- account() is internal: drive it through fallback_log's parsing.
  local saved = ngx.var
  ngx.var = { edgeweir_tier_tried = "u1,u2", upstream_status = "502, 504 : 200", upstream_header_time = "-, - : 0.010" }
  tier.fallback_log()
  tier.fallback_log()
  ngx.var = saved
  assert(d:get("tier|d|u1"), "u1 down after two failures")
  assert(d:get("tier|d|u2"), "u2 down after two timeouts")
  local c = tier.candidates({ { id = "u1", cdn_id = "x" }, { id = "u3", cdn_id = "y" } }, function() return false end,
    function(id) return d:get("tier|d|" .. id) ~= nil end)
  eq(#c, 1); eq(c[1].id, "u3")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
