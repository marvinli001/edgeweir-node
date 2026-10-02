-- Lua unit tests for edgeweir.bans (see `make lua-test`):
--
--   resty -I lua --shdict 'edgeweir_bans 4m' test/lua/bans.lua
local cjson = require("cjson.safe")
local bans = require("edgeweir.bans")
local ipaddr = require("edgeweir.ipaddr")
local router = require("edgeweir.router")

local dict = ngx.shared.edgeweir_bans
local passed, failed = 0, 0

local function reset()
  dict:flush_all()
  dict:flush_expired()
  bans.forget()
  bans.capacity = 100000
  bans.clock = function()
    return ngx.now()
  end
end

local function test(name, fn)
  reset()
  ngx.update_time()
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

local function ban(id, cidr, scope, kind, ttl, site)
  return { id = id, cidr = cidr, scope = scope, site_id = site, kind = kind, expires_at = ngx.now() + (ttl or 3600) }
end

local function put(seq, list)
  local st, err, code = bans.replace({ sequence = seq, bans = list })
  assert(st, "replace: " .. tostring(err) .. " " .. tostring(code))
  return st
end

local function key(scope, addr, len)
  return bans.key_for(scope, ipaddr.parse(addr), len)
end

test("keys mask host bits for IPv4 and IPv6", function()
  eq(key("*", "198.51.100.77", 24), key("*", "198.51.100.0", 24), "/24")
  eq(key("*", "198.51.100.77", 24), "e|*|4/24|" .. string.char(198, 51, 100), "/24 key")
  eq(key("*", "198.51.31.255", 20), key("*", "198.51.16.0", 20), "/20 masks inside a byte")
  assert(key("*", "198.51.32.0", 20) ~= key("*", "198.51.16.0", 20), "/20 neighbours differ")
  eq(key("site-a", "203.0.113.7", 32), "e|site-a|4/32|" .. string.char(203, 0, 113, 7), "/32 key")
  eq(key("*", "2001:db8:1:ffff::1", 48), key("*", "2001:db8:1::", 48), "/48")
  eq(#key("*", "2001:db8::1", 128), #"e|*|6/128|" + 16, "/128 keeps 16 bytes")
  assert(key("*", "2001:db8:1::", 48) ~= key("site-a", "2001:db8:1::", 48), "scopes differ")
end)

test("no bans: match reads nothing but the version", function()
  local asked = 0
  local function addr()
    asked = asked + 1
    return "203.0.113.7"
  end
  eq(bans.match("site-a", addr), nil)
  put("1", {})
  eq(bans.match("site-a", addr), nil)
  put("2", { ban("s", "198.51.100.0/24", "site", "m", nil, "site-b") })
  eq(bans.match("site-a", addr), nil)
  eq(asked, 0, "the client address was read without any ban in scope")
  eq(bans.match("site-b", addr), nil)
  eq(asked, 1)
end)

test("lookup across prefix lengths, scopes and families", function()
  local st = put("5", {
    ban("p24", "198.51.100.0/24", "platform", "m"),
    ban("p16", "10.20.0.0/16", "platform", "c"),
    ban("s32", "203.0.113.7/32", "site", "m", nil, "site-a"),
    ban("s48", "2001:db8:1::/48", "site", "m", nil, "site-a"),
  })
  eq(st.sequence, "5")
  eq(st.entries, 4)
  local kind, id = bans.match("site-x", "198.51.100.200")
  eq(kind, "m"); eq(id, "p24")
  kind, id = bans.match("site-x", "10.20.255.1")
  eq(kind, "c"); eq(id, "p16")
  eq(bans.match("site-x", "10.21.0.1"), nil, "outside the /16")
  eq(select(2, bans.match("site-a", "203.0.113.7")), "s32")
  eq(bans.match("site-b", "203.0.113.7"), nil, "site ban on another site")
  eq(bans.match("site-a", "203.0.113.8"), nil, "neighbour address")
  eq(select(2, bans.match("site-a", "2001:db8:1:abcd::99")), "s48")
  eq(bans.match("site-a", "2001:db8:2::1"), nil)
  eq(select(2, bans.match("site-x", "::ffff:198.51.100.9")), "p24", "IPv4-mapped address")
  eq(bans.match("site-a", "unix:"), nil, "not an address")
  eq(bans.match(nil, "198.51.100.1") ~= nil, true, "platform bans without a site")
end)

test("platform bans are checked before site bans", function()
  put("1", {
    ban("site", "203.0.113.7/32", "site", "m", nil, "site-a"),
    ban("platform", "203.0.113.0/24", "platform", "m"),
  })
  eq(select(2, bans.match("site-a", "203.0.113.7")), "platform")
end)

test("bans expire with their TTL", function()
  put("1", { ban("short", "203.0.113.7/32", "platform", "m", 0.3), ban("long", "203.0.113.8/32", "platform", "m", 60) })
  eq(select(2, bans.match("s", "203.0.113.7")), "short")
  ngx.sleep(0.5)
  ngx.update_time()
  eq(bans.match("s", "203.0.113.7"), nil, "expired ban")
  eq(select(2, bans.match("s", "203.0.113.8")), "long")
  -- Already expired bans are not written at all.
  local st = put("2", { ban("gone", "203.0.113.9/32", "platform", "m", -1), ban("long", "203.0.113.8/32", "platform", "m", 60) })
  eq(st.entries, 1)
  eq(bans.match("s", "203.0.113.9"), nil)
end)

test("the ban count follows expiry minute by minute", function()
  local now = ngx.now()
  put("1", { ban("a", "203.0.113.1/32", "platform", "m", 30), ban("b", "203.0.113.2/32", "platform", "m", 600) })
  eq(bans.status().entries, 2)
  bans.clock = function()
    return now + 150
  end
  eq(bans.status().entries, 1, "after the first ban's minute")
  bans.clock = function()
    return now + 700
  end
  eq(bans.status().entries, 0, "after both minutes")
end)

test("replace keeps own bans and drops console bans that are gone", function()
  put("1", { ban("a", "198.51.100.0/24", "platform", "m"), ban("b", "203.0.113.7/32", "site", "c", nil, "site-a") })
  assert(bans.add_auto("site-a", "192.0.2.50", 600, { metric = "ip_qps", observed = 120, threshold = 100, window_seconds = 10 }))
  local st = put("9", { ban("b", "203.0.113.7/32", "site", "c", nil, "site-a"), ban("c", "2001:db8:5::/48", "platform", "m") })
  eq(st.sequence, "9")
  eq(st.entries, 3, "b, c and the own ban")
  eq(bans.match("x", "198.51.100.1"), nil, "a is gone")
  eq(select(2, bans.match("site-a", "203.0.113.7")), "b")
  eq(select(2, bans.match("x", "2001:db8:5::1")), "c")
  eq(bans.match("site-a", "192.0.2.50"), "a", "own ban kept")
end)

test("a delta applies only on top of the data plane's sequence", function()
  put("3", { ban("a", "198.51.100.0/24", "platform", "m") })
  local st, err, code = bans.add({ base = "2", sequence = "4", upsert = {}, remove = {} })
  eq(st, nil); eq(code, 409); assert(err:find("holds 3"), err)
  st = assert(bans.add({ base = "3", sequence = "4", upsert = { ban("b", "203.0.113.0/24", "site", "m", nil, "site-a") } }))
  eq(st.sequence, "4")
  eq(select(2, bans.match("site-a", "203.0.113.99")), "b", "new length of a new scope")
  eq(st.entries, 2)
end)

test("delta removals delete only the ban with the same id", function()
  put("1", { ban("a", "198.51.100.0/24", "platform", "m") })
  assert(bans.add_auto("site-a", "192.0.2.50", 600))
  local st = assert(bans.add({ base = "1", sequence = "2", remove = {
    { id = "other", cidr = "198.51.100.0/24", scope = "platform" },
    { id = "local-1", cidr = "192.0.2.50/32", scope = "site", site_id = "site-a" },
  } }))
  eq(select(2, bans.match("x", "198.51.100.1")), "a", "another id at the same key")
  eq(bans.match("site-a", "192.0.2.50"), "a", "own bans are never removed by the console")
  eq(st.entries, 2)
  st = assert(bans.add({ base = "2", sequence = "3", remove = { { id = "a", cidr = "198.51.100.0/24", scope = "platform" } } }))
  eq(bans.match("x", "198.51.100.1"), nil)
  eq(st.entries, 1)
end)

test("release deletes own bans the console lifted, unless they expire later", function()
  put("1", { ban("c1", "203.0.113.7/32", "site", "c", nil, "site-a") })
  assert(bans.add_auto("site-a", "192.0.2.50", 600))
  assert(bans.add_auto("site-a", "192.0.2.51", 600))
  assert(bans.add_auto("site-b", "2001:db8::7", 600))
  local now = ngx.now()
  local n = assert(bans.release({
    { site_id = "site-a", cidr = "192.0.2.50/32", expires_at = now + 600 },
    -- Lifted before this ban was renewed: it expires later and stays.
    { site_id = "site-a", cidr = "192.0.2.51/32", expires_at = now + 300 },
    -- An IPv6 own ban holds the /64.
    { site_id = "site-b", cidr = "2001:db8::/64", expires_at = now + 600 },
    -- Console bans and unknown addresses are left alone.
    { site_id = "site-a", cidr = "203.0.113.7/32", expires_at = now + 7200 },
    { site_id = "site-a", cidr = "192.0.2.99/32", expires_at = now + 600 },
  }))
  eq(n, 2)
  eq(bans.match("site-a", "192.0.2.50"), nil)
  eq(bans.match("site-b", "2001:db8::7"), nil)
  eq(bans.match("site-b", "2001:db8::8"), nil)
  eq(bans.match("site-a", "192.0.2.51"), "a")
  eq(select(2, bans.match("site-a", "203.0.113.7")), "c1")
  eq(bans.status().entries, 2)
  local _, err, code = bans.release({ { site_id = "site-a", cidr = "192.0.2.0/24", expires_at = now } })
  eq(code, 400); assert(err:find("cidr"), err)
end)

test("capacity evicts own bans, oldest first, before console bans", function()
  bans.capacity = 3
  assert(bans.add_auto("site-a", "192.0.2.1", 600))
  assert(bans.add_auto("site-a", "192.0.2.2", 600))
  assert(bans.add_auto("site-a", "192.0.2.3", 600))
  local st = put("1", { ban("m1", "198.51.100.0/24", "platform", "m"), ban("c1", "203.0.113.0/24", "platform", "c") })
  eq(st.entries, 3)
  eq(st.auto_evicted, 2)
  eq(bans.match("site-a", "192.0.2.1"), nil, "oldest own ban evicted")
  eq(bans.match("site-a", "192.0.2.2"), nil, "second oldest evicted")
  eq(bans.match("site-a", "192.0.2.3"), "a", "newest own ban kept")
  -- A new own ban replaces the older own one, never a console ban.
  assert(bans.add_auto("site-a", "192.0.2.4", 600))
  eq(bans.match("site-a", "192.0.2.3"), nil)
  eq(bans.match("site-a", "192.0.2.4"), "a")
  eq(bans.match("x", "198.51.100.1"), "m")
  -- Full of console bans: an own ban does not fit.
  bans.capacity = 2
  put("2", { ban("m1", "198.51.100.0/24", "platform", "m"), ban("c1", "203.0.113.0/24", "platform", "c") })
  local ok, err = bans.add_auto("site-a", "192.0.2.5", 600)
  eq(ok, nil); eq(err, "full")
  eq(bans.match("x", "203.0.113.1"), "c")
end)

test("manual bans that do not fit are reported, automatic ones counted", function()
  bans.capacity = 2
  local st = put("7", {
    ban("m1", "198.51.100.1/32", "platform", "m"),
    ban("m2", "198.51.100.2/32", "platform", "m"),
    ban("m3", "198.51.100.3/32", "platform", "m"),
    ban("c1", "198.51.100.4/32", "platform", "c"),
  })
  eq(st.entries, 2)
  eq(st.unapplied, 1)
  eq(cjson.encode(st.unapplied_ids), '["m3"]')
  eq(st.auto_evicted, 1)
  eq(bans.match("x", "198.51.100.3"), nil)
  -- Retried once there is room (the agent resends the unapplied bans).
  bans.capacity = 3
  st = assert(bans.add({ base = "7", sequence = "7", upsert = { ban("m3", "198.51.100.3/32", "platform", "m") } }))
  eq(st.unapplied, 0)
  eq(cjson.encode(st.unapplied_ids), "[]")
  eq(bans.match("x", "198.51.100.3"), "m")
  -- Removing an unapplied ban forgets it.
  bans.capacity = 3
  st = assert(bans.add({ base = "7", sequence = "8", upsert = { ban("m4", "198.51.100.5/32", "platform", "m") } }))
  eq(st.unapplied, 1)
  st = assert(bans.add({ base = "8", sequence = "9", remove = { { id = "m4", cidr = "198.51.100.5/32", scope = "platform" } } }))
  eq(st.unapplied, 0)
end)

test("own bans are queued for reporting and drained", function()
  assert(bans.add_auto("site-a", "192.0.2.1", 60, { reason = "cc_ip_rate", metric = "ip_qps", observed = 250, threshold = 100, window_seconds = 10 }))
  assert(bans.add_auto("site-b", "2001:db8::7", 120))
  assert(bans.add_auto("site-a", "192.0.2.2", 60))
  eq(bans.status().pending_reports, 3)
  local first = bans.drain(2)
  eq(#first, 2)
  eq(first[1].site_id, "site-a"); eq(first[1].ip, "192.0.2.1"); eq(first[1].prefix_len, 32)
  eq(first[1].metric, "ip_qps"); eq(first[1].observed, 250); eq(first[1].window_seconds, 10)
  eq(first[1].reason, "cc_ip_rate")
  assert(first[1].expires_at - first[1].created_at == 60)
  eq(first[2].ip, "2001:db8::"); eq(first[2].prefix_len, 64)
  local rest = bans.drain()
  eq(#rest, 1)
  eq(cjson.encode(bans.drain()), "[]", "empty drain encodes as an array")
  eq(bans.match("site-b", "2001:db8::7"), "a")
  eq(bans.match("site-b", "2001:db8::ffff:1"), "a", "another address of the /64")
  eq(bans.match("site-b", "2001:db8:0:1::7"), nil, "the next /64")
end)

test("own bans hold an IPv4 address or an IPv6 /64, never loopback", function()
  assert(bans.add_auto("site-a", "2001:db8:aa:bb::/64", 60))
  assert(bans.add_auto("site-a", "2001:db8:aa:bb:1::1", 60), "the same /64 again")
  assert(bans.add_auto("site-a", "::ffff:192.0.2.9", 60), "IPv4-mapped: the IPv4 address")
  eq(bans.status(true).entries, 2)
  local list = bans.drain()
  eq(list[1].ip, "2001:db8:aa:bb::"); eq(list[1].prefix_len, 64)
  eq(list[3].ip, "192.0.2.9"); eq(list[3].prefix_len, 32)
  eq(bans.match("site-a", "2001:db8:aa:bb:ffff::2"), "a")
  eq(bans.match("site-a", "192.0.2.9"), "a")
  for _, addr in ipairs({ "127.0.0.1", "127.1.2.3", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1" }) do
    local ok, err = bans.add_auto("site-a", addr, 60)
    eq(ok, nil, addr); eq(err, "protected address", addr)
  end
  eq(bans.add_auto("site-a", "2001:db8::/48", 60), nil, "only a /64")
  eq(bans.add_auto("site-a", "192.0.2.0/24", 60), nil, "only an address")
end)

test("add_auto validates its input and extends an own ban", function()
  eq(bans.add_auto("bad site", "192.0.2.1", 60), nil)
  eq(bans.add_auto("site-a", "not-an-ip", 60), nil)
  eq(bans.add_auto("site-a", "192.0.2.1", 0), nil)
  eq(bans.add_auto("site-a", "192.0.2.1", 8 * 86400), nil)
  assert(bans.add_auto("site-a", "192.0.2.1", 600))
  assert(bans.add_auto("site-a", "192.0.2.1", 60))
  local st = bans.status(true)
  eq(st.entries, 1)
  eq(#st.bans, 1)
  assert(st.bans[1].expires_at > ngx.now() + 500, "the later expiry wins")
  -- An address a console ban holds is reported but not stored again.
  put("1", { ban("m", "203.0.113.0/24", "site", "m", nil, "site-a") })
  bans.drain()
  assert(bans.add_auto("site-a", "203.0.113.5", 60))
  eq(#bans.drain(), 1)
  eq(select(2, bans.match("site-a", "203.0.113.5")), "m")
end)

test("the eviction queue does not grow with repeated own bans", function()
  for _ = 1, 20 do
    assert(bans.add_auto("site-a", "192.0.2.1", 600))
  end
  assert(dict:llen("#q") <= 2, "queue length " .. tostring(dict:llen("#q")))
  eq(bans.status().entries, 1)
  bans.capacity = 1
  put("1", { ban("m", "198.51.100.0/24", "platform", "m") })
  eq(bans.match("site-a", "192.0.2.1"), nil, "the own ban is still evictable")
end)

test("the control documents are validated", function()
  local cases = {
    { sequence = "x", bans = {} },
    { sequence = "1", bans = { { id = "a b", cidr = "192.0.2.0/24", scope = "platform", kind = "m", expires_at = 1 } } },
    { sequence = "1", bans = { { id = "a", cidr = "10.0.0.0/8", scope = "platform", kind = "m", expires_at = 1 } } },
    { sequence = "1", bans = { { id = "a", cidr = "2001:db8::/32", scope = "platform", kind = "m", expires_at = 1 } } },
    { sequence = "1", bans = { { id = "a", cidr = "192.0.2.0/24", scope = "site", kind = "m", expires_at = 1 } } },
    { sequence = "1", bans = { { id = "a", cidr = "192.0.2.0/24", scope = "platform", kind = "x", expires_at = 1 } } },
    { sequence = "1", bans = { { id = "a", cidr = "192.0.2.0/24", scope = "platform", kind = "m" } } },
    { sequence = "1", bans = "nope" },
  }
  for i, doc in ipairs(cases) do
    local st, _, code = bans.replace(doc)
    eq(st, nil, "case " .. i)
    eq(code, 400, "case " .. i)
  end
  eq(bans.status().sequence, "0", "nothing applied")
  local st, _, code = bans.add({ base = "0", sequence = "1", remove = { { id = "a", cidr = "x", scope = "platform" } } })
  eq(st, nil); eq(code, 400)
end)

test("status lists bans on request", function()
  put("12345678901234567", { ban("p", "198.51.100.0/24", "platform", "m"), ban("s", "2001:db8:1::/48", "site", "c", nil, "site-a") })
  local st = bans.status(true)
  eq(st.sequence, "12345678901234567", "sequences stay exact")
  eq(#st.bans, 2)
  local by = {}
  for _, b in ipairs(st.bans) do
    by[b.id] = b
  end
  eq(by.p.scope, "platform"); eq(by.p.cidr, "198.51.100.0/24"); eq(by.p.kind, "m"); eq(by.p.site_id, nil)
  eq(by.s.scope, "site"); eq(by.s.site_id, "site-a"); eq(by.s.cidr, "2001:db8:1::/48")
  eq(bans.status().bans, nil, "no list by default")
end)

test("platform allow lists exempt addresses from bans", function()
  local expressions = require("edgeweir.expressions")
  local site = { _config = { allows = { expressions.ip_set({ "198.51.100.0/28" }) } } }
  eq(router.platform_allowed(site, "198.51.100.3"), true)
  eq(router.platform_allowed(site, "198.51.100.30"), false)
  eq(router.platform_allowed({ _config = {} }, "198.51.100.3"), false)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
