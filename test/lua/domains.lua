-- Proto v0.25.0 in the HTTP data plane: suffix and pattern domains
-- (domains-v2) and the unknown host handling with scan protection
-- (unknown-host-v1).
--
--   resty -I lua --shdict 'edgeweir_sites 4m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_cc 1m' --shdict 'edgeweir_bans 1m' test/lua/domains.lua
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local errorpages = require("edgeweir.errorpages")
local unknownhost = require("edgeweir.unknownhost")
local bans = require("edgeweir.bans")
local policy = require("edgeweir.policy")
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

local function site(id, domains)
  return {
    id = id, cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random",
    domains = domains,
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
  }
end

-- domain turns a formatted domain of the shared vectors into a site table domain.
local function domain(formatted, order)
  if formatted:sub(1, 1) == "~" then
    return { name = formatted:sub(2), match = "regex", order = order }
  elseif formatted:sub(1, 2) == "*." then
    return { name = formatted:sub(3), wildcard = true }
  elseif formatted:sub(1, 1) == "." then
    return { name = formatted:sub(2), match = "suffix" }
  end
  return { name = formatted }
end

test("lookup_host: the shared vectors (exact, *., the longest ., patterns by order)", function()
  local f = assert(io.open("/t/host-match-vectors.json"))
  local v = cjson.decode(f:read("*a"))
  f:close()
  local list = {}
  for _, s in ipairs(v.sites) do
    local domains, index = {}, 0
    for _, d in ipairs(s.domains) do
      local entry = domain(d, s.created * 16 + index)
      if entry.match == "regex" then index = index + 1 end
      domains[#domains + 1] = entry
    end
    list[#list + 1] = site(s.id, domains)
  end
  assert(store.replace({ revision = "1", sites = list }))
  for _, c in ipairs(v.cases) do
    local found = store.lookup_host(c.host)
    local want = c.site ~= cjson.null and c.site or nil
    eq(found and found.id, want, c.host)
    -- A second lookup comes from the caches and agrees.
    found = store.lookup_host(c.host)
    eq(found and found.id, want, c.host .. " (cached)")
  end
  assert(#v.cases > 25)
end)

test("lookup_host: how the site was found; patterns never stored as host names", function()
  assert(store.replace({ revision = "2", sites = {
    site("s1", { { name = "a.test" }, { name = "a.test", wildcard = true }, { name = "a.test", match = "suffix" },
      { name = "x\\.test", match = "regex", order = 1 } }),
  } }))
  local s, ver, how = store.lookup_host("a.test")
  eq(s.id, "s1")
  eq(how, "exact")
  assert(ver)
  local _
  _, _, how = store.lookup_host("b.a.test")
  eq(how, "wildcard")
  _, _, how = store.lookup_host("c.b.a.test")
  eq(how, "match")
  _, _, how = store.lookup_host("x.test")
  eq(how, "match")
  eq(store.lookup_host("x\\.test"), nil, "a pattern is no host name")
  eq(store.lookup_host("xxtest"), nil, "anchored, and . matches one character")
  eq(ngx.shared.edgeweir_sites:get("v" .. ver .. ":host:x\\.test"), nil)
end)

test("replace: a pattern PCRE2 refuses rejects the table", function()
  local before = store.status().version
  local st, err, code = store.replace({ revision = "3", sites = { site("bad", { { name = "a(", match = "regex", order = 1 } }) } })
  eq(st, nil)
  eq(code, 400)
  assert(err:find("invalid domain pattern"), err)
  eq(store.status().version, before, "the table stays")
end)

test("offline hosts: suffix and pattern domains of disabled sites keep their page", function()
  assert(store.replace({ revision = "4", sites = { site("s1", { { name = "a.test" } }) }, offline_hosts = {
    { name = "off.test", reason = "disabled" },
    { name = "deep.test", match = "suffix", reason = "disabled" },
    { name = "p\\d+\\.test", match = "regex", reason = "disabled" },
  } }))
  local cfg = store.config()
  eq(errorpages.offline_reason(cfg, "off.test"), "disabled")
  eq(errorpages.offline_reason(cfg, "x.y.deep.test"), "disabled")
  eq(errorpages.offline_reason(cfg, "deep.test"), nil, "a suffix is not its own host")
  eq(errorpages.offline_reason(cfg, "p7.test"), "disabled")
  eq(errorpages.offline_reason(cfg, "p.test"), nil)
end)

test("unknown_hosts: the table's handling, defaults for anything else", function()
  assert(store.replace({ revision = "5", sites = { site("s1", { { name = "a.test" } }) },
    unknown_hosts = { unknown_host = "close", ip_access = "site", default_site_id = "s1", default_certificate = true,
      scan_threshold = 100, scan_ban_seconds = 600 } }))
  local u = store.config().unknown
  eq(u.unknown_host, "close")
  eq(u.ip_access, "site")
  eq(u.default_site_id, "s1")
  eq(u.default_certificate, true)
  eq(u.scan_threshold, 100)
  eq(u.scan_ban_seconds, 600)
  assert(store.replace({ revision = "6", sites = { site("s1", { { name = "a.test" } }) },
    unknown_hosts = { unknown_host = "redirect", scan_threshold = 5 } }))
  u = store.config().unknown
  eq(u.unknown_host, "page")
  eq(u.ip_access, "page")
  eq(u.scan_threshold, 0, "a threshold without ban seconds is off")
  assert(store.replace({ revision = "7", sites = { site("s1", { { name = "a.test" } }) } }))
  eq(store.config().unknown, nil)
end)

test("ip_access: IP literals and empty hosts", function()
  for _, host in ipairs({ "", "_", "203.0.113.5", "[2001:db8::1]", "[::1]" }) do
    eq(unknownhost.ip_access(host), true, host)
  end
  for _, host in ipairs({ "a.test", "203.0.113.5.nip.io", "1.2.3", "localhost" }) do
    eq(unknownhost.ip_access(host), false, host)
  end
  eq(unknownhost.ip_access(nil), true)
end)

test("action: node IP access and unknown hosts each by their setting", function()
  local cfg = { unknown = { unknown_host = "close", ip_access = "site" } }
  eq(unknownhost.action(cfg, "x.test"), "close")
  eq(unknownhost.action(cfg, "198.51.100.1"), "site")
  eq(unknownhost.action({}, "x.test"), "page", "no setting")
end)

-- banned tells whether addr is banned on a site (bans.match returns the ban's kind).
local function banned(site_id, addr)
  return bans.match(site_id, function() return addr end) ~= nil
end

test("scan protection: the request after the threshold bans at platform scope, once", function()
  bans.clock = function() return 1791331200 end
  -- A short guard against concurrent bans, so the test can wait it out.
  unknownhost.BAN_GUARD = 1
  local cfg = policy.prepare_config({ ip_lists = { { id = "allow", platform = true, kind = "allow", entries = { "192.0.2.200/32" } } } })
  cfg.trusted = expressions.ip_set({ "10.0.0.0/8" })
  cfg.unknown = { unknown_host = "page", ip_access = "page", scan_threshold = 3, scan_ban_seconds = 600 }
  for i = 1, 3 do eq(unknownhost.count(cfg, "192.0.2.50"), i) end
  eq(banned("any-site", "192.0.2.50"), false, "not yet")
  eq(unknownhost.count(cfg, "192.0.2.50"), 4)
  eq(banned("any-site", "192.0.2.50"), true, "banned on every site")
  eq(unknownhost.count(cfg, "192.0.2.50"), 5, "still counted")
  local reports = bans.drain()
  eq(#reports, 1, "one ban")
  local r = reports[1]
  eq(r.site_id, "*")
  eq(r.ip, "192.0.2.50")
  eq(r.prefix_len, 32)
  eq(r.reason, "unknown_host_scan")
  eq(r.metric, "unknown_host_requests")
  eq(r.observed, 4)
  eq(r.threshold, 3)
  eq(r.window_seconds, 60)
  eq(r.expires_at - r.created_at, 600)
  -- IPv6 clients by their /64; allowed and trusted addresses are not counted.
  for _ = 1, 3 do unknownhost.count(cfg, "2001:db8:1:2::1") end
  eq(unknownhost.count(cfg, "2001:db8:1:2::ffff"), 4, "the same /64")
  eq(banned("x", "2001:db8:1:2::77"), true)
  for _ = 1, 10 do
    eq(unknownhost.count(cfg, "192.0.2.200"), nil, "allow list")
    eq(unknownhost.count(cfg, "10.1.2.3"), nil, "trusted proxy")
  end
  eq(unknownhost.count({ unknown = { scan_threshold = 0 } }, "192.0.2.51"), nil, "off")
  -- The console lifts the node's own platform ban: the address is counted
  -- afresh and banned again if it keeps scanning.
  eq(bans.release({ { site_id = "*", cidr = "192.0.2.50/32", expires_at = 1791331200 + 600 } }), 1)
  eq(banned("any-site", "192.0.2.50"), false, "lifted")
  for i = 1, 3 do eq(unknownhost.count(cfg, "192.0.2.50"), i, "a new window") end
  eq(banned("any-site", "192.0.2.50"), false, "not yet again")
  eq(unknownhost.count(cfg, "192.0.2.50"), 4)
  eq(banned("any-site", "192.0.2.50"), true, "banned again")
  reports = bans.drain()
  eq(#reports, 2, "the IPv6 ban and the new one")
  eq(reports[2].ip, "192.0.2.50")
  -- The same for an IPv6 /64.
  eq(bans.release({ { site_id = "*", cidr = "2001:db8:1:2::/64", expires_at = 1791331200 + 600 } }), 1)
  eq(unknownhost.count(cfg, "2001:db8:1:2::9"), 1, "the /64 counted afresh")
  -- A shared ban (the console's copy took the node's entry) lifted by the
  -- console: the next request over the threshold bans again.
  local shared = { id = "shared-1", cidr = "192.0.2.50/32", scope = "platform", kind = "c", expires_at = 1791331200 + 600 }
  assert(bans.replace({ sequence = "77", bans = { shared } }))
  eq(banned("any-site", "192.0.2.50"), true, "the shared copy")
  assert(bans.add({ base = "77", sequence = "78", upsert = {}, remove = { shared } }))
  eq(banned("any-site", "192.0.2.50"), false, "no ban left")
  ngx.sleep(1.1)
  eq(unknownhost.count(cfg, "192.0.2.50"), 5, "still counted, the guard expired")
  eq(banned("any-site", "192.0.2.50"), true, "banned again after the shared ban was lifted")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
