-- Layer-4 applications (edgeweir.l4, edgeweir.l4control,
-- edgeweir.proxyproto): PROXY protocol headers against the spec's bytes
-- and nginx's own v2 output, origin selection with backups and passive
-- health, IP lists, rates and connection limits with the crash sweep,
-- minute statistics, the table store and the control relay's dispatch.
--
--   resty -I lua --shdict 'edgeweir_l4 1m' --shdict 'edgeweir_l4_state 1m' --shdict 'edgeweir_l4_stats 1m' test/lua/l4.lua
local cjson = require("cjson.safe")
local dns = require("edgeweir.dns")
local l4 = require("edgeweir.l4")
local l4control = require("edgeweir.l4control")
local pp = require("edgeweir.proxyproto")

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

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function ids(list)
  local out = {}
  for i, o in ipairs(list) do
    out[i] = o.id
  end
  return table.concat(out, ",")
end

-- rand returns a deterministic sequence for weighted_order.
local function seq(...)
  local values, i = { ... }, 0
  return function()
    i = i + 1
    return values[(i - 1) % #values + 1]
  end
end

local function app(fields)
  local a = {
    id = "app-a", protocol = "tcp", port = 9000, max_fails = 2, fail_timeout = 30, connect_timeout_ms = 500, idle_timeout = 60,
    max_connections = 0, new_connections_per_second = 0, proxy_protocol_version = 0,
    origins = {
      { id = "p1", address = "10.0.0.1", port = 7000, weight = 1 },
      { id = "p2", address = "10.0.0.2", port = 7000, weight = 3 },
      { id = "b1", address = "10.0.0.3", port = 7000, weight = 1, backup = true },
    },
  }
  for k, v in pairs(fields or {}) do
    a[k] = v
  end
  return a
end

local function reset()
  ngx.shared.edgeweir_l4:flush_all()
  ngx.shared.edgeweir_l4_state:flush_all()
  ngx.shared.edgeweir_l4_stats:flush_all()
end

------------------------------------------------------------------------

local SIG = "0d0a0d0a000d0a515549540a"

test("proxyproto v2: IPv4 equals nginx's own proxy_protocol v2 header", function()
  -- Captured from OpenResty 1.31.1.1 (proxy_protocol v2) for a client
  -- 127.0.0.1:38506 connected to 127.0.0.1:9000.
  eq(hex(pp.v2("127.0.0.1", "127.0.0.1", 38506, "9000")), SIG .. "2111000c7f0000017f000001966a2328")
  -- Spec layout: version 2 + PROXY, AF_INET + STREAM, 12 bytes of
  -- addresses, source then destination, ports in network order.
  eq(hex(pp.v2("203.0.113.7", "198.51.100.9", 40000, 443)), SIG .. "2111000c" .. "cb007107" .. "c6336409" .. "9c40" .. "01bb")
  eq(#pp.v2("203.0.113.7", "198.51.100.9", 40000, 443), 16 + 12)
end)

test("proxyproto v2: IPv6, mixed families as IPv4-mapped, unknown", function()
  eq(hex(pp.v2("2001:db8::1", "2001:db8::2", "40000", 443)),
    SIG .. "21210024" .. "20010db8000000000000000000000001" .. "20010db8000000000000000000000002" .. "9c40" .. "01bb")
  eq(#pp.v2("2001:db8::1", "2001:db8::2", 40000, 443), 16 + 36)
  eq(hex(pp.v2("192.0.2.1", "2001:db8::2", 1, 2)),
    SIG .. "21210024" .. "00000000000000000000ffffc0000201" .. "20010db8000000000000000000000002" .. "0001" .. "0002")
  -- Unusable input: PROXY command, AF_UNSPEC, no addresses.
  eq(hex(pp.v2("unix:", "127.0.0.1", 1, 2)), SIG .. "21000000")
  eq(hex(pp.v2("127.0.0.1", "127.0.0.1", 70000, 2)), SIG .. "21000000")
  eq(hex(pp.v2(nil, nil, nil, nil)), SIG .. "21000000")
end)

test("proxyproto v1: TCP4, TCP6, mixed, unknown", function()
  eq(pp.v1("203.0.113.7", "198.51.100.9", 40000, "443"), "PROXY TCP4 203.0.113.7 198.51.100.9 40000 443\r\n")
  eq(pp.v1("2001:db8::1", "2001:db8::2", 40000, 443), "PROXY TCP6 2001:db8::1 2001:db8::2 40000 443\r\n")
  eq(pp.v1("192.0.2.1", "2001:db8::2", 1, 2), "PROXY TCP6 0:0:0:0:0:ffff:c000:201 2001:db8::2 1 2\r\n")
  eq(pp.v1("", "127.0.0.1", 1, 2), "PROXY UNKNOWN\r\n")
  eq(pp.v1("127.0.0.1", "127.0.0.1", -1, 2), "PROXY UNKNOWN\r\n")
end)

------------------------------------------------------------------------

test("order: weighted among healthy primaries, backups only when every primary is down", function()
  reset()
  local a = app()
  local never = function() return false end
  -- r * total(4): 0.1*4=0.4 < 1 picks p1, then p2.
  eq(ids(l4.order(a, 100, never, seq(0.1, 0.1))), "p1,p2")
  -- 0.5*4=2 passes p1 (1): p2 first.
  eq(ids(l4.order(a, 100, never, seq(0.5, 0.1))), "p2,p1")
  -- One primary down: the other one only (backups never take traffic
  -- while a primary is up).
  local p1down = function(_, id) return id == "p1" end
  eq(ids(l4.order(a, 100, p1down, seq(0.9))), "p2")
  -- Every primary down: the healthy backups.
  local prims = function(_, id) return id ~= "b1" end
  eq(ids(l4.order(a, 100, prims, seq(0.9))), "b1")
  -- Everything down: all of them, primaries first (fail open).
  eq(ids(l4.order(a, 100, function() return true end, seq(0.1))), "p1,p2,b1")
  -- At most MAX_TRIES.
  local many = app({ origins = {} })
  for i = 1, 5 do
    many.origins[i] = { id = "o" .. i, address = "x", port = 1, weight = 1 }
  end
  eq(#l4.order(many, 100, never), l4.MAX_TRIES)
  -- Forbidden origins are never used, not even failing open.
  local f = app()
  f.origins[1].forbidden = true
  f.origins[3].forbidden = true
  eq(ids(l4.order(f, 100, function() return true end, seq(0.1))), "p2")
  -- Only backups: they take the traffic.
  local b = app({ origins = { { id = "b1", address = "x", port = 1, weight = 1, backup = true } } })
  eq(ids(l4.order(b, 100, never)), "b1")
end)

test("weighted_order: proportional to weight", function()
  math.randomseed(42)
  local list = { { id = "a", weight = 1 }, { id = "b", weight = 9 } }
  local first = { a = 0, b = 0 }
  for _ = 1, 10000 do
    local o = l4.weighted_order(list)
    first[o[1].id] = first[o[1].id] + 1
  end
  assert(first.b > 8500 and first.b < 9500, "b first " .. first.b .. " of 10000")
end)

test("passive health: max_fails within fail_timeout takes an origin out; success brings it back", function()
  reset()
  local a = app()
  eq(l4.failure(a, "p1", 1000), false)
  eq(l4.is_down("app-a", "p1", 1000), false)
  eq(l4.failure(a, "p1", 1001), true, "second failure")
  eq(l4.is_down("app-a", "p1", 1001), true)
  eq(l4.is_down("app-a", "p1", 1031), false, "after fail_timeout")
  eq(l4.is_down("app-b", "p1", 1001), false, "per application")
  -- A success ends the count and the down period.
  l4.success(a, "p1")
  eq(l4.is_down("app-a", "p1", 1001), false)
  eq(l4.failure(a, "p2", 1000), false)
  l4.success(a, "p2")
  eq(l4.failure(a, "p2", 1000), false, "consecutive failures only")
  -- The default check reads the shared dict.
  l4.failure(a, "p1", ngx.now())
  l4.failure(a, "p1", ngx.now())
  eq(ids(l4.order(a, ngx.now(), nil, seq(0.1))), "p2")
  local st = l4.status()
  eq(st.version, 0, "no table yet")
end)

test("peers: resolves in order; a failing name is a health failure and skipped", function()
  reset()
  local resolve = dns.resolve
  dns.resolve = function(host, allowed)
    eq(allowed, "ALLOWED")
    if host == "bad.test" then
      return nil, "dns bad.test: no address", "dns_failed"
    end
    return "192.0.2." .. #host
  end
  local a = app({ max_fails = 1, origins = {
    { id = "o1", address = "bad.test", port = 1, weight = 1 },
    { id = "o2", address = "good.test", port = 2, weight = 1 },
  } })
  local peers = l4.peers(a, { allowed = "ALLOWED" }, ngx.now())
  dns.resolve = resolve
  eq(#peers, 1)
  eq(peers[1].origin.id, "o2")
  eq(peers[1].ip, "192.0.2.9")
  eq(peers[1].port, 2)
  eq(l4.is_down("app-a", "o1", ngx.now()), true, "unresolvable origin counted")
end)

------------------------------------------------------------------------

test("admit: allow and block lists by client address", function()
  reset()
  local doc = assert(l4.prepare({
    revision = "1",
    ip_lists = { { id = "allow", entries = { "198.51.100.0/24", "2001:db8::/32" } }, { id = "block", entries = { "198.51.100.7/32" } } },
    apps = { app({ allow_lists = { "allow" }, block_lists = { "block" } }), app({ id = "app-b", port = 9001, block_lists = { "block" } }) },
  }))
  local a, b = doc.by_port["tcp:9000"], doc.by_port["tcp:9001"]
  eq(l4.admit(a, "198.51.100.8", 1, 11), nil)
  eq(l4.admit(a, "2001:db8::5", 1, 11), nil)
  eq(l4.admit(a, "::ffff:198.51.100.9", 1, 11), nil, "IPv4-mapped")
  eq(l4.admit(a, "203.0.113.1", 1, 11), "allow_list")
  eq(l4.admit(a, "198.51.100.7", 1, 11), "block_list", "blocked inside the allow list")
  eq(l4.admit(b, "203.0.113.1", 1, 11), nil, "no allow list: every address")
  eq(l4.admit(b, "198.51.100.7", 1, 11), "block_list")
  eq(ngx.shared.edgeweir_l4_state:get("c|app-a"), 3)
end)

test("admit: new connections per second and concurrent connections per node", function()
  reset()
  local a = app({ new_connections_per_second = 2 })
  eq(l4.admit(a, "192.0.2.1", 100.1, 11), nil)
  eq(l4.admit(a, "192.0.2.1", 100.9, 11), nil)
  eq(l4.admit(a, "192.0.2.1", 100.95, 11), "rate")
  eq(l4.admit(a, "192.0.2.1", 101.0, 11), nil, "next second")
  reset()
  local c = app({ max_connections = 2 })
  local _, n = l4.admit(c, "192.0.2.1", 1, 11)
  eq(n, 1)
  _, n = l4.admit(c, "192.0.2.1", 1, 12)
  eq(n, 2)
  eq(l4.admit(c, "192.0.2.1", 1, 11), "limit")
  eq(ngx.shared.edgeweir_l4_state:get("c|app-a"), 2, "a refusal holds nothing")
  l4.release("app-a", 11)
  eq(l4.admit(c, "192.0.2.1", 1, 11), nil, "a slot freed")
  l4.release("app-a", 11)
  l4.release("app-a", 12)
  eq(ngx.shared.edgeweir_l4_state:get("c|app-a"), 0)
  eq(ngx.shared.edgeweir_l4_state:get("p|11|app-a"), nil, "per-worker count removed at zero")
  -- Never below zero.
  l4.release("app-a", 11)
  eq(ngx.shared.edgeweir_l4_state:get("c|app-a"), 0)
end)

test("sweep: counts of a worker that is gone are taken back", function()
  reset()
  local st = ngx.shared.edgeweir_l4_state
  local c = app({ max_connections = 3 })
  for _, pid in ipairs({ 11, 11, 12 }) do
    assert(l4.admit(c, "192.0.2.1", 1, pid) == nil)
  end
  st:set("pid|11", 0)
  st:set("pid|12", 0)
  st:set("pid|13", 990) -- young: not known to the others yet
  -- Worker 11 crashed holding two connections.
  eq(l4.sweep({ 12, 20 }, 1000), 2)
  eq(st:get("c|app-a"), 1)
  eq(st:get("pid|11"), nil)
  eq(st:get("p|11|app-a"), nil)
  eq(st:get("pid|12"), 0, "alive")
  eq(st:get("pid|13"), 990, "young registration kept")
  eq(l4.sweep({ 12, 20 }, 1000), 0)
  -- The surviving worker's connection ends normally.
  l4.release("app-a", 12)
  eq(st:get("c|app-a"), 0)
  eq(l4.admit(c, "192.0.2.1", 1, 12), nil)
end)

------------------------------------------------------------------------

test("statistics: connections, refusals, peaks and bytes per completed minute", function()
  reset()
  l4.count("app-a", "conn", 1, 120)
  l4.count("app-a", "conn", 1, 130)
  l4.count("app-a", "refused", 3, 130)
  l4.peak("app-a", 2, 125)
  l4.peak("app-a", 5, 126)
  l4.peak("app-a", 3, 127)
  local e = { app = "app-a", rx = 0, tx = 0 }
  l4.account(e, 100, 1000, 150)
  -- A long connection is counted as it goes, in the minute it moved data.
  l4.account(e, "150", "1000", 185)
  l4.account(e, 120, 900, 186) -- counters never go back
  l4.count("app-b", "conn", 1, 185)
  l4.count("app-b", "conn", 1, 245) -- current minute at drain time
  local list = l4.drain(250)
  eq(#list, 3)
  local a1, a2, b = list[1], list[2], list[3]
  eq(a1.minute, 120)
  eq(a1.app_id, "app-a")
  eq(a1.connections, 2)
  eq(a1.refused, 3)
  eq(a1.peak_concurrent, 5)
  eq(a1.bytes_received, 100)
  eq(a1.bytes_sent, 1000)
  eq(a2.minute, 180)
  eq(a2.bytes_received, 50)
  eq(a2.bytes_sent, 0)
  eq(a2.connections, 0)
  eq(b.app_id, "app-b")
  eq(b.minute, 180)
  eq(#l4.drain(250), 0, "drained")
  eq(l4.drain(300)[1].minute, 240)
  -- JSON: an empty drain is an array.
  eq(cjson.encode({ stats = l4.drain(300) }), '{"stats":[]}')
end)

test("sample: open sessions of the worker and concurrent counts", function()
  reset()
  assert(l4.replace(cjson.encode({ revision = "1", content_hash = "h", apps = { app() } })))
  local counters = { rx = 10, tx = 20 }
  l4.live[1] = { app = "app-a", relay = counters, rx = 0, tx = 0 }
  l4.live[2] = { app = "app-a", r = "REQUEST", rx = 0, tx = 0 }
  l4.read_bytes = function(r)
    eq(r, "REQUEST")
    return 5, 6
  end
  ngx.shared.edgeweir_l4_state:set("c|app-a", 4)
  l4.sample(60)
  counters.rx = 15
  l4.sample(70)
  l4.live[1], l4.live[2], l4.read_bytes = nil, nil, nil
  local b = l4.drain(200)[1]
  eq(b.bytes_received, 20)
  eq(b.bytes_sent, 26)
  eq(b.peak_concurrent, 4)
end)

------------------------------------------------------------------------

test("prepare: indexes applications by protocol and port, refuses broken tables", function()
  local doc = assert(l4.prepare({
    revision = "1", origin_allowed_cidrs = { "10.0.0.0/8", "bad" },
    apps = { app(), app({ id = "app-u", protocol = "udp" }) },
  }))
  eq(doc.by_port["tcp:9000"].id, "app-a")
  eq(doc.by_port["udp:9000"].id, "app-u")
  eq(#doc.allowed, 1)
  for name, mutate in pairs({
    ["no apps"] = function(d) d.apps = nil end,
    ["protocol"] = function(d) d.apps[1].protocol = "sctp" end,
    ["port"] = function(d) d.apps[1].port = 0 end,
    ["id"] = function(d) d.apps[1].id = "a|b" end,
    ["two on a port"] = function(d) d.apps[2] = app({ id = "app-b" }) end,
    ["no origin"] = function(d) d.apps[1].origins = {} end,
    ["origin weight"] = function(d) d.apps[1].origins[1].weight = 0 end,
    ["origin port"] = function(d) d.apps[1].origins[1].port = 70000 end,
    ["timeouts"] = function(d) d.apps[1].idle_timeout = 0 end,
    ["unknown list"] = function(d) d.apps[1].allow_lists = { "nope" } end,
    ["list entry"] = function(d) d.ip_lists = { { id = "l", entries = { "1.2.3.4" } } } end,
  }) do
    local d = { revision = "1", apps = { app() } }
    mutate(d)
    local ok, err = l4.prepare(d)
    if ok or not err then
      error(name .. ": accepted")
    end
  end
end)

test("replace: versioned table, previous one kept, lock, status", function()
  reset()
  local d = ngx.shared.edgeweir_l4
  eq(l4.current(), nil)
  local st = assert(l4.replace(cjson.encode({ revision = "7", content_hash = "abc", apps = { app() } })))
  eq(st.version, 1)
  eq(st.revision, "7")
  eq(st.content_hash, "abc")
  eq(st.apps, 1)
  eq(l4.current().by_port["tcp:9000"].id, "app-a")
  st = assert(l4.replace(cjson.encode({ revision = "8", content_hash = "def", apps = { app({ port = 9100 }) } })))
  eq(st.version, 2)
  eq(l4.current().by_port["tcp:9000"], nil, "the worker sees the new version")
  eq(l4.current().by_port["tcp:9100"].id, "app-a")
  assert(d:get("t:1"), "previous table kept")
  assert(l4.replace(cjson.encode({ revision = "9", content_hash = "x", apps = {} })))
  eq(d:get("t:1"), nil, "table before the previous one deleted")
  local res, err, code = l4.replace("{")
  eq(res, nil)
  eq(code, 400)
  res, err, code = l4.replace(cjson.encode({ revision = 9, apps = {} }))
  eq(code, 400, "numeric revision")
  d:set("#lock", true)
  res, err, code = l4.replace(cjson.encode({ revision = "10", apps = {} }))
  eq(code, 409)
  d:delete("#lock")
  eq(l4.status().version, 3)
  -- Status lists the origins the passive check holds down.
  assert(l4.replace(cjson.encode({ revision = "11", apps = { app({ max_fails = 1 }) } })))
  l4.failure(l4.current().by_port["tcp:9000"], "p2", ngx.now())
  st = l4.status()
  eq(#st.down, 1)
  eq(st.down[1].origin_id, "p2")
  assert(err == nil or type(err) == "string")
end)

test("l4control.dispatch: the relay's endpoints", function()
  reset()
  local code, res = l4control.dispatch("GET", "/v1/l4", "")
  eq(code, 200)
  eq(res.version, 0)
  code, res = l4control.dispatch("PUT", "/v1/l4", cjson.encode({ revision = "3", content_hash = "h", apps = { app() } }))
  eq(code, 200)
  eq(res.revision, "3")
  code, res = l4control.dispatch("PUT", "/v1/l4", "not json")
  eq(code, 400)
  assert(res.error)
  l4.count("app-a", "conn", 1, 60)
  code, res = l4control.dispatch("POST", "/v1/l4/stats/drain", "")
  eq(code, 200)
  eq(res.stats[1].connections, 1)
  -- The current minute stays unless the agent asks for all of it (shutdown).
  l4.count("app-a", "conn", 1, ngx.time())
  eq(#select(2, l4control.dispatch("POST", "/v1/l4/stats/drain", "")).stats, 0)
  code, res = l4control.dispatch("POST", "/v1/l4/stats/drain", '{"all":true}')
  eq(code, 200)
  eq(res.stats[1].connections, 1)
  eq((l4control.dispatch("DELETE", "/v1/l4", "")), 405)
  eq((l4control.dispatch("GET", "/v1/l4/stats/drain", "")), 405)
  eq((l4control.dispatch("GET", "/v1/other", "")), 404)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
