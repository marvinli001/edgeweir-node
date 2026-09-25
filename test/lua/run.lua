-- Lua unit tests for the data plane modules. Run inside the OpenResty
-- image with the resty CLI (see `make lua-test`):
--
--   resty -I lua --shdict 'edgeweir_sites 4m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_stats 4m' test/lua/run.lua
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local origin = require("edgeweir.origin")
local stats = require("edgeweir.stats")

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

local function site(id, domains, extra)
  local s = {
    id = id,
    cache_zone = "edgeweir_default",
    cache_generation = "1",
    load_balance = "weighted_random",
    domains = domains,
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
  }
  for k, v in pairs(extra or {}) do
    s[k] = v
  end
  return s
end

test("rules.extension", function()
  eq(rules.extension("/a/b.PNG"), "png")
  eq(rules.extension("/a/b.tar.gz"), "gz")
  eq(rules.extension("/a.b/c"), nil)
  eq(rules.extension("/"), nil)
end)

test("rules.match first match wins", function()
  local s = {
    cache_rules = {
      rules.prepare({ id = "r1", action = "bypass", ttl = 0, mode = "override", path_prefixes = { "/api/" } }),
      rules.prepare({ id = "r2", action = "cache", ttl = 60, mode = "override", extensions = { "png", "css" } }),
      rules.prepare({ id = "r3", action = "cache", ttl = 10, mode = "respect", path_prefixes = { "/static/" }, extensions = { "js" } }),
      rules.prepare({ id = "r4", action = "cache", ttl = 5, mode = "override" }),
    },
  }
  eq(rules.match(s, "/api/x.png").id, "r1")
  eq(rules.match(s, "/img/logo.PNG").id, "r2")
  eq(rules.match(s, "/static/app.js").id, "r3")
  eq(rules.match(s, "/other/app.js").id, "r4", "catch-all")
  eq(rules.match({}, "/x"), nil)
end)

test("store.replace and lookup", function()
  local st, err = store.replace({
    revision = "3",
    content_hash = "abc",
    sites = {
      site("s1", { { name = "a.test" }, { name = "wild.test", wildcard = true } }),
      site("s2", { { name = "b.test" } }),
    },
  })
  assert(st, err)
  eq(st.site_count, 2)
  eq(store.status().revision, "3")
  eq(store.status().content_hash, "abc")
  eq(store.lookup_host("a.test").id, "s1")
  eq(store.lookup_host("b.test").id, "s2")
  eq(store.lookup_host("x.wild.test").id, "s1", "wildcard")
  eq(store.lookup_host("wild.test"), nil, "wildcard does not match apex")
  eq(store.lookup_host("x.y.wild.test"), nil, "wildcard matches one label only")
  eq(store.lookup_host("unknown.test"), nil)
end)

test("store.replace flips versions and keeps previous table", function()
  local before = store.status().version
  local st = assert(store.replace({ revision = "4", content_hash = "def", sites = { site("s3", { { name = "c.test" } }) } }))
  eq(st.version, before + 1)
  eq(store.lookup_host("a.test"), nil, "old host gone after flip")
  eq(store.lookup_host("c.test").id, "s3")
  -- Requests that raced the flip can still resolve sites of the previous table.
  eq(store.site_current("s1").id, "s1")
  assert(store.replace({ revision = "5", content_hash = "ghi", sites = {} }))
  eq(store.site_current("s1"), nil, "tables older than the previous one are removed")
  local keys = ngx.shared.edgeweir_sites:get_keys(0)
  for _, k in ipairs(keys) do
    assert(k:sub(1, #("v" .. before)) ~= "v" .. before .. ":", "stale key " .. k)
  end
end)

test("store.replace rejects invalid sites atomically", function()
  assert(store.replace({ revision = "6", content_hash = "ok", sites = { site("good", { { name = "good.test" } }) } }))
  local st, err, code = store.replace({
    revision = "7",
    sites = { site("s4", { { name = "d.test" } }), { id = "bad", domains = {} } },
  })
  eq(st, nil)
  eq(code, 400)
  assert(err:find("domains"), err)
  eq(store.status().revision, "6", "status unchanged")
  eq(store.lookup_host("d.test"), nil, "partial table not visible")
  eq(store.lookup_host("good.test").id, "good")
end)

test("store.prepare precomputes origins", function()
  local s = store.prepare(site("p", { { name = "p.test" } }, {
    origins = {
      { id = "a", scheme = "https", address = "2001:db8::1", port = 443, weight = 0, host_header = "api.test:8443" },
      { id = "b", scheme = "http", address = "10.0.0.2", port = 8080, weight = 3, backup = true, sni = "x.test" },
    },
  }))
  eq(s._primaries[1].url, "https://[2001:db8::1]:443")
  eq(s._primaries[1].weight, 1, "weight defaults to 1")
  eq(s._primaries[1].sni_name, "api.test")
  eq(s._backups[1].sni_name, "x.test")
  eq(s._pw, 1)
  eq(s._bw, 3)
end)

test("origin.pick weights and backups", function()
  local s = store.prepare(site("w", { { name = "w.test" } }, {
    origins = {
      { id = "heavy", scheme = "http", address = "h", port = 80, weight = 9 },
      { id = "light", scheme = "http", address = "l", port = 80, weight = 1 },
      { id = "spare", scheme = "http", address = "s", port = 80, weight = 1, backup = true },
    },
  }))
  local counts = { heavy = 0, light = 0, spare = 0 }
  for _ = 1, 10000 do
    local o = origin.pick(s)
    counts[o.id] = counts[o.id] + 1
  end
  eq(counts.spare, 0, "backup used while primaries exist")
  assert(counts.heavy > 8500 and counts.heavy < 9500, "heavy share " .. counts.heavy)
  local b = store.prepare(site("b", { { name = "b.test" } }, {
    origins = { { id = "spare", scheme = "http", address = "s", port = 80, weight = 1, backup = true } },
  }))
  eq(origin.pick(b).id, "spare", "backup used without primaries")
  eq(origin.pick({ _primaries = {}, _backups = {} }), nil)
end)

test("origin.accel_expires", function()
  eq(origin.accel_expires(60, "override", 200, "no-store", nil), 60)
  eq(origin.accel_expires(60, "override", 502, nil, nil), nil, "errors are not cached by rule TTL")
  eq(origin.accel_expires(60, "respect", 200, nil, nil), 60)
  eq(origin.accel_expires(60, "respect", 200, "max-age=5", nil), nil)
  eq(origin.accel_expires(60, "respect", 200, nil, "Thu, 01 Jan 2099 00:00:00 GMT"), nil)
  eq(origin.accel_expires(0, "override", 200, nil, nil), nil)
end)

test("stats.drain aggregates completed minutes", function()
  local dict = ngx.shared.edgeweir_stats
  local now = 1800000030 -- 30s into a minute
  local cur = 1800000000
  local prev = cur - 60
  dict:incr(prev .. "|s1|req", 3, 0)
  dict:incr(prev .. "|s1|out", 300, 0)
  dict:incr(prev .. "|s1|in", 30, 0)
  dict:incr(prev .. "|s1|hit", 2, 0)
  dict:incr(prev .. "|s1|miss", 1, 0)
  dict:incr(prev .. "|s1|s200", 2, 0)
  dict:incr(prev .. "|s1|s404", 1, 0)
  dict:incr(prev .. "|s|2|req", 1, 0) -- site ids may contain the separator
  dict:incr(cur .. "|s1|req", 5, 0) -- current minute stays
  local list = stats.drain(now)
  eq(#list, 2)
  local by = {}
  for _, b in ipairs(list) do
    by[b.site_id] = b
  end
  local b = by.s1
  eq(b.minute, prev)
  eq(b.requests, 3)
  eq(b.bytes_sent, 300)
  eq(b.bytes_received, 30)
  eq(b.cache_hits, 2)
  eq(b.cache_misses, 1)
  eq(b.status_codes["200"], 2)
  eq(b.status_codes["404"], 1)
  eq(by["s|2"].requests, 1)
  eq(dict:get(cur .. "|s1|req"), 5, "current minute not drained")
  eq(#stats.drain(now), 0, "drained counters are deleted")
  eq(cjson.encode(stats.drain(now)), "[]", "empty drain encodes as a JSON array")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
