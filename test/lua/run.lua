-- Lua unit tests for the data plane modules. Run inside the OpenResty
-- image with the resty CLI (see `make lua-test`):
--
--   resty -I lua --shdict 'edgeweir_sites 4m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_stats 4m' --shdict 'edgeweir_purge 4m' \
--         --shdict 'edgeweir_health 1m' test/lua/run.lua
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local origin = require("edgeweir.origin")
local stats = require("edgeweir.stats")
local cachekey = require("edgeweir.cachekey")
local purge = require("edgeweir.purge")
local health = require("edgeweir.health")
local lb = require("edgeweir.lb")
local dns = require("edgeweir.dns")
local ipaddr = require("edgeweir.ipaddr")
local router = require("edgeweir.router")

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

test("lb.order weights and backups", function()
  local s = store.prepare(site("w", { { name = "w.test" } }, {
    origins = {
      { id = "heavy", scheme = "http", address = "h", port = 80, weight = 9 },
      { id = "light", scheme = "http", address = "l", port = 80, weight = 1 },
      { id = "spare", scheme = "http", address = "s", port = 80, weight = 1, backup = true },
    },
  }))
  local counts = { heavy = 0, light = 0, spare = 0 }
  for _ = 1, 10000 do
    local order = lb.order(s, "/x", 1000)
    counts[order[1].id] = counts[order[1].id] + 1
    eq(#order, 2, "retries only among the primaries")
    for _, o in ipairs(order) do
      assert(o.id ~= "spare", "backup offered while the primaries are up")
    end
  end
  eq(counts.spare, 0, "backup used while primaries exist")
  assert(counts.heavy > 8500 and counts.heavy < 9500, "heavy share " .. counts.heavy)
  local b = store.prepare(site("b", { { name = "b.test" } }, {
    origins = { { id = "spare-only", scheme = "http", address = "s", port = 80, weight = 1, backup = true } },
  }))
  eq(lb.order(b, "/", 1000)[1].id, "spare-only", "backup used without primaries")
  eq(#lb.order({ _primaries = {}, _backups = {} }, "/", 1000), 0)
end)

test("lb.order uses backups only when every primary is down", function()
  local s = store.prepare(site("bk", { { name = "bk.test" } }, {
    load_balance = "round_robin",
    origins = {
      { id = "p1", scheme = "http", address = "a", port = 80, weight = 1 },
      { id = "p2", scheme = "http", address = "b", port = 80, weight = 1 },
      { id = "b1", scheme = "http", address = "c", port = 80, weight = 1, backup = true },
      { id = "b2", scheme = "http", address = "d", port = 80, weight = 1, backup = true },
    },
  }))
  local function ids(order)
    local out = {}
    for i, o in ipairs(order) do
      out[i] = o.id
    end
    table.sort(out)
    return table.concat(out, ",")
  end
  eq(ids(lb.order(s, "/", 1000)), "p1,p2", "both primaries up: no backup, not even as a retry")
  health.failure("bk", "p1", "timeout", 1, 30, 1000)
  eq(ids(lb.order(s, "/", 1001)), "p2", "one primary left: retries stay on it")
  health.failure("bk", "p2", "timeout", 1, 30, 1000)
  eq(ids(lb.order(s, "/", 1001)), "b1,b2", "every primary down: backups")
  health.failure("bk", "b1", "timeout", 1, 30, 1000)
  eq(ids(lb.order(s, "/", 1001)), "b2")
  health.failure("bk", "b2", "timeout", 1, 30, 1000)
  local all = lb.order(s, "/", 1001)
  eq(#all, 3, "everything down: fail open, at most MAX_TRIES")
  assert(not all[1].backup and not all[2].backup, "primaries first when failing open")
  health.success("bk", "p2")
  eq(ids(lb.order(s, "/", 1001)), "p2", "a recovered primary takes over again")
  for _, id in ipairs({ "p1", "b1", "b2" }) do
    health.success("bk", id)
  end
end)

test("lb.order skips origins marked down and fails open", function()
  local s = store.prepare(site("hs", { { name = "hs.test" } }, {
    origins = {
      { id = "p1", scheme = "http", address = "a", port = 80, weight = 1 },
      { id = "b1", scheme = "http", address = "b", port = 80, weight = 1, backup = true },
    },
  }))
  health.failure("hs", "p1", "timeout", 1, 30, 1000)
  local order = lb.order(s, "/", 1001)
  eq(#order, 1)
  eq(order[1].id, "b1", "backup takes over while the primary is down")
  eq(lb.order(s, "/", 1031)[1].id, "p1", "primary tried again after recovery")
  health.failure("hs", "b1", "timeout", 1, 30, 1000)
  order = lb.order(s, "/", 1001)
  eq(order[1].id, "p1", "all down: fail open, primaries first")
  eq(order[2].id, "b1")
  health.success("hs", "p1")
  health.success("hs", "b1")
end)

test("lb round robin is smooth and weighted", function()
  local s = store.prepare(site("rr", { { name = "rr.test" } }, {
    load_balance = "round_robin",
    origins = {
      { id = "a", scheme = "http", address = "a", port = 80, weight = 5 },
      { id = "b", scheme = "http", address = "b", port = 80, weight = 1 },
      { id = "c", scheme = "http", address = "c", port = 80, weight = 1 },
    },
  }))
  local seq = {}
  for i = 1, 7 do
    seq[i] = lb.order(s, "/", 1000)[1].id
  end
  -- nginx's smooth weighted round robin for weights 5, 1, 1.
  eq(table.concat(seq), "aabacaa")
  local order = lb.order(s, "/", 1000)
  eq(#order, 3, "retries go to the other origins")
  assert(order[2].id ~= order[1].id and order[3].id ~= order[1].id)
end)

test("lb consistent hash is stable and moves only a down origin's keys", function()
  local origins = {}
  for i = 1, 4 do
    origins[i] = { id = "o" .. i, scheme = "http", address = "o" .. i, port = 80, weight = 1 }
  end
  local s = store.prepare(site("ch", { { name = "ch.test" } }, { load_balance = "consistent_hash", origins = origins }))
  local first, per = {}, {}
  for i = 1, 400 do
    local key = "/asset/" .. i
    first[key] = lb.order(s, key, 1000)[1].id
    eq(lb.order(s, key, 1000)[1].id, first[key], "same key, same origin")
    per[first[key]] = (per[first[key]] or 0) + 1
  end
  for id, n in pairs(per) do
    assert(n > 50, id .. " got only " .. n .. " of 400 keys")
  end
  health.failure("ch", "o2", "down", 1, 30, 1000)
  local moved = 0
  for key, id in pairs(first) do
    local now = lb.order(s, key, 1001)[1].id
    assert(now ~= "o2", "down origin chosen")
    if id ~= "o2" then
      eq(now, id, "keys of healthy origins stay")
    else
      moved = moved + 1
    end
  end
  assert(moved > 0)
  health.success("ch", "o2")
  eq(#lb.order(s, "/x", 1000), lb.MAX_TRIES, "at most MAX_TRIES candidates")
end)

test("health counts consecutive failures and reports them", function()
  eq(health.failure("hs2", "x", "connection failed", 3, 10, 2000), false)
  eq(health.failure("hs2", "x", "connection failed", 3, 10, 2001), false)
  eq(health.is_down("hs2", "x", 2002), false)
  eq(health.failure("hs2", "x", "timeout", 3, 10, 2002), true)
  eq(health.is_down("hs2", "x", 2003), true)
  eq(health.is_down("hs2", "x", 2013), false, "recovered after the recovery time")
  local report = health.report(2003)
  local entry
  for _, r in ipairs(report) do
    if r.origin_id == "x" then
      entry = r
    end
  end
  eq(entry.site_id, "hs2")
  eq(entry.failures, 3)
  eq(entry.healthy, false)
  eq(entry.last_error, "timeout")
  eq(entry.down_until, 2012)
  -- After the recovery time traffic may try it again, but it stays
  -- unhealthy until a request succeeds.
  for _, r in ipairs(health.report(2020)) do
    if r.origin_id == "x" then
      eq(r.healthy, false, "unhealthy until a success")
      eq(r.down_until, 0, "no longer held down")
    end
  end
  eq(health.failure("hs2", "y", "timeout", 3, 10, 2000), false)
  for _, r in ipairs(health.report(2001)) do
    if r.origin_id == "y" then
      eq(r.healthy, true, "below max_fails counts as healthy")
    end
  end
  health.success("hs2", "y")
  -- One more failure after the recovery time marks it down again at once.
  eq(health.failure("hs2", "x", "timeout", 3, 10, 2013), true)
  health.success("hs2", "x")
  eq(health.is_down("hs2", "x", 2014), false)
  for _, r in ipairs(health.report(2014)) do
    assert(r.origin_id ~= "x", "success clears the entry")
  end
  -- Origins are tracked per site: the same origin id in another site is
  -- independent.
  health.failure("site-1", "shared", "timeout", 1, 30, 3000)
  eq(health.is_down("site-1", "shared", 3001), true)
  eq(health.is_down("site-2", "shared", 3001), false)
  local sites = {}
  for _, r in ipairs(health.report(3001)) do
    if r.origin_id == "shared" then
      sites[#sites + 1] = r.site_id
    end
  end
  eq(table.concat(sites, ","), "site-1")
  health.success("site-1", "shared")
end)

test("rules chain and response conditions", function()
  local s = {
    cache_rules = {
      rules.prepare({ id = "notfound", action = "cache", ttl = 30, mode = "override", status_codes = { 404 } }),
      rules.prepare({ id = "big", action = "bypass", ttl = 0, mode = "override", min_size = 1000 }),
      rules.prepare({ id = "index", action = "cache", ttl = 5, mode = "override", paths = { "/index.html" } }),
      rules.prepare({ id = "all", action = "cache", ttl = 60, mode = "override" }),
      rules.prepare({ id = "never", action = "cache", ttl = 1, mode = "respect" }),
    },
  }
  local chain = rules.chain(s, "/a.js")
  local ids = {}
  for i, r in ipairs(chain) do
    ids[i] = r.id
  end
  eq(table.concat(ids, ","), "notfound,big,all,never", "exact path rule skipped; respect rule ends the chain")
  eq(rules.decide(chain, 404, nil).id, "notfound")
  eq(rules.decide(chain, 200, 5000).id, "big")
  eq(rules.decide(chain, 200, 10).id, "all")
  eq(rules.decide(chain, 200, nil).id, "all", "unknown size fails size bounds")
  eq(rules.decide(chain, 206, 10).id, "all", "206 counts as cacheable")
  eq(rules.decide(chain, 500, 10).id, "never", "override rule without status list skips errors")
  eq(rules.chain(s, "/index.html")[3].id, "index")
  eq(rules.may_cache(chain), true)
  eq(rules.may_cache({ rules.prepare({ id = "b", action = "bypass", mode = "override" }) }), false)
  eq(rules.chain({ cache_rules = { rules.prepare({ id = "x", action = "cache", mode = "override", paths = { "/y" } }) } }, "/x"), nil)
end)

local function prepared_chain(list)
  local chain = {}
  for i, r in ipairs(list) do
    chain[i] = rules.prepare(r)
  end
  return chain
end

test("origin.decide sets TTLs like accel_expires did", function()
  local override = prepared_chain({ { id = "o", action = "cache", ttl = 60, mode = "override" } })
  local respect = prepared_chain({ { id = "r", action = "cache", ttl = 60, mode = "respect" } })
  eq(origin.decide(override, 200, 10, "no-store", nil).accel_expires, 60)
  eq(origin.decide(override, 502, 10, nil, nil).accel_expires, 0, "errors are not cached by rule TTL")
  eq(origin.decide(respect, 200, 10, nil, nil).accel_expires, 60)
  eq(origin.decide(respect, 200, 10, "max-age=5", nil).accel_expires, nil, "origin headers win")
  eq(origin.decide(respect, 200, 10, nil, "Thu, 01 Jan 2099 00:00:00 GMT").accel_expires, nil)
  eq(origin.decide(respect, 500, 10, nil, nil).accel_expires, 0, "no fallback TTL for errors")
  eq(origin.decide(prepared_chain({ { id = "z", action = "cache", ttl = 0, mode = "override" } }), 200, 1, nil, nil).accel_expires, 0)
  eq(origin.decide(prepared_chain({ { id = "b", action = "bypass", mode = "override" } }), 200, 1, nil, nil).accel_expires, 0)
  eq(origin.decide(nil, 200, 1, nil, nil).accel_expires, 0, "no rule, no caching")
  local status = prepared_chain({ { id = "s", action = "cache", ttl = 20, mode = "override", status_codes = { 404 } } })
  eq(origin.decide(status, 404, 1, nil, nil).accel_expires, 20)
  eq(origin.decide(status, 200, 1, nil, nil).accel_expires, 0)
end)

test("origin.decide carries stale-while-revalidate and stale-if-error", function()
  local override = prepared_chain({ { id = "o", action = "cache", ttl = 60, mode = "override", swr = 30, sie = 600 } })
  local d = origin.decide(override, 200, 10, "no-cache, private, stale-if-error=5, x-custom", nil)
  eq(d.accel_expires, 60)
  eq(d.stash, "no-cache, private, stale-if-error=5, x-custom")
  eq(d.cache_control, "x-custom, max-age=60, stale-while-revalidate=30, stale-if-error=600")
  d = origin.decide(override, 200, 10, nil, nil)
  eq(d.stash, "-", "absent Cache-Control is restored as absent")
  local respect = prepared_chain({ { id = "r", action = "cache", ttl = 60, mode = "respect", sie = 120 } })
  d = origin.decide(respect, 200, 10, "public, max-age=10, stale-if-error=1", nil)
  eq(d.accel_expires, nil)
  eq(d.cache_control, "public, max-age=10, stale-if-error=120")
  eq(origin.decide(override, 404, 10, nil, nil).cache_control, nil, "uncached responses keep their headers")
end)

test("cachekey keeps the Phase 0 key by default", function()
  local s = store.prepare(site("k", { { name = "k.test" } }, { cache_generation = "7" }))
  local req = { scheme = "http", host = "k.test", path = "/a/b.js", args = "v=1&x=2" }
  eq(cachekey.build(s, req, 0), "k:7:http://k.test/a/b.js?v=1&x=2")
  req.args = ""
  eq(cachekey.build(s, req, 0), "k:7:http://k.test/a/b.js")
  eq(cachekey.build(s, req, 1759000000123), "k:7:http://k.test/a/b.js#1759000000123", "epoch as an integer")
end)

test("cachekey query modes, sorting, device, headers, cookies and host", function()
  local key = cachekey.prepare({ query = "ignore" })
  eq(cachekey.normalize_query("a=1", key), "")
  key = cachekey.prepare({ query = "all", sort_query = true })
  eq(cachekey.normalize_query("b=2&a=1", key), "a=1&b=2")
  eq(cachekey.normalize_query("a=1&b=2", key), "a=1&b=2")
  key = cachekey.prepare({ query = "include", query_params = { "v", "lang" }, sort_query = true })
  eq(cachekey.normalize_query("utm=x&v=3&lang=de&%76=4", key), "%76=4&lang=de&v=3", "names compared raw and unescaped")
  eq(cachekey.normalize_query("utm=x", key), "")
  eq(cachekey.device("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"), "m")
  eq(cachekey.device("Mozilla/5.0 (Linux; Android 14; Pixel 8)"), "m")
  eq(cachekey.device("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "d")
  eq(cachekey.device(nil), "d")
  local s = store.prepare(site("v", { { name = "v.test" } }, {
    cache_key = { query = "all", device = true, headers = { "accept-language" }, cookies = { "ab" }, exclude_host = true },
  }))
  local req = {
    scheme = "http", host = "v.test", path = "/p", args = "",
    user_agent = "Android", headers = { ["accept-language"] = { "de", "en" } },
    cookie = function(name)
      return name == "ab" and "b" or nil
    end,
  }
  eq(cachekey.build(s, req, 0), "v:1:http:///p|d=m|h:accept-language=de,en|c:ab=b")
end)

test("cachekey parts are escaped so no value can imitate another part", function()
  local s = store.prepare(site("x", { { name = "x.test" } }, {
    cache_key = { query = "all", headers = { "h1", "h2" }, cookies = { "c1", "c2" } },
  }))
  local function key(path, args, h, c)
    return cachekey.build(s, {
      scheme = "http", host = "x.test", path = path, args = args, headers = h,
      cookie = function(name)
        return c and c[name]
      end,
    }, 0)
  end
  -- A header value cannot inject a later header part.
  local a = key("/p", "", { h1 = "x|h:h2=y", h2 = "" })
  local b = key("/p", "", { h1 = "x", h2 = "y|h:h2=" })
  assert(a ~= b, "header values collide: " .. a)
  -- Nor ":" / "=" games between name and value, or cookies.
  assert(key("/p", "", {}, { c1 = "a|c:c2=b" }) ~= key("/p", "", {}, { c1 = "a", c2 = "b|c:c2=" }), "cookie values collide")
  assert(key("/p", "", { h1 = "a=b" }) ~= key("/p", "", { h1 = "a", h2 = "b" }))
  -- A path (decoded $uri) cannot imitate the query or a header part, and a
  -- query cannot imitate a header part or the purge epoch.
  assert(key("/p?a=1", "") ~= key("/p", "a=1"), "path vs query")
  assert(key("/p|h:h1=v", "", {}) ~= key("/p", "", { h1 = "v" }), "path vs header")
  assert(key("/p", "a=1|h:h1=v", {}) ~= key("/p", "a=1", { h1 = "v" }), "query vs header")
  assert(key("/p#1", "") ~= cachekey.build(s, { scheme = "http", host = "x.test", path = "/p", args = "" }, 1), "path vs epoch")
  -- "%" itself is escaped: an escaped-looking value is not an escape.
  assert(key("/a%7Cb", "") ~= key("/a|b", ""), "percent escapes are not ambiguous")
  eq(key("/a|b", "q=%41", { h1 = "v:1" }), "x:1:http://x.test/a%7Cb?q=%2541|h:h1=v%3A1|h:h2=|c:c1=|c:c2=")
  -- Repeated header fields join with "," (equivalent in HTTP), escaped each.
  eq(key("/p", "", { h1 = { "a|b", "c" } }), "x:1:http://x.test/p|h:h1=a%7Cb,c|h:h2=|c:c1=|c:c2=")
  -- Control characters never reach the key.
  assert(not key("/a\nb", ""):find("\n", 1, true))
end)

test("cachekey.normalize_path matches nginx's $uri", function()
  -- Expected values recorded from OpenResty 1.31.1.1 ($uri of the raw path).
  local cases = {
    ["/%73tatic/x"] = "/static/x", ["/a/../b"] = "/b", ["//a///b"] = "/a/b", ["/a/./b"] = "/a/b",
    ["/a/b/.."] = "/a/", ["/a/b/."] = "/a/b/", ["/a/%2e%2e/c"] = "/c", ["/a%2Fb"] = "/a/b",
    ["/a%2F..%2Fc"] = "/c", ["/a+b%20c"] = "/a+b c", ["/%7C%23%3F"] = "/|#?", ["/a/b/"] = "/a/b/",
    ["/a/.%2e/b"] = "/b", ["/x/.."] = "/", ["/./a"] = "/a", ["/"] = "/", ["/static/"] = "/static/",
  }
  for raw, want in pairs(cases) do
    eq(cachekey.normalize_path(raw), want, raw)
  end
  eq(cachekey.normalize_path("/../../x"), "/x", "never above the root")
  eq(cachekey.normalize_path(""), "/")
end)

test("purge markers match encoded variants of their paths", function()
  local key = cachekey.prepare({ query = "all" })
  assert(purge.replace({ id = "enc", markers = {
    { site_id = "e1", type = "prefix", host = "e.test", path = "/static/", epoch = 500 },
    { site_id = "e1", type = "url", host = "e.test", path = "/img/a%20b.png", query = "", epoch = 600 },
    { site_id = "e1", type = "prefix", host = "e.test", path = "/%64ocs/", epoch = 700 },
  } }))
  -- Requests are matched with nginx's normalized $uri.
  eq(purge.epoch("e1", key, "e.test", cachekey.normalize_path("/%73tatic/x.js"), ""), 500, "/%73tatic/ escapes no prefix purge")
  eq(purge.epoch("e1", key, "e.test", "/static/x.js", ""), 500)
  eq(purge.epoch("e1", key, "e.test", "/img/a b.png", ""), 600, "URL marker path is normalized too")
  eq(purge.epoch("e1", key, "e.test", "/docs/index.html", ""), 700, "encoded prefix marker")
  eq(purge.epoch("e1", key, "e.test", "/staticx", ""), 0)
  assert(purge.replace({ id = "empty-enc", markers = {} }))
end)

test("purge markers change the epoch of matching requests only", function()
  local key = cachekey.prepare({ query = "all", sort_query = true })
  eq(purge.epoch("p1", key, "a.test", "/x", ""), 0, "no markers")
  local st = assert(purge.add({
    id = "set-1",
    markers = {
      { site_id = "p1", type = "url", host = "a.test", path = "/img/1.png", query = "b=2&a=1", epoch = 100 },
      { site_id = "p1", type = "prefix", host = "a.test", path = "/static/", epoch = 200 },
    },
  }))
  eq(st.id, "set-1")
  eq(purge.epoch("p1", key, "a.test", "/img/1.png", "a=1&b=2"), 100, "query compared after normalization")
  eq(purge.epoch("p1", key, "a.test", "/img/1.png", "a=1"), 0, "other query untouched")
  eq(purge.epoch("p1", key, "b.test", "/img/1.png", "a=1&b=2"), 0, "other host untouched")
  eq(purge.epoch("p1", key, "a.test", "/static/app.js", ""), 200)
  eq(purge.epoch("p1", key, "a.test", "/staticx", ""), 0, "prefix is a plain string prefix")
  eq(purge.epoch("p2", key, "a.test", "/static/app.js", ""), 0, "other site untouched")
  local nohost = cachekey.prepare({ query = "all", sort_query = true, exclude_host = true })
  eq(purge.epoch("p1", nohost, "b.test", "/static/app.js", ""), 200, "host ignored when the key excludes it")
  -- Later purges raise the epoch; older ones never lower it.
  assert(purge.add({ id = "set-2", markers = {
    { site_id = "p1", type = "prefix", host = "a.test", path = "/static/", epoch = 150 },
    { site_id = "p1", type = "site", epoch = 300 },
  } }))
  eq(purge.epoch("p1", key, "a.test", "/static/app.js", ""), 300, "site marker covers everything")
  eq(purge.epoch("p1", key, "z.test", "/anything", "q=1"), 300)
  -- replace installs exactly the given set.
  st = assert(purge.replace({ id = "set-3", markers = {
    { site_id = "p1", type = "url", host = "a.test", path = "/img/1.png", query = "a=1&b=2", epoch = 400 },
  } }))
  eq(st.id, "set-3")
  eq(st.entries, 1)
  eq(purge.epoch("p1", key, "a.test", "/static/app.js", ""), 0, "replaced markers are gone")
  eq(purge.epoch("p1", key, "a.test", "/img/1.png", "b=2&a=1"), 400)
  local _, err, code = purge.add({ id = "bad", markers = { { site_id = "p1", type = "nope", epoch = 1 } } })
  eq(code, 400)
  assert(err:find("invalid marker"), err)
  assert(purge.replace({ id = "empty", markers = {} }))
end)

test("store.prepare applies M2 defaults", function()
  local s = store.prepare(site("d", { { name = "d.test" } }))
  eq(s.tls_verify, true)
  eq(s.websocket, true)
  eq(s.slice, false)
  eq(s.health.max_fails, 3)
  eq(s.conn.connect_timeout_ms, 10000)
  eq(s.conn.keepalive, true)
  eq(s.cache_key.query, "all")
  local t = store.prepare(site("e", { { name = "e.test" } }, {
    tls_verify = false, websocket = false, slice = true,
    conn = { keepalive = false, connect_timeout_ms = 1500 },
    origins = {
      { id = "s3", scheme = "https", address = "s3.test", port = 443, weight = 1 },
      { id = "m", scheme = "http", address = "minio", port = 9000, weight = 1 },
    },
  }))
  eq(t.tls_verify, false)
  eq(t.websocket, false)
  eq(t.slice, true)
  eq(t.conn.keepalive, false, "explicit false kept")
  eq(t.conn.connect_timeout_ms, 1500)
  eq(t.conn.read_timeout_ms, 60000, "missing values defaulted")
  eq(t._primaries[1]._s3_host, "s3.test", "default port left out")
  eq(t._primaries[2]._s3_host, "minio:9000")
end)

test("dns passes allowed IP literals through and refuses special-purpose ones", function()
  eq(dns.resolve("93.184.216.34", {}), "93.184.216.34")
  eq(dns.resolve("2606:4700:4700::1111", {}), "2606:4700:4700::1111")
  for _, a in ipairs({ "10.0.0.7", "127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "2001:db8::1" }) do
    local ip, err, code, params = dns.resolve(a, {})
    eq(ip, nil, a)
    eq(code, "address_forbidden", a)
    eq(params.address, a)
    assert(err:find("special%-purpose"), err)
  end
  local allowed = ipaddr.prefixes({ "10.0.0.0/8", "::1/128" })
  eq(dns.resolve("10.0.0.7", allowed), "10.0.0.7", "allow list")
  eq(dns.resolve("::1", allowed), "::1")
end)

test("dns drops special-purpose answers", function()
  local orig = dns.query
  local calls = 0
  dns.query = function(host)
    calls = calls + 1
    if host == "mixed.test" then
      return { "10.0.0.5", "93.184.216.34", "127.0.0.1" }, nil, 30
    elseif host == "private.test" then
      return { "169.254.169.254", "fd00::1" }, nil, 30
    elseif host == "mapped.test" then
      return { "0:0:0:0:0:ffff:7f00:1" }, nil, 30 -- lua-resty-dns style, uncompressed
    end
    return nil, "name error"
  end
  for _ = 1, 50 do
    eq(dns.resolve("mixed.test", {}), "93.184.216.34", "only the public answer is used")
  end
  local ip, err, code, params = dns.resolve("private.test", {})
  eq(ip, nil)
  eq(code, "address_forbidden")
  eq(params.address, "169.254.169.254")
  assert(err:find("private.test", 1, true), err)
  eq(select(3, dns.resolve("mapped.test", {})), "address_forbidden", "IPv4-mapped loopback")
  -- Cached answers are checked again against the current allow list.
  local before = calls
  eq(dns.resolve("private.test", ipaddr.prefixes({ "169.254.0.0/16" })), "169.254.169.254")
  eq(calls, before, "answer came from the cache")
  local _, _, dcode, dparams = dns.resolve("missing.test", {})
  eq(dcode, "dns_failed")
  eq(dparams.host, "missing.test")
  dns.query = orig
  for _, h in ipairs({ "mixed.test", "private.test", "mapped.test", "missing.test" }) do
    dns.invalidate(h)
  end
end)

test("ipaddr parses literals and applies the special-purpose list", function()
  local p = ipaddr.parse
  eq(#p("1.2.3.4"), 4)
  eq(#p("::"), 16)
  eq(#p("2001:db8::1"), 16)
  eq(#p("::ffff:10.0.0.1"), 16)
  eq(#p("1:2:3:4:5:6:7:8"), 16)
  for _, bad in ipairs({ "", "1.2.3", "1.2.3.256", "01.2.3.4", "1::2::3", "1:2:3:4:5:6:7:8:9", "fe80::1%eth0", "g::1", "host.test", "::1.2.3" }) do
    eq(p(bad), nil, bad)
  end
  local forbidden = {
    "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
    "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9",
    "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "100::1", "2001:db8::1", "fc00::1", "fd12:3456::1",
    "fe80::1", "febf::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe", "not-an-ip",
  }
  local allowed = {
    "1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.1",
    "192.169.0.1", "198.17.255.255", "198.20.0.0", "223.255.255.255", "2606:4700:4700::1111", "fec0::1",
    "::2", "::ffff:8.8.8.8", "64:ff9b::808:808",
  }
  for _, a in ipairs(forbidden) do
    eq(ipaddr.forbidden(a, {}), true, a)
  end
  for _, a in ipairs(allowed) do
    eq(ipaddr.forbidden(a, {}), false, a)
  end
  eq(#ipaddr.FORBIDDEN, 21, "the list shared with configir/address.go")
  local list = ipaddr.prefixes({ "10.1.0.0/16", "127.0.0.1/32", "fd00::/8", "bogus", "192.168.1.77/24" })
  eq(#list, 4, "invalid entries skipped")
  for _, a in ipairs({ "10.1.2.3", "127.0.0.1", "fd00::5", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "192.168.1.200" }) do
    eq(ipaddr.forbidden(a, list), false, a .. " allowed")
  end
  for _, a in ipairs({ "10.2.0.1", "127.0.0.2", "fc00::1", "::1", "192.168.2.1" }) do
    eq(ipaddr.forbidden(a, list), true, a .. " outside the list")
  end
end)

test("store keeps the allow list and cdn-id per table", function()
  assert(store.replace({ revision = "30", content_hash = "cfg", cdn_id = "edgeweir-0123456789abcdef",
    origin_allowed_cidrs = { "10.0.0.0/8" }, sites = { site("cfg", { { name = "cfg.test" } }) } }))
  local cfg = store.config()
  eq(cfg.cdn_id, "edgeweir-0123456789abcdef")
  eq(#cfg.allowed, 1)
  eq(ipaddr.forbidden("10.9.9.9", cfg.allowed), false)
  eq(store.status().cdn_id, "edgeweir-0123456789abcdef")
  assert(store.replace({ revision = "31", content_hash = "cfg2", sites = {} }))
  eq(store.config().cdn_id, "", "older agents send no cdn-id")
  eq(#store.config().allowed, 0)
end)

test("router CDN-Loop detection and header value", function()
  local id = "edgeweir-0123456789abcdef"
  eq(router.cdn_loop_contains(nil, id), false)
  eq(router.cdn_loop_contains("", id), false)
  eq(router.cdn_loop_contains("other.example", id), false)
  eq(router.cdn_loop_contains("other.example, " .. id, id), true)
  eq(router.cdn_loop_contains(" EDGEWEIR-0123456789ABCDEF ; hop=2", id), true, "case-insensitive, parameters")
  eq(router.cdn_loop_contains(id .. "0, x" .. id, id), false, "no substring matches")
  eq(router.cdn_loop_value(nil, id), id)
  eq(router.cdn_loop_value("", id), id)
  eq(router.cdn_loop_value("a.example; v=1", id), "a.example; v=1, " .. id)
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
