-- Rules of proto v0.13.0 (feature rules-v2) in the data plane: dynamic
-- redirects and rewrites with query edits, the request snapshot, bulk
-- redirects, origin rules and groups, config overrides, the compression
-- phase, cache rule conditions and browser TTLs.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_health 1m' --shdict 'edgeweir_policy_logs 1m' \
--         --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' test/lua/rules_v2.lua
local policy = require("edgeweir.policy")
local store = require("edgeweir.store")
local rules = require("edgeweir.rules")
local origin = require("edgeweir.origin")
local lb = require("edgeweir.lb")
local challenge = require("edgeweir.challenge")

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

local TRUE = { op = "literal", value_type = "boolean", value = "true" }
local PATH = { op = "field", field = "http.request.uri.path", value_type = "string" }
local function const(v) return { op = "const", value_type = "string", value = v } end
local function call(name, typ, ...) return { op = "call", field = name, value_type = typ, children = { ... } } end
local function path_is(p) return { op = "eq", field = "http.request.uri.path", value_type = "string", value = p } end

-- site prepares a site with rules (and platform rules) like the site table.
local function site(extra, platform_rules)
  local s = {
    id = "s1", cache_zone = "edgeweir_default", load_balance = "weighted_random", domains = { { name = "a.test" } },
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
  }
  for k, v in pairs(extra or {}) do s[k] = v end
  return store.prepare(s, policy.prepare_config({ platform_rules = platform_rules or {} }))
end

-- with_request runs fn with a fake ngx for one request; it returns fn's
-- results and the request state (uri, args, request headers, response
-- headers).
local function with_request(req, fn)
  local real = ngx
  local state = { uri = req.uri or "/", args = req.args, headers = req.headers or {}, header = req.response_headers or {} }
  local var = setmetatable({}, { __index = function(_, k)
    if k == "uri" then return state.uri end
    if k == "args" then return state.args end
    if k == "request_uri" then return req.request_uri or ((req.uri or "/") .. (req.args and ("?" .. req.args) or "")) end
    if k == "host" then return req.host or "a.test" end
    if k == "scheme" then return req.scheme or "http" end
    if k == "remote_addr" then return "192.0.2.1" end
    if k == "edgeweir_local" then return req.is_local and "1" or "" end
  end })
  local fake = setmetatable({
    ctx = {}, var = var, header = state.header, status = req.status or 200,
    req = {
      get_method = function() return req.method or "GET" end,
      set_uri = function(u, jump) assert(jump == false); state.uri = u end,
      set_uri_args = function(a) state.args = a end,
      set_header = function(k, v) state.headers[k:lower()] = v end,
      clear_header = function(k) state.headers[k:lower()] = nil end,
    },
    resp = { get_headers = function() return state.header end },
  }, { __index = real })
  _G.ngx = fake
  local ok, a, b = pcall(fn, fake)
  _G.ngx = real
  if not ok then error(a, 0) end
  return a, state, fake.ctx.edgeweir_policy, b
end

local function access(s, req)
  return with_request(req, function() return policy.access(s, req.headers or {}) end)
end

test("percent_encode and edit_query", function()
  eq(policy.percent_encode("zh CN/é~._-aZ9"), "zh%20CN%2F%C3%A9~._-aZ9")
  eq(policy.percent_encode(""), "")
  eq(policy.edit_query("a=1&utm_source=x&b&utm_source=y&utm_sourcex=1", { { name = "lang", value = "zh CN" } }, { "utm_source", "b" }),
    "a=1&utm_sourcex=1&lang=zh%20CN", "raw names compared exactly")
  eq(policy.edit_query("lang=en&a=1", { { name = "lang", value = "zh" } }, nil), "a=1&lang=zh", "set replaces")
  eq(policy.edit_query("a=1&&b=2", nil, { "a" }), "b=2", "empty elements go")
  eq(policy.edit_query("", nil, { "a" }), "")
  eq(policy.edit_query("", { { name = "v", value = "" } }, nil), "v=")
end)

test("redirect_location", function()
  local r = policy.redirect_location
  eq(r("/new", "a=1", nil, nil, nil), "/new", "query dropped by default")
  eq(r("/new", "a=1", true), "/new?a=1")
  eq(r("/new?x=1#top", "a=1", true), "/new?x=1&a=1#top", "fragment stays last")
  eq(r("/new?", "a=1", true), "/new?a=1")
  eq(r("/new?x=1", "", true), "/new?x=1", "no query to append")
  eq(r("https://b.test/n?a=1#f", "utm_source=x&k=v", true, { { name = "lang", value = "zh CN" }, { name = "src", value = "old" } }, { "session", "utm_source" }),
    "https://b.test/n?a=1&k=v&lang=zh%20CN&src=old#f")
  eq(r("/n?a=1", nil, nil, nil, { "a" }), "/n", "a dangling ? is dropped")
  eq(r("/n?a=1#f", nil, nil, nil, { "a" }), "/n#f")
  eq(r("/n?a=1", nil, true, nil, nil), "/n?a=1", "nothing to preserve")
end)

test("computed targets are checked", function()
  for v, ok in pairs({
    ["/a"] = true, ["https://b.test/x?y#z"] = true, ["HTTP://b.test"] = true, ["//b.test/"] = false, ["/a b"] = false,
    ["/a\\b"] = false, ["/a\tb"] = false, ["/a\127"] = false, ["ftp://b.test/"] = false, ["https://"] = false,
    ["https://u@b.test/"] = false, ["b.test/x"] = false, [""] = false, ["https:/b.test"] = false,
  }) do
    eq(policy.valid_location(v), ok, "location " .. v)
  end
  for v, ok in pairs({ ["/a"] = true, ["/a b"] = true, ["//a"] = false, ["/a?b"] = false, ["/a#b"] = false, ["/a\\b"] = false,
    ["/a\nb"] = false, ["a"] = false, [""] = false }) do
    eq(policy.valid_rewrite(v), ok, "rewrite " .. v)
  end
end)

test("origin override header", function()
  eq(policy.origin_header(nil), "")
  eq(policy.origin_header({}), "")
  local value = policy.origin_header({ origin = { g = "api", h = "api.test:8080", s = "sni.test", p = 8443, c = 2000, w = 30000, r = 1000 } })
  eq(value, "g=api;h=api.test:8080;s=sni.test;p=8443;c=2000;w=30000;r=1000")
  local o = policy.parse_origin_header(value)
  eq(o.group, "api"); eq(o.host, "api.test:8080"); eq(o.sni, "sni.test"); eq(o.port, 8443)
  eq(o.connect, 2000); eq(o.send, 30000); eq(o.read, 1000)
  eq(policy.parse_origin_header(""), nil)
  eq(policy.parse_origin_header(nil), nil)
  eq(policy.parse_origin_header("x=1;p=0;r=abc;c=1.5"), nil, "invalid values are ignored")
  o = policy.parse_origin_header("p=65535;r=3600000")
  eq(o.port, 65535); eq(o.read, 3600000); eq(o.group, nil)
end)

test("bulk redirect table", function()
  eq(policy.prepare_bulk(nil), nil)
  eq(policy.prepare_bulk({}), nil)
  local bulk = policy.prepare_bulk({
    { source = "/old", target = "/new", status = 301 },
    { source = "a.test/old", target = "https://b.test/", status = 308, preserve_query = true },
  })
  eq(policy.bulk_lookup(bulk, "a.test", "/old").status, 308, "host entry first")
  eq(policy.bulk_lookup(bulk, "c.test", "/old").status, 301)
  eq(policy.bulk_lookup(bulk, "a.test", "/old/"), nil, "exact match only")
  assert(not pcall(policy.prepare_bulk, { { source = "/x" } }), "entry without target")
end)

test("dynamic redirects with query edits", function()
  local s = site({ rules = { { id = "r", phase = "redirect", expression = call("starts_with", "boolean", PATH, const("/old/")),
    action = { kind = "redirect", status_code = 308, preserve_query = true, set_query = { { name = "lang", value = "zh CN" } }, remove_query = { "utm_source" },
      target = call("regex_replace", "string", PATH, const("^/old/(.*)$"), const("/new/${1}")) } } } })
  local result = access(s, { uri = "/old/a/b", args = "x=1&utm_source=z" })
  eq(result.status, 308)
  eq(result.location, "/new/a/b?x=1&lang=zh%20CN")
  eq(access(s, { uri = "/other" }), nil, "no match")
  local bad = site({ rules = { { id = "r", phase = "redirect", expression = TRUE,
    action = { kind = "redirect", status_code = 301, target = call("concat", "string", const("//evil.test"), PATH) } } } })
  assert(not pcall(access, bad, { uri = "/x" }), "an invalid computed target fails closed")
end)

test("dynamic rewrites keep the client's request for later lookups", function()
  local s = site({
    rules = {
      { id = "rw", phase = "request-transform", expression = TRUE, action = { kind = "rewrite", preserve_query = false,
        set_query = { { name = "v", value = "2" } }, target = call("wildcard_replace", "string", PATH, const("/IMG/*"), const("/images/${1}")) } },
      { id = "h", phase = "request-transform", expression = TRUE, action = { kind = "request_header", header = "x-a", value = "1" } },
      { id = "seen", phase = "redirect", expression = path_is("/images/a.PNG"), action = { kind = "redirect", status_code = 302, value = "/seen" } },
    },
  })
  local result, state, ctx = access(s, { uri = "/img/a.PNG", args = "a=1" })
  eq(result.location, "/seen", "later phases see the rewritten path")
  eq(state.uri, "/images/a.PNG"); eq(state.args, "v=2")
  eq(ctx.values["http.request.uri"], "/images/a.PNG?v=2")
  eq(ctx.values["http.request.uri.query"], "v=2")
  eq(ctx.values["http.request.uri.path.extension"], "png")
  eq(ctx.values["http.request.headers.x-a"], "1")
  eq(ctx.original["http.request.uri.path"], "/img/a.PNG", "the original stays")
  eq(ctx.original["http.request.uri.query"], "a=1")
  eq(ctx.original["http.request.headers.x-a"], nil)
  eq(ctx.original["http.request.full_uri"], nil, "no rule reads it")
  -- Unset preserve_query keeps the query; edits still apply.
  local keep = site({ rules = { { id = "rw", phase = "request-transform", expression = TRUE, action = { kind = "rewrite", value = "/b", remove_query = { "debug" } } } } })
  local _, st = access(keep, { uri = "/a", args = "debug=1&x=2" })
  eq(st.uri, "/b"); eq(st.args, "x=2")
  _, st = access(keep, { uri = "/a" })
  eq(st.args, nil, "nothing to change")
  local bad = site({ rules = { { id = "rw", phase = "request-transform", expression = TRUE, action = { kind = "rewrite", target = call("concat", "string", PATH, const("?x")) } } } })
  assert(not pcall(access, bad, { uri = "/a" }), "an invalid computed path fails closed")
end)

test("bulk redirects come after the redirect rules and use the original request", function()
  local s = site({
    bulk_redirects = {
      { source = "/old", target = "/new?a=1#f", status = 301, preserve_query = true },
      { source = "/rule", target = "/bulk", status = 301 },
      { source = "a.test/old", target = "https://a.test/host", status = 308 },
    },
    rules = {
      { id = "rw", phase = "request-transform", expression = path_is("/moved"), action = { kind = "rewrite", value = "/old" } },
      { id = "r", phase = "redirect", expression = path_is("/rule"), action = { kind = "redirect", status_code = 302, value = "/from-rule" } },
    },
  })
  local result = access(s, { uri = "/old", args = "q=1", host = "b.test" })
  eq(result.status, 301); eq(result.location, "/new?a=1&q=1#f")
  result = access(s, { uri = "/old", host = "a.test" })
  eq(result.status, 308); eq(result.location, "https://a.test/host", "host entries first")
  eq(access(s, { uri = "/rule" }).location, "/from-rule", "redirect rules first")
  eq(access(s, { uri = "/moved", host = "b.test" }), nil, "a rewritten path is not looked up")
  eq(access(s, { uri = "/old/", host = "b.test" }), nil)
end)

test("config and origin rules fill the policy context", function()
  local s = site({ rules = {
    { id = "c1", phase = "config", expression = TRUE, action = { kind = "config", gzip = true, brotli = false, zstd = false, websocket = false,
      under_attack = true, cc_enabled = false, cc_max_level = "js", origin_connect_timeout_ms = 2000, origin_read_timeout_ms = 5000, log_sample_rate = 0 } },
    { id = "c2", phase = "config", expression = TRUE, action = { kind = "config", brotli = true, origin_read_timeout_ms = 1000 } },
    { id = "o1", phase = "origin", expression = TRUE, action = { kind = "origin", origin_group = "api", host_header = "api.test", port = 8080 } },
    { id = "o2", phase = "origin", expression = TRUE, action = { kind = "origin", sni = "sni.test", port = 8081 } },
  } })
  local _, _, ctx = access(s, { uri = "/" })
  eq(ctx.gzip, true); eq(ctx.br, true, "later rules override"); eq(ctx.zstd, false)
  eq(ctx.websocket, false); eq(ctx.under_attack, true); eq(ctx.cc_enabled, false); eq(ctx.cc_max_level, 2)
  eq(ctx.log_sample_rate, 0)
  eq(policy.origin_header(ctx), "g=api;h=api.test;s=sni.test;p=8081;c=2000;r=1000")
  eq(policy.cc_level(ctx, 4), 0, "CC off")
  eq(policy.cc_level({ cc_max_level = 2 }, 4), 2)
  eq(policy.cc_level({ cc_max_level = 2 }, 1), 1)
  eq(policy.cc_level(nil, 3), 3)
end)

test("config gzip=false no longer bypasses the cache", function()
  local rule = { id = "g", phase = "config", expression = TRUE, action = { kind = "config", gzip = false } }
  local plain = site({ rules = { rule } })
  local _, state, ctx = access(plain, { uri = "/", headers = { ["accept-encoding"] = "gzip, br" } })
  eq(state.headers["accept-encoding"], nil, "no edge compression: the origin gets no Accept-Encoding")
  eq(ctx.cache_bypass, nil)
  local edge = site({ rules = { rule }, tls = { gzip = true, gzip_min_length = 1 } })
  _, state, ctx = access(edge, { uri = "/", headers = { ["accept-encoding"] = "gzip, br" } })
  eq(state.headers["accept-encoding"], "gzip, br", "the edge compresses: gzip is dropped per response")
  eq(ctx.gzip, false); eq(ctx.cache_bypass, nil)
end)

test("response phases: response-transform, then compression with the media type", function()
  local s = site({ rules = {
    { id = "t", phase = "response-transform", expression = TRUE, action = { kind = "response_header", header = "content-type", value = "application/json; charset=utf-8" } },
    { id = "c1", phase = "compression", expression = TRUE, action = { kind = "compression", compression = { "br" } } },
    { id = "c2", phase = "compression", expression = { op = "eq", field = "http.response.content_type.media_type", value_type = "string", value = "text/html" },
      action = { kind = "compression", compression = { "gzip", "br" } } },
    { id = "c3", phase = "compression", expression = call("ends_with", "boolean", { op = "field", field = "http.response.headers.x-off", value_type = "string" }, const("1")),
      action = { kind = "compression" } },
  } })
  local _, _, ctx = with_request({ uri = "/", response_headers = { ["content-type"] = " Text/HTML ; charset=x" } }, function()
    policy.access(s, {})
    policy.response(s)
  end)
  eq(ctx.values["http.response.content_type.media_type"], "application/json", "after response-transform")
  eq(table.concat(ctx.compression, ","), "br")
  local html = site({ rules = { s.rules[2], s.rules[3] } })
  _, _, ctx = with_request({ uri = "/", response_headers = { ["content-type"] = " Text/HTML ; charset=x" } }, function()
    policy.access(html, {})
    policy.response(html)
  end)
  eq(ctx.values["http.response.content_type.media_type"], "text/html")
  eq(table.concat(ctx.compression, ","), "gzip,br", "the last matching rule wins")
  _, _, ctx = with_request({ uri = "/", response_headers = { ["content-type"] = "text/html", ["x-off"] = "1" } }, function()
    policy.access(s, {})
    policy.response(s)
  end)
  eq(#ctx.compression, 0, "an empty list (omitted in the site table) is identity")
  eq(ctx.original, nil, "the original request is dropped once the response phases run")
end)

test("derived fields are computed only for sites that read them", function()
  local full = { op = "contains", field = "http.request.full_uri", value_type = "string", value = "x" }
  local ext = { op = "eq", field = "http.request.uri.path.extension", value_type = "string", value = "png" }
  local plain = site({ rules = { { id = "r", phase = "waf-custom", expression = path_is("/x"), action = { kind = "log" } } } })
  eq(plain._full_uri, nil); eq(plain._extension, nil); eq(plain._media_type, nil)
  local _, _, ctx = access(plain, { uri = "/a.PNG", args = "q=1" })
  eq(ctx.values["http.request.full_uri"], nil); eq(ctx.values["http.request.uri.path.extension"], nil)
  -- A platform rule, a cache rule condition or a value expression reading them.
  local platform = site(nil, { { id = "p", phase = "waf-custom", expression = full, action = { kind = "log" } } })
  eq(platform._full_uri, true)
  _, _, ctx = access(platform, { uri = "/a.PNG", args = "q=1", scheme = "https" })
  eq(ctx.values["http.request.full_uri"], "https://a.test/a.PNG?q=1")
  eq(ctx.values["http.request.uri.path.extension"], nil)
  local cached = site({ cache_rules = { { id = "c", action = "cache", ttl = 1, mode = "override", condition = ext } } })
  eq(cached._extension, true)
  _, _, ctx = access(cached, { uri = "/a.PNG" })
  eq(ctx.original["http.request.uri.path.extension"], "png")
  local target = site({ rules = { { id = "r", phase = "redirect", expression = TRUE,
    action = { kind = "redirect", status_code = 301, target = call("concat", "string", const("/x"), { op = "field", field = "http.request.full_uri", value_type = "string" }) } } } })
  eq(target._full_uri, true)
  local media = site({ rules = { { id = "c", phase = "compression", expression = { op = "eq", field = "http.response.content_type.media_type", value_type = "string", value = "text/html" }, action = { kind = "compression" } } } })
  eq(media._media_type, true); eq(media._response_rules, true)
end)

test("response phases are skipped without response rules", function()
  local s = site({ rules = { { id = "r", phase = "waf-custom", expression = TRUE, action = { kind = "log" } } } })
  eq(s._response_rules, false)
  local _, _, ctx = with_request({ uri = "/" }, function(fake)
    policy.access(s, {})
    fake.resp.get_headers = function() error("response headers read") end
    policy.response(s)
  end)
  eq(ctx.values["http.response.code"], nil)
  assert(ctx.original, "nothing touched the original request")
  eq(site(nil, { { id = "p", phase = "response-transform", expression = TRUE, action = { kind = "response_header", header = "x-a", value = "1" } } })._response_rules, true,
    "platform response rules count")
  -- Response rules that do not read the media type do not compute it.
  local t = site({ rules = { { id = "t", phase = "response-transform", expression = TRUE, action = { kind = "response_header", header = "x-a", value = "1" } } } })
  _, _, ctx = with_request({ uri = "/", response_headers = { ["content-type"] = "text/html" } }, function()
    policy.access(t, {})
    policy.response(t)
  end)
  eq(ctx.values["http.response.code"], 200)
  eq(ctx.values["http.response.content_type.media_type"], nil)
end)

test("browser TTL flag", function()
  eq(site({ cache_rules = { { id = "c", action = "cache", ttl = 1, mode = "override", path_prefixes = { "/" } } } })._browser_ttl, nil)
  eq(site({ cache_rules = { { id = "c", action = "cache", ttl = 1, mode = "override", browser_ttl = 60 } } })._browser_ttl, true)
  eq(site({})._browser_ttl, nil)
end)

test("cache rule conditions see the original request", function()
  local s = site({
    rules = { { id = "rw", phase = "request-transform", expression = TRUE, action = { kind = "rewrite", value = "/rewritten.css" } } },
    cache_rules = {
      { id = "img", action = "cache", ttl = 60, mode = "override", browser_ttl = 600,
        condition = { op = "and", children = { call("starts_with", "boolean", PATH, const("/img/")),
          { op = "in", field = "http.request.uri.path.extension", value_type = "string", values = { "png" } } } } },
      { id = "css", action = "cache", ttl = 60, mode = "override", extensions = { "css" } },
      { id = "rest", action = "bypass", ttl = 0, mode = "override" },
    },
  })
  local _, _, ctx = access(s, { uri = "/img/a.PNG" })
  local chain = rules.chain(s, "/img/a.PNG", false, ctx.original)
  eq(chain[1].id, "img")
  eq(ctx.values["http.request.uri.path"], "/rewritten.css")
  eq(rules.chain(s, ctx.values["http.request.uri.path"], false, ctx.values)[1].id, "css", "the rewritten request would differ")
  eq(rules.chain(s, "/img/a.png")[1].id, "img", "values built from the path when absent")
  eq(rules.chain(s, "/x/a.png", false, { ["http.request.uri.path"] = "/x/a.png", ["http.request.uri.path.extension"] = "png" })[1].id, "rest")
  -- Browser TTL: the deciding rule caches.
  eq(rules.browser_cache_control(chain, 200, 10, false, "max-age=5, private"), "max-age=600", "override replaces")
  eq(rules.browser_cache_control(chain, 404, 10, false, nil), nil, "not cached: rest decides")
  eq(rules.browser_cache_control(rules.chain(s, "/a.css"), 200, 10, false, nil), nil, "no browser TTL")
  local respect = rules.prepare({ id = "r", action = "cache", ttl = 60, mode = "respect", browser_ttl = 30 })
  eq(rules.browser_cache_control({ respect }, 200, 1, false, "public, max-age=10"), "max-age=30")
  eq(rules.browser_cache_control({ respect }, 200, 1, false, { "public", "Private" }), nil, "origin keeps it private")
  eq(rules.browser_cache_control({ respect }, 200, 1, false, "no-store"), nil)
  eq(rules.browser_cache_control({ respect }, 200, 1, true, nil), nil, "Authorization without cache_authorized")
  local zero = rules.prepare({ id = "z", action = "cache", ttl = 0, mode = "override", browser_ttl = 30 })
  eq(rules.browser_cache_control({ zero }, 200, 1, false, nil), nil, "a TTL of 0 stores nothing")
end)

test("origin rules: groups, Host, SNI and port", function()
  local s = site({ origins = {
    { id = "d1", scheme = "https", address = "default.test", port = 443, weight = 1, sni = "own.test" },
    { id = "a1", scheme = "http", address = "api1.test", port = 80, weight = 1, group = "api", host_header = "own.test:80" },
    { id = "a2", scheme = "http", address = "api2.test", port = 80, weight = 1, group = "api", backup = true },
    { id = "s3", scheme = "https", address = "s3.test", port = 443, weight = 1, group = "store", s3 = { region = "r", credential_id = "c" } },
  } })
  local now = ngx.now()
  local function ids(list) local out = {}; for i, o in ipairs(list) do out[i] = o.id end; return table.concat(out, ",") end
  eq(ids(lb.order(s, "/", now)), "d1", "the default group")
  eq(ids(lb.order(s, "/", now, nil, "")), "d1")
  eq(ids(lb.order(s, "/", now, nil, "api")), "a1", "backups wait")
  eq(ids(lb.order(s, "/", now, nil, "missing")), "", "a group without origins")
  eq(#s._primaries, 1); eq(s._pools.api.bw, 1)
  local o = s._pools[""].primaries[1]
  eq(origin.effective(o, nil), o)
  eq(origin.effective(o, { group = "api" }), o, "nothing to override")
  local e = origin.effective(o, { host = "h.test:8443", port = 8443 })
  eq(e.port, 8443); eq(e.host_header, "h.test:8443"); eq(e.url, "https://default.test:8443"); eq(e.sni_name, "own.test", "the origin's SNI stays")
  eq(o.port, 443, "the site's origin is unchanged")
  e = origin.effective(s._pools.api.primaries[1], { host = "h.test" })
  eq(e.sni_name, "h.test", "a Host override names the TLS server like a configured Host")
  e = origin.effective(s._pools.api.primaries[1], { sni = "x.test", port = 8081 })
  eq(e.sni_name, "x.test"); eq(e.host_header, "own.test:80"); eq(e.port, 8081)
  local s3 = s._pools.store.primaries[1]
  e = origin.effective(s3, { host = "h.test" })
  eq(e, s3, "S3 origins keep their signing host")
  e = origin.effective(s3, { host = "h.test", port = 9000 })
  eq(e.host_header, nil); eq(e._s3_host, "s3.test:9000")
end)

test("store: field flags, bulk redirects and invalid pushes", function()
  local geo = { op = "eq", field = "ip.geoip.country", value_type = "string", value = "NZ" }
  local ja4 = { op = "field", field = "tls.ja4", value_type = "string" }
  eq(site({ cache_rules = { { id = "c", action = "cache", ttl = 1, mode = "override", condition = geo } } })._geo, true, "cache rule condition")
  eq(site({ rules = { { id = "r", phase = "redirect", expression = TRUE, action = { kind = "redirect", status_code = 301, target = call("concat", "string", const("/"), ja4) } } } })._ja4, true, "value expression")
  eq(site({ rules = { { id = "r", phase = "waf-custom", expression = { op = "eq", value_type = "string", value = "x", children = { call("lower", "string", ja4) } }, action = { kind = "log" } } } })._ja4, true, "function argument")
  local plain = site({ rules = { { id = "r", phase = "waf-custom", expression = call("starts_with", "boolean", PATH, const("/ip.geoip.")), action = { kind = "log" } } } })
  eq(plain._geo, nil); eq(plain._ja4, false)
  eq(site({ bulk_redirects = { { source = "/a", target = "/b", status = 301 } } })._bulk["/a"].target, "/b")
  local base = { id = "p1", domains = { { name = "p.test" } }, cache_zone = "z", origins = { { id = "o", scheme = "http", address = "o.test", port = 80 } } }
  local function push(extra)
    local s = {}
    for k, v in pairs(base) do s[k] = v end
    for k, v in pairs(extra) do s[k] = v end
    return store.replace({ revision = "9", sites = { s } })
  end
  local st, err, code = push({ cache_rules = { { id = "c", action = "cache", condition = { op = "in_list", field = "ip.src", value_type = "ip", value = "missing" } } } })
  eq(st, nil); eq(err, "invalid site policy"); eq(code, 400)
  st, err = push({ bulk_redirects = { { source = "/a" } } })
  eq(err, "invalid site policy")
  st, err = push({ bulk_redirects = { { source = "/a", target = "/b", status = 301 } } })
  assert(st, err)
end)

test("log rules count their matches per rule and minute, never on the local listeners", function()
  local stats = require("edgeweir.stats")
  ngx.shared.edgeweir_stats:flush_all()
  local s = site({ rules = {
    { id = "seen", phase = "waf-custom", expression = path_is("/x"), action = { kind = "log" } },
    { id = "other", phase = "waf-custom", expression = path_is("/y"), action = { kind = "log" } },
  } }, { { id = "global", phase = "waf-custom", expression = TRUE, action = { kind = "log" } } })
  access(s, { uri = "/x" })
  access(s, { uri = "/x" })
  access(s, { uri = "/z" })
  access(s, { uri = "/x", is_local = true })
  -- Summed over the buckets, in case a minute ended in between.
  local counts, buckets = {}, 0
  for _, b in ipairs(stats.drain(ngx.time() + 60)) do
    if b.site_id == "s1" then
      buckets = buckets + 1
      eq(b.waf_rules, nil)
      for id, n in pairs(b.logged_rules or {}) do counts[id] = (counts[id] or 0) + n end
    end
  end
  assert(buckets > 0, "no bucket for the site")
  eq(counts.seen, 2)
  eq(counts.global, 3, "platform log rules count for the site")
  eq(counts.other, nil, "rules that never matched are absent")
  eq(#stats.drain(ngx.time() + 60), 0, "drained")
end)

test("logged rules keep the heaviest of a minute", function()
  local stats = require("edgeweir.stats")
  local dict = ngx.shared.edgeweir_stats
  dict:flush_all()
  local minute = math.floor(ngx.time() / 60) * 60 - 60
  for i = 1, stats.MAX_LOGGED_RULES + 5 do
    dict:set(minute .. "|s2|lr" .. string.format("%02d", i), i)
  end
  local bucket = stats.drain(ngx.time())[1]
  eq(bucket.site_id, "s2")
  local n = 0
  for _ in pairs(bucket.logged_rules) do n = n + 1 end
  eq(n, stats.MAX_LOGGED_RULES, "bounded")
  eq(bucket.logged_rules["r25"], 25)
  eq(bucket.logged_rules["r05"], nil, "the lightest are dropped")
end)

test("config rules switch the site's Under Attack", function()
  local s = { id = "s", _config = {}, protection = { under_attack = false, under_attack_challenge = "pow" } }
  eq(challenge.required(s, 0), 0)
  local level, kind = challenge.required(s, 0, true)
  eq(level, 3); eq(kind, "pow")
  s.protection.under_attack = true
  eq(challenge.required(s, 0, false), 0, "turned off for the request")
  level, kind = challenge.required({ id = "t", _config = {} }, 0, true)
  eq(level, 2); eq(kind, "js", "without a site protection: js")
  s._config.platform_protection = { under_attack = true, challenge = "cookie302" }
  eq(challenge.required(s, 0, false), 1, "the platform's stays")
end)

test("domains waiting for the certificate are served over HTTP (tls-pending-domains-v1)", function()
  local s = site({
    certificate_id = "cert-a",
    tls = { force_https = true, hsts_max_age = 60 },
    domains = {
      { name = "a.test" }, { name = "new.a.test", tls_pending = true },
      { name = "w.test", wildcard = true, tls_pending = true }, { name = "x.w.test" },
    },
  })
  eq(policy.tls_pending(s, "a.test"), false)
  eq(policy.tls_pending(s, "new.a.test"), true)
  eq(policy.tls_pending(s, "y.w.test"), true, "below the waiting wildcard")
  eq(policy.tls_pending(s, "x.w.test"), false, "an exact name wins over the wildcard")
  eq(policy.tls_pending(s, "w.test"), false, "a wildcard does not cover its own name")
  eq(policy.tls_pending(s, nil), false)
  eq(access(s, { host = "a.test", uri = "/p" }).status, 301)
  eq(access(s, { host = "a.test", uri = "/p" }).location, "https://a.test/p")
  eq(access(s, { host = "new.a.test", uri = "/p" }), nil, "no redirect to an HTTPS it has not")
  eq(access(s, { host = "y.w.test", uri = "/p" }), nil)
  -- A config rule forcing HTTPS does not redirect it either.
  local forced = site({
    certificate_id = "cert-a",
    rules = { { id = "r1", phase = "config", expression = TRUE, action = { kind = "config", force_https = true } } },
    domains = { { name = "a.test" }, { name = "new.a.test", tls_pending = true } },
  })
  eq(access(forced, { host = "new.a.test", uri = "/" }), nil)
  eq(access(forced, { host = "a.test", uri = "/" }).status, 301)
  -- Sites without waiting domains carry nothing.
  eq(site({})._tls_pending, nil)
  eq(policy.tls_pending(site({}), "a.test"), false)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
