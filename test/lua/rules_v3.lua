-- Rules of proto v0.22.0 (feature rules-v3) in the data plane: the new
-- request and response fields, cookies and query parameters by name (also
-- after rewrites), computed header values (skipped when invalid, logged
-- once per rule), response header lines added with append, computed query
-- parameters and redirect status 303, and the site flags that keep the
-- per-request work to sites whose rules read the fields.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' \
--         --shdict 'edgeweir_health 1m' --shdict 'edgeweir_policy_logs 1m' \
--         --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' test/lua/rules_v3.lua
local policy = require("edgeweir.policy")
local store = require("edgeweir.store")

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
local function field(name, typ) return { op = "field", field = name, value_type = typ or "string" } end
local function const(v) return { op = "const", value_type = "string", value = v } end
local function call(name, typ, ...) return { op = "call", field = name, value_type = typ, children = { ... } } end
local function is(name, v) return { op = "eq", field = name, value_type = "string", value = v } end

local function site(extra, platform_rules)
  local s = {
    id = "s1", cache_zone = "edgeweir_default", load_balance = "weighted_random", domains = { { name = "a.test" } },
    origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
  }
  for k, v in pairs(extra or {}) do s[k] = v end
  return store.prepare(s, policy.prepare_config({ platform_rules = platform_rules or {} }))
end

-- with_request runs fn with a fake ngx for one request; it returns fn's
-- result, the request state (uri, args, request and response headers) and
-- the policy context.
local function with_request(req, fn)
  local real = ngx
  local state = { uri = req.uri or "/", args = req.args, headers = req.headers or {}, header = req.response_headers or {} }
  local vars = {
    host = req.host or "a.test", scheme = req.scheme or "https", remote_addr = "192.0.2.1",
    server_protocol = req.protocol or "HTTP/2.0", edgeweir_request_id = req.id or "req-1",
    server_port = req.port or "443", upstream_cache_status = req.cache_status,
  }
  local var = setmetatable({}, { __index = function(_, k)
    if k == "uri" then return state.uri end
    if k == "args" then return state.args end
    if k == "request_uri" then return (req.uri or "/") .. (req.args and ("?" .. req.args) or "") end
    return vars[k]
  end })
  local fake = setmetatable({
    ctx = {}, var = var, header = state.header, status = req.status or 200,
    req = {
      get_method = function() return "GET" end,
      start_time = function() return 1791331200.25 end,
      set_uri = function(u, jump) assert(jump == false); state.uri = u end,
      set_uri_args = function(a) state.args = a end,
      set_header = function(k, v) state.headers[k:lower()] = v end,
      clear_header = function(k) state.headers[k:lower()] = nil end,
    },
    resp = { get_headers = function() return state.header end },
  }, { __index = real })
  _G.ngx = fake
  local ok, a = pcall(fn, fake)
  _G.ngx = real
  if not ok then error(a, 0) end
  return a, state, fake.ctx.edgeweir_policy
end

local function access(s, req)
  return with_request(req, function() return policy.access(s, req.headers or {}) end)
end

-- respond runs the access phase, then the response phases with the
-- response headers in req.response_headers.
local function respond(s, req)
  return with_request(req, function(fake)
    local result = policy.access(s, req.headers or {})
    assert(result == nil, "the request was answered")
    policy.response(s)
    return fake.header
  end)
end

-- echo returns a site whose request-transform rule copies field into
-- request header x-echo.
local function echo(expression, extra)
  local s = extra or {}
  s.rules = { { id = "echo", phase = "request-transform", expression = TRUE,
    action = { kind = "request_header", header = "x-echo", target = expression } } }
  return site(s)
end

test("request fields: version, scheme, id, timestamp, port, Referer and User-Agent", function()
  for f, want in pairs({
    ["http.request.version"] = "HTTP/2.0", ["http.request.scheme"] = "https", ["http.request.id"] = "req-1",
    ["http.referer"] = "https://b.test/", ["http.user_agent"] = "curl/8.10.1",
  }) do
    local _, state = access(echo(field(f)), { headers = { referer = "https://b.test/", ["user-agent"] = "curl/8.10.1" } })
    eq(state.headers["x-echo"], want, f)
  end
  local _, state = access(echo(call("to_string", "string", field("http.request.timestamp.sec", "number"))), {})
  eq(state.headers["x-echo"], "1791331200", "whole seconds")
  _, state = access(echo(call("to_string", "string", field("edge.server_port", "number"))), { port = "8443" })
  eq(state.headers["x-echo"], "8443")
  _, state = access(echo(field("http.user_agent")), {})
  eq(state.headers["x-echo"], "", "no User-Agent")
end)

test("cookies and query parameters by name: first value, raw, empty when missing", function()
  local cookie = echo(call("concat", "string", field("http.request.cookies.role"), const("|"), field("http.request.cookies.sid")))
  local _, state = access(cookie, { headers = { cookie = "sid=a%20b; role=admin; role=root" } })
  eq(state.headers["x-echo"], "admin|a%20b")
  _, state = access(cookie, { headers = { cookie = { "role=x", "sid=y" } } })
  eq(state.headers["x-echo"], "x|y", "several Cookie headers")
  _, state = access(cookie, {})
  eq(state.headers["x-echo"], "|", "no Cookie header")
  local arg = echo(field("http.request.uri.args.next"))
  _, state = access(arg, { args = "a=1&next=%2Fhome&next=x" })
  eq(state.headers["x-echo"], "%2Fhome")
  _, state = access(arg, {})
  eq(state.headers["x-echo"], "")
end)

test("query parameters follow rewrites like http.request.uri.query", function()
  local s = site({ rules = {
    { id = "rw", phase = "request-transform", expression = TRUE,
      action = { kind = "rewrite", value = "/b", preserve_query = false, set_query = { { name = "next", value = "/new" } } } },
    { id = "echo", phase = "request-transform", expression = TRUE,
      action = { kind = "request_header", header = "x-echo", target = field("http.request.uri.args.next") } },
  } })
  local _, state = access(s, { uri = "/a", args = "next=/old" })
  eq(state.args, "next=%2Fnew")
  eq(state.headers["x-echo"], "%2Fnew", "the rewritten query")
end)

test("computed request headers in request-transform and origin; aliases follow", function()
  local s = site({ rules = {
    { id = "ua", phase = "request-transform", expression = TRUE,
      action = { kind = "request_header", header = "user-agent", target = call("concat", "string", const("edge "), field("http.user_agent")) } },
    { id = "check", phase = "waf-custom", expression = { op = "wildcard", field = "http.user_agent", value_type = "string", value = "edge *" },
      action = { kind = "block", status_code = 403 } },
    { id = "country", phase = "origin", expression = TRUE,
      action = { kind = "request_header", header = "x-req", target = field("http.request.id") } },
  } })
  local result, state = access(s, { headers = { ["user-agent"] = "curl" } })
  eq(result and result.status, 403, "later rules read the computed User-Agent")
  eq(state.headers["user-agent"], "edge curl")
  s = site({ rules = { s.rules[3] } })
  result, state = access(s, {})
  eq(result, nil)
  eq(state.headers["x-req"], "req-1")
end)

test("invalid computed header values skip the action and log once per rule", function()
  local logs = ngx.shared.edgeweir_policy_logs
  logs:flush_all()
  local s = site({ rules = {
    { id = "bad", phase = "request-transform", expression = TRUE,
      action = { kind = "request_header", header = "x-v", target = call("url_decode", "string", field("http.request.uri.args.v")) } },
  } })
  local real_log, notices = ngx.log, 0
  ngx.log = function(level, ...)
    if level == ngx.NOTICE and table.concat({ ... }):find("header value skipped site=s1 rule=bad", 1, true) then notices = notices + 1 end
  end
  local ok, err = pcall(function()
    local result, state = access(s, { args = "v=a%0Ab", headers = { ["x-v"] = "client" } })
    eq(result, nil, "the request goes on")
    eq(state.headers["x-v"], "client", "the header is left alone")
    access(s, { args = "v=" .. string.rep("a", 4097) })
    result, state = access(s, { args = "v=a%20b" })
    eq(state.headers["x-v"], "a b")
  end)
  ngx.log = real_log
  assert(ok, err)
  eq(notices, 1, "one NOTICE per rule and node every 60 seconds")
  eq(logs:get("header:bad"), true)
end)

test("response headers: computed values, cache status and added lines", function()
  local s = site({ rules = {
    { id = "status", phase = "response-transform", expression = TRUE,
      action = { kind = "response_header", header = "x-cache-status", target = call("concat", "string", const("edge-"), field("http.response.cache_status")) } },
    { id = "l1", phase = "response-transform", expression = TRUE,
      action = { kind = "response_header", header = "link", value = "</a.css>; rel=preload", append = true } },
    { id = "l2", phase = "response-transform", expression = TRUE,
      action = { kind = "response_header", header = "link", target = call("concat", "string", const("<"), PATH, const(">; rel=canonical")), append = true } },
    { id = "check", phase = "response-transform", expression = is("http.response.headers.link", "<o>, </a.css>; rel=preload, </p>; rel=canonical"),
      action = { kind = "response_header", header = "x-links", value = "3" } },
  } })
  local header = respond(s, { uri = "/p", cache_status = "HIT", response_headers = { link = "<o>" } })
  eq(header["x-cache-status"], "edge-HIT")
  eq(type(header.link), "table")
  eq(table.concat(header.link, " | "), "<o> | </a.css>; rel=preload | </p>; rel=canonical")
  eq(header["x-links"], "3", "later rules read every line")
  header = respond(s, { uri = "/p" })
  eq(header["x-cache-status"], "edge-", "responses the node made itself")
  eq(table.concat(header.link, " | "), "</a.css>; rel=preload | </p>; rel=canonical", "the first line starts the header")
end)

test("303 redirects and computed query parameters", function()
  local s = site({ rules = {
    { id = "r", phase = "redirect", expression = is("http.request.uri.path", "/login"),
      action = { kind = "redirect", value = "/signin", status_code = 303,
        set_query = { { name = "next", value = "", expression = field("http.request.uri.args.next") }, { name = "v", value = "1" } } } },
    { id = "rw", phase = "request-transform", expression = is("http.request.uri.path", "/x"),
      action = { kind = "rewrite", value = "/y", set_query = { { name = "sig", value = "", expression = call("md5", "string", PATH) } } } },
  } })
  local result = access(s, { uri = "/login", args = "next=/a b" })
  eq(result.status, 303)
  eq(result.location, "/signin?next=%2Fa%20b&v=1", "computed values are percent-encoded")
  local _, state = access(s, { uri = "/x", args = "k=1" })
  eq(state.uri, "/y")
  eq(state.args, "k=1&sig=" .. ngx.md5("/x"), "computed from the request before the rewrite")
end)

test("site flags: only sites whose rules read the new fields compute them", function()
  local plain = site({ rules = { { id = "p", phase = "waf-custom", expression = is("http.host", "a.test"), action = { kind = "log" } } } })
  eq(plain._request_v3, nil); eq(plain._cookies, nil); eq(plain._args, nil); eq(plain._cache_status, nil)
  local s = site({ rules = {
    { id = "q", phase = "redirect", expression = TRUE,
      action = { kind = "redirect", value = "/", status_code = 302, set_query = { { name = "n", value = "", expression = field("http.request.uri.args.page") } } } },
    { id = "h", phase = "response-transform", expression = TRUE,
      action = { kind = "response_header", header = "x-s", target = field("http.response.cache_status") } },
  } }, { { id = "pl", phase = "waf-custom", expression = is("http.request.cookies.role", "x"), action = { kind = "log" } },
    { id = "pv", phase = "waf-custom", expression = is("http.request.version", "HTTP/1.0"), action = { kind = "log" } } })
  eq(s._args and s._args.page, true, "set query parameter expressions")
  eq(s._cookies and s._cookies.role, true, "platform rules")
  eq(s._request_v3, true)
  eq(s._cache_status, true, "header value expressions")
  local geo = site({ rules = { { id = "g", phase = "origin", expression = TRUE,
    action = { kind = "request_header", header = "x-as", target = field("ip.geoip.as_name") } } } })
  eq(geo._geo, true, "a header value reads GeoIP")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
