local json = require("cjson.safe")
local api = require("edgeweir.apisecurity")
local store = require("edgeweir.store")
local router = require("edgeweir.router")
local auth = require("edgeweir.auth")
local policy = require("edgeweir.policy")
local accesslogs = require("edgeweir.accesslogs")
local reasons = require("edgeweir.reasons")

local passed, failed = 0, 0
local real_ask, real_auth = api.ask, auth.check
local function eq(got, want) assert(got == want, "got " .. tostring(got) .. ", want " .. tostring(want)) end
local function test(name, fn)
  ngx.shared.edgeweir_logs:flush_all()
  local ok, err = pcall(fn)
  api.ask, auth.check = real_ask, real_auth
  if ok then passed = passed + 1; print("ok   " .. name) else failed = failed + 1; print("FAIL " .. name .. ": " .. tostring(err)) end
end
local function settings()
  return { version = 1, discovery = { enabled = false, sampleRate = 1000 },
    schema = { mode = "off", unknownEndpoints = "allow", endpoints = {}, issues = {} },
    jwt = { mode = "enforce", scope = { domains = {}, pathPrefixes = { "/private/" }, extensions = {}, excludePathPrefixes = { "/private/public/" } } },
    graphql = { mode = "off", pathPrefixes = { "/graphql" } }, exceptions = {} }
end
local function install(cfg, extra)
  local site = { id = "api-site", domains = { { name = "api.test" } }, origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } },
    cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random", log_sample_rate = 0,
    api_security = cfg or settings(), api_security_version = string.rep("a", 64),
    cache_rules = { { id = "all", action = "cache", ttl = 600, mode = "override", cache_authorized = true } } }
  for k, v in pairs(extra or {}) do site[k] = v end
  assert(store.replace({ revision = "1", content_hash = "api", sites = { site } }))
  return store.lookup_host("api.test")
end
local sequence = 0
local function request(req, run)
  req = req or {}
  sequence = sequence + 1
  local runtime = ngx
  local headers = req.headers or {}
  local uri = req.uri or "/private/data"
  local path, args = uri:match("^([^?]*)%??(.*)$")
  local var = { scheme = "http", host = req.host or "api.test", http_host = "api.test", uri = req.path or path, request_uri = uri,
    args = args ~= "" and args or nil, server_port = "80", remote_addr = "192.0.2.1", realip_remote_addr = "192.0.2.1",
    edgeweir_request_id = "api-req-" .. sequence, request_id = string.format("%032x", sequence), edgeweir_site = "", edgeweir_local = "", edgeweir_ctx_ref = "",
    http_authorization = headers.authorization, http_cookie = headers.cookie, http_content_length = req.body and tostring(#req.body) or req.content_length,
    http_transfer_encoding = req.transfer_encoding, request_method = req.method or "GET", server_protocol = "HTTP/1.1" }
  local ctx, response, out = {}, {}, { body = {} }
  local h = setmetatable({}, { __index = function(_, k) return response[k:lower()] end, __newindex = function(_, k, v) response[k:lower()] = v end })
  local fake = setmetatable({ ctx = ctx, var = var, header = h, is_subrequest = false,
    req = { get_method = function() return req.method or "GET" end,
      get_headers = function() local copy = {}; for k, v in pairs(headers) do copy[k] = v end; return copy end,
      clear_header = function(k) headers[k:lower()] = nil; if k:lower() == "authorization" then var.http_authorization = nil end end,
      set_header = function(k, v) headers[k:lower()] = v end,
      set_uri = function(p) var.uri = p end, set_uri_args = function(a) var.args = a end,
      http_version = function() return req.http_version or 1.1 end, read_body = function() out.read = true end,
      get_body_data = function() return req.body end, get_body_file = function() return nil end,
    },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    exit = function(code) out.exit = code end, exec = function(name) out.exec = name end,
    redirect = function(target, status) out.location, out.redirect = target, status end,
    log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, value = pcall(run or router.access)
  _G.ngx = runtime
  assert(ok, value)
  out.ctx, out.var, out.headers, out.response = ctx, var, headers, response
  out.status = rawget(fake, "status") or out.redirect or 200
  out.value = value
  return out
end
local function allowed(request)
  return { status = 0, log = { template = api.discover(request.path), source = "traffic", issues = {}, exceptionIds = {} } }
end

test("API executes after auth, captures original Authorization and precedes request rules", function()
  local cfg = settings()
  cfg.schema.mode = "enforce"
  cfg.schema.endpoints = { { method = "GET", path = "/private/data" } }
  install(cfg, { auth_rules = { { id = "auth", kind = "forward", forward = { url = "https://auth.test" } } }, rules = {
    { id = "allow", phase = "waf-custom", expression = { op = "literal", value_type = "boolean", value = "true" }, action = { kind = "allow" } },
    { id = "skip", phase = "waf-custom", expression = { op = "literal", value_type = "boolean", value = "true" }, action = { kind = "skip", skip = { "rules", "crs", "rate_limits" } } },
  } })
  local authenticated, asked = false, false
  auth.check = function() authenticated = true; ngx.req.clear_header("authorization") end
  api.ask = function(req)
    assert(authenticated); eq(req.authorization[1], "Bearer original")
    eq(ngx.var.http_authorization, nil); eq(req.version, string.rep("a", 64))
    eq(ngx.ctx.edgeweir_policy.allowed, nil)
    asked = true
    return { status = 403, error = "api-security-schema", log = { template = "/private/data", source = "schema", issues = { { check = "schema", mode = "enforce", code = "schema-type" } }, exceptionIds = {} } }
  end
  local out = request({ headers = { authorization = "Bearer original" } })
  assert(asked); eq(out.status, 403); eq(out.response["x-edgeweir-error"], "api-security-schema"); eq(out.ctx.edgeweir_reason, "api_security")
end)

test("JWT scope bypasses cache even observe, exception or cache-authorized rules", function()
  for _, mode in ipairs({ "observe", "enforce" }) do
    local cfg = settings(); cfg.jwt.mode = mode
    install(cfg, { rules = { { id = "cache-on", phase = "config", expression = { op = "literal", value_type = "boolean", value = "true" }, action = { kind = "config", cache_bypass = false } } } })
    api.ask = function(req)
      assert(req.jwt_scoped)
      local result = allowed(req); result.log.exceptionIds = { "12345678-1234-4234-8234-123456789abc" }; return result
    end
    local out = request({ headers = { authorization = "Bearer credential" } })
    eq(out.status, 200); eq(out.ctx.edgeweir_api_cache_bypass, true); assert(out.var.edgeweir_cache_bypass ~= "0", "JWT lookup enabled cache")
    assert(out.var.edgeweir_no_cache ~= "0", "JWT response may be cached")
  end
  local s = install()
  api.ask = allowed
  local out = request({ uri = "/public/data", headers = { authorization = "Bearer credential" } })
  eq(out.ctx.edgeweir_api_cache_bypass, nil)
  eq(out.var.edgeweir_cache_bypass, "0", "outside scope retains existing cache-authorized behavior")
end)

test("scope matches auth domains, case-insensitive prefixes, extensions and excludes", function()
  local cfg = settings(); cfg.jwt.scope = { domains = { "*.api.test" }, pathPrefixes = { "/private/" }, extensions = { "json" }, excludePathPrefixes = { "/private/public/" } }
  local s = install(cfg)
  for _, c in ipairs({
    { "/PRIVATE/data.JSON", "sub.api.test", true }, { "/private/data.json", "api.test", false },
    { "/private/data.png", "sub.api.test", false }, { "/private/public/data.json", "sub.api.test", false },
    { "/private/public/data.json;x", "sub.api.test", true }, { "/private%2fpublic/data.json", "sub.api.test", true },
  }) do
    request({ uri = c[1], host = c[2] }, function() local selected = api.selected(s); eq(selected, c[3]) end)
  end
end)

test("mismatched versions, overload and socket failures enforce or observe explicitly", function()
  for _, code in ipairs({ "policy-unavailable", "check-overloaded", "check-unavailable" }) do
    for _, mode in ipairs({ "enforce", "observe" }) do
      local cfg = settings(); cfg.jwt.mode = mode; install(cfg)
      api.ask = function() return nil, code end
      local out = request()
      eq(out.status, mode == "enforce" and 503 or 200)
      eq(out.ctx.edgeweir_api_log.issues[1].code, code)
      eq(out.ctx.edgeweir_api_cache_bypass, true)
    end
  end
end)

test("body transfer is base64, limited and only for matched schemas or GraphQL", function()
  local cfg = settings(); cfg.jwt.mode = "off"; cfg.schema.mode = "enforce"; cfg.schema.endpoints = { { method = "POST", path = "/api/{id}" } }; install(cfg)
  local seen
  api.ask = function(req) seen = req; return allowed(req) end
  local out = request({ method = "POST", uri = "/api/1", body = "{\"name\":\"😀\"}", headers = { ["content-type"] = "application/json" } })
  assert(out.read); eq(ngx.decode_base64(seen.body), "{\"name\":\"😀\"}"); eq(seen.body_truncated, false)
  out = request({ method = "POST", uri = "/upload", content_length = "9999999" })
  eq(out.read, nil); eq(seen.body_truncated, false)
  out = request({ method = "POST", uri = "/api/1", content_length = "9999999" })
  eq(out.read, nil); eq(seen.body_truncated, true)
  out = request({ method = "POST", uri = "/api/1", transfer_encoding = "chunked" })
  eq(seen.body_truncated, true)
end)

test("unknown endpoints remain allowed during checker outages when unknown policy allows", function()
  local cfg = settings(); cfg.jwt.mode = "off"; cfg.schema.mode = "enforce"
  cfg.schema.endpoints = { { method = "GET", path = "/api/known" } }
  install(cfg)
  api.ask = function() return nil, "check-overloaded" end
  eq(request({ uri = "/outside" }).status, 200)
  eq(request({ uri = "/api/known" }).status, 503)
  cfg.schema.unknownEndpoints = "block"; install(cfg)
  eq(request({ uri = "/outside" }).status, 503)
end)

test("discovery uses fixed words and empty issue/id arrays stay JSON arrays", function()
  local cfg = settings(); cfg.jwt.mode = "off"; cfg.discovery = { enabled = true, sampleRate = 10000 }; install(cfg)
  api.ask = allowed
  local out = request({ uri = "/api/users/secret-random-token" })
  eq(out.ctx.edgeweir_api_log.template, "/api/users/{segment3}")
  local encoded = assert(json.encode(out.ctx.edgeweir_api_log))
  assert(encoded:find('"issues":[]', 1, true), encoded); assert(encoded:find('"exceptionIds":[]', 1, true), encoded)
  assert(not encoded:find("secret-random-token", 1, true))
end)

test("API metadata forces logs within the shared 100 per site/second cap", function()
  local site = install()
  local runtime = ngx
  site.log_query, site.log_headers = true, { "x-secret" }
  local ctx = { edgeweir_site = site, edgeweir_original_args = "token=discovery-private-value", edgeweir_log_headers = { ["x-secret"] = "discovery-private-value" }, edgeweir_api_force_log = true, edgeweir_api_log = { template = "/api/{segment2}", source = "traffic", issues = json.empty_array, exceptionIds = json.empty_array } }
  local fake = setmetatable({ ctx = ctx, var = { request_id = "id", host = "api.test", uri = "/api/id", scheme = "http", request_method = "GET" },
    status = 200, is_subrequest = false, now = function() return 1800000000 end }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(function() for _ = 1, 150 do accesslogs.log(nil, false, site.id) end end)
  _G.ngx = runtime
  assert(ok, err)
  local logs = accesslogs.drain(); eq(#logs, accesslogs.MAX_FORCED)
  local encoded = assert(json.encode(logs))
  assert(encoded:find('"issues":%[%]') and encoded:find('"exceptionIds":%[%]'), "drained metadata must preserve empty arrays")
  eq(logs[1].path, "/api/{segment2}")
  assert(not encoded:find("discovery-private-value", 1, true), "API records must not retain request values")
  eq(logs[1].api_security.template, "/api/{segment2}")
  eq(reasons.REASONS.api_security, true)
end)

test("GraphQL prefix templates select entire segment paths", function()
  local cfg = settings(); cfg.jwt.mode = "off"; cfg.graphql = { mode = "enforce", pathPrefixes = { "/api/{tenant}/graphql" } }
  local s = install(cfg)
  request({ uri = "/api/customer/graphql" }, function() local _, selected = api.selected(s); eq(selected, true) end)
  request({ uri = "/api/graphql" }, function() local _, selected = api.selected(s); eq(selected, false) end)
end)

print(string.format("API security: %d passed, %d failed", passed, failed))
if failed > 0 then os.exit(1) end
