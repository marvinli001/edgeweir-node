-- The custom WAF actions, request body and crawler fields of proto v0.29.0
-- (features waf-v2, rules-body-v1, challenge-v2, ADR-0040) through
-- edgeweir.router: ban (site and platform scope, prefixes, once, the
-- exemptions), respond, close, skip (rules, rate limits by scope, the CRS,
-- challenges), access log lines of log rules, rate limit bans, the config
-- rules' CRS mode, bodies read only when evaluated and never for sites whose
-- rules do not read them, and verified crawlers skipping Under Attack.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_policy_logs 1m' --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' \
--     --shdict 'edgeweir_bans 1m' --shdict 'edgeweir_cc 1m' --shdict 'edgeweir_challenge 1m' \
--     --shdict 'edgeweir_purge 1m' --shdict 'edgeweir_tags 1m' --shdict 'edgeweir_bots 1m' \
--     --shdict 'edgeweir_rate_77 256k' test/lua/wafv2.lua
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local router = require("edgeweir.router")
local bans = require("edgeweir.bans")
local bots = require("edgeweir.bots")
local waf = require("edgeweir.waf")
local resolver = require("resty.dns.resolver")

local passed, failed = 0, 0

local function test(name, fn)
  ngx.shared.edgeweir_bans:flush_all()
  ngx.shared.edgeweir_rate_77:flush_all()
  ngx.shared.edgeweir_bots:flush_all()
  bans.forget()
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

-- Expression IR.
local PATH = { op = "field", field = "http.request.uri.path", value_type = "string" }
local function const(v) return { op = "const", value_type = "string", value = v } end
local function path_is(p) return { op = "eq", field = "http.request.uri.path", value_type = "string", value = p } end
local function path_starts(p) return { op = "call", field = "starts_with", value_type = "boolean", children = { PATH, const(p) } } end
local function any(...) return { op = "or", children = { ... } } end
local function all(...) return { op = "and", children = { ... } } end
local POST = { op = "eq", field = "http.request.method", value_type = "string", value = "POST" }
local function call_eq(name, arg, op, value)
  return { op = op, value_type = "string", value = value,
    children = { { op = "call", field = name, value_type = "string", children = { const(arg) } } } }
end
local function rule(id, phase, expression, action) return { id = id, phase = phase, expression = expression, action = action } end

local function site(id, domain, extra)
  local s = { id = id, cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random",
    domains = { { name = domain } }, origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } } }
  for k, v in pairs(extra or {}) do s[k] = v end
  return s
end

local W_RULES = {
  rule("r-crs", "config", path_starts("/crsoff"), { kind = "config", crs = "off" }),
  rule("r-detect", "config", path_starts("/detect"), { kind = "config", crs = "detect" }),
  rule("r-ban", "waf-custom", path_is("/ban"), { kind = "ban", ban_seconds = 600, ban_prefix_v4 = 24 }),
  rule("r-respond", "waf-custom", path_is("/respond"), { kind = "respond", status_code = 200, content_type = "application/json", body = '{"ok":true}' }),
  rule("r-html", "waf-custom", path_is("/html"), { kind = "respond", status_code = 503, content_type = "text/html", body = "<h1>down</h1>" }),
  rule("r-204", "waf-custom", path_is("/nothing"), { kind = "respond", status_code = 204, content_type = "text/plain" }),
  rule("r-page", "waf-custom", path_is("/teapot"), { kind = "respond", status_code = 418, error_page = true }),
  rule("r-close", "waf-custom", path_is("/close"), { kind = "close" }),
  rule("r-skip", "waf-custom", path_starts("/skip/"), { kind = "skip", skip = { "rules" } }),
  rule("r-skip-blocked", "waf-custom", path_starts("/skip/"), { kind = "block", status_code = 403 }),
  rule("r-skipcrs", "waf-custom", path_starts("/skipcrs"), { kind = "skip", skip = { "crs" } }),
  rule("r-skiprl", "waf-custom", path_starts("/rlskip"), { kind = "skip", skip = { "rate_limits" } }),
  rule("r-log", "waf-custom", path_starts("/log"), { kind = "log", access_log = true }),
  rule("r-log2", "waf-custom", path_starts("/log"), { kind = "log", access_log = true }),
  rule("r-form", "waf-custom", all(POST, call_eq("form_value", "user", "eq", "admin")), { kind = "block", status_code = 403 }),
  rule("r-json", "waf-custom", call_eq("json_value", "cmd.0", "contains", "rm"), { kind = "block", status_code = 451 }),
  rule("r-trunc", "waf-custom", all(path_is("/upload"), { op = "eq", field = "http.request.body.truncated", value_type = "boolean", value = "true" }),
    { kind = "block", status_code = 403 }),
  rule("r-bot", "waf-custom", all(path_is("/botonly"), { op = "eq", field = "http.request.bot.name", value_type = "string", value = "googlebot" }),
    { kind = "respond", status_code = 200, content_type = "text/plain", body = "crawler" }),
  rule("r-rl", "ratelimit", any(path_starts("/rl"), path_starts("/pskip")),
    { kind = "rate_limit", status_code = 429, limit = 1, window_seconds = 60, key = "ip.src", ban_seconds = 600 }),
}

local PLATFORM_RULES = {
  rule("p-ban", "waf-custom", path_is("/pban"), { kind = "ban", ban_seconds = 600, ban_scope = "platform", ban_prefix_v6 = 48 }),
  rule("p-skip", "waf-custom", path_starts("/pskip"), { kind = "skip", skip = { "rate_limits" } }),
  rule("p-rl", "ratelimit", any(path_starts("/rlskip"), path_starts("/pskip")),
    { kind = "rate_limit", status_code = 429, limit = 1, window_seconds = 60, key = "ip.src" }),
}

local function install()
  assert(store.replace({ revision = "1", content_hash = "1",
    ip_lists = {
      { id = "platform-allow", kind = "allow", platform = true, entries = { "198.51.100.10/32" } },
      { id = "site-allow", kind = "collection", entries = { "192.0.2.50/32" } },
    },
    platform_rules = PLATFORM_RULES,
    client_address = { trusted_cidrs = { "10.0.0.0/8" } },
    sites = {
      site("w", "w.test", { rules = W_RULES, rules_body_limit = 1024, access_control = { allow_list_ids = { "site-allow" } },
        waf = { mode = "block", paranoia_level = 1, anomaly_threshold = 5, request_body_limit = 0,
          exclusions = { { path = "/api/", token = "0123456789abcdef" } } } }),
      site("plain", "plain.test"),
      site("g", "g.test", { protection = { under_attack = true, under_attack_challenge = "js", pass_ttl = 3600, allow_verified_bots = true },
        rules = { rule("g-open", "waf-custom", path_is("/open"), { kind = "skip", skip = { "challenges" } }) } }),
      site("g2", "g2.test", { protection = { under_attack = true, under_attack_challenge = "js", pass_ttl = 3600 } }),
    } }))
end
install()
waf.init({ 0 })

local function header_table()
  local raw = {}
  return setmetatable({}, {
    __index = function(_, k) return raw[k:lower()] end,
    __newindex = function(_, k, v) raw[k:lower()] = v end,
  }), raw
end

local reads = 0

-- request runs edgeweir.router.access with a stand-in ngx: req = { host,
-- uri, method, addr, headers, body, version, local }. Returns { passed,
-- status, code, header, body, exit, exec, ctx, err }.
local function request(req)
  local runtime = ngx
  local header, raw = header_table()
  local out = { header = raw, body = {} }
  local headers = {}
  for k, v in pairs(req.headers or {}) do headers[k:lower()] = v end
  if req.body then headers["content-length"] = headers["content-length"] or tostring(#req.body) end
  local uri = req.uri or "/"
  local var = {
    scheme = "http", host = req.host or "w.test", uri = uri, request_uri = uri, server_port = "80",
    remote_addr = req.addr or "192.0.2.1", edgeweir_request_id = "req-1", edgeweir_local = req["local"] and "1" or "",
    http_upgrade = headers.upgrade, http_user_agent = headers["user-agent"], http_content_length = headers["content-length"],
    http_content_type = headers["content-type"], http_transfer_encoding = headers["transfer-encoding"], edgeweir_ctx_ref = "",
  }
  local ctx = {}
  local fake = setmetatable({
    var = var, ctx = ctx, header = header, is_subrequest = false,
    req = {
      get_method = function() return req.method or "GET" end,
      get_headers = function() local copy = {}; for k, v in pairs(headers) do copy[k] = v end; return copy end,
      clear_header = function(k) headers[k:lower()] = nil end,
      set_header = function(k, v) headers[k:lower()] = v end,
      start_time = function() return 0 end,
      http_version = function() return req.version or 1.1 end,
      read_body = function() reads = reads + 1 end,
      get_body_data = function() return req.body end,
      get_body_file = function() return nil end,
    },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    exit = function(code) out.exit = code; error("exit", 0) end,
    exec = function(name) out.exec = name end,
    redirect = function(location, status) out.location, out.redirect = location, status; error("exit", 0) end,
    log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(router.access)
  _G.ngx = runtime
  out.passed = ok
  out.err = not ok and err ~= "exit" and err or nil
  out.status = rawget(fake, "status") or out.redirect or out.exit
  out.code = raw["x-edgeweir-error"]
  out.ctx = ctx
  out.body = table.concat(out.body)
  out.headers = headers
  return out
end

local function passes(req, msg)
  local out = request(req)
  assert(out.passed, (msg or "request") .. ": answered " .. tostring(out.status) .. " " .. tostring(out.code) .. " " .. tostring(out.err))
  return out
end

local function answered(req, status, code, msg)
  local out = request(req)
  assert(not out.passed and not out.err, (msg or "request") .. ": passed or failed: " .. tostring(out.err))
  eq(out.status, status, (msg or "request") .. " status")
  eq(out.code, code, (msg or "request") .. " code")
  return out
end

test("ban: 403 ip-banned, the client's /24 banned at site scope once and reported with the rule", function()
  answered({ uri = "/ban", addr = "192.0.2.10" }, 403, "ip-banned")
  answered({ uri = "/", addr = "192.0.2.99" }, 403, "ip-banned", "the rest of the /24")
  passes({ uri = "/", addr = "192.0.3.1" }, "outside the /24")
  passes({ host = "plain.test", uri = "/", addr = "192.0.2.99" }, "another site")
  local list = bans.drain()
  eq(#list, 1)
  eq(list[1].site_id, "w"); eq(list[1].ip, "192.0.2.0"); eq(list[1].prefix_len, 24)
  eq(list[1].rule_id, "r-ban"); eq(list[1].reason, "waf_rule")
  -- A ban already holds the network: nothing written again.
  answered({ uri = "/ban", addr = "192.0.2.50" }, 403, "ip-banned", "site allow list: still 403")
  eq(#bans.drain(), 0)
end)

test("ban: platform scope from a platform rule, the IPv6 /48", function()
  answered({ uri = "/pban", addr = "2001:db8:5:6::1" }, 403, "ip-banned")
  answered({ host = "plain.test", uri = "/", addr = "2001:db8:5:ffff::1" }, 403, "ip-banned", "every site, the /48")
  local list = bans.drain()
  eq(#list, 1); eq(list[1].site_id, "*"); eq(list[1].prefix_len, 48); eq(list[1].rule_id, "p-ban")
end)

test("ban: never written for platform-allowed addresses, trusted proxies, the local listeners, site scope of site-allowed clients", function()
  answered({ uri = "/ban", addr = "198.51.100.10" }, 403, "ip-banned", "platform allow list")
  answered({ uri = "/ban", addr = "10.1.2.3" }, 403, "ip-banned", "trusted proxy")
  answered({ uri = "/ban", addr = "192.0.2.50" }, 403, "ip-banned", "site allow list")
  passes({ uri = "/ban", addr = "203.0.113.5", ["local"] = true }, "local listener: no deny")
  eq(#bans.drain(), 0, "nothing written")
  passes({ uri = "/", addr = "198.51.100.10" })
  passes({ uri = "/", addr = "192.0.2.51" })
  passes({ uri = "/", addr = "203.0.113.5" })
  -- Platform scope applies to the site's allow lists.
  answered({ uri = "/pban", addr = "192.0.2.50" }, 403, "ip-banned")
  eq(#bans.drain(), 1, "platform scope for a site-allowed client")
end)

test("respond: a static body with its type and no-store, 204 and HEAD without a body, the site's error page", function()
  local out = answered({ uri = "/respond" }, 200, nil)
  eq(out.body, '{"ok":true}'); eq(out.header["content-type"], "application/json"); eq(out.header["cache-control"], "no-store")
  eq(out.header["content-length"], 11)
  out = answered({ uri = "/html" }, 503, nil)
  eq(out.body, "<h1>down</h1>"); eq(out.header["content-type"], "text/html; charset=utf-8")
  out = answered({ uri = "/nothing" }, 204, nil)
  eq(out.body, ""); eq(out.header["content-type"], nil)
  out = answered({ uri = "/respond", method = "HEAD" }, 200, nil)
  eq(out.body, "", "HEAD"); eq(out.header["content-length"], 11)
  out = answered({ uri = "/teapot" }, 418, "rule-response")
  eq(out.header["content-type"], "text/html; charset=utf-8")
  assert(out.body:find("418", 1, true), "the built-in page of the status")
  passes({ uri = "/respond", ["local"] = true }, "local listener")
end)

test("close: 444, no response", function()
  local out = request({ uri = "/close" })
  eq(out.exit, 444); eq(out.body, "")
  passes({ uri = "/close", ["local"] = true }, "local listener")
end)

test("skip: rules of the scope, then evaluation goes on; challenges; the CRS", function()
  local out = passes({ uri = "/skip/x" }, "the block after the skip")
  eq(out.exec, "@edgeweir_waf_0", "into the CRS")
  out = passes({ uri = "/skipcrs/x" })
  eq(out.exec, nil, "skip crs: no CRS location")
  out = passes({ uri = "/crsoff/x" })
  eq(out.exec, nil, "config crs off")
  out = passes({ uri = "/detect/x" })
  eq(out.exec, "@edgeweir_waf_0")
  eq(out.headers["x-edgeweir-waf"], "w;detect;1;5", "config crs detect")
  out = passes({ uri = "/api/x" })
  eq(out.headers["x-edgeweir-waf"], "w;block;1;5")
  eq(out.headers["x-edgeweir-waf-ex"], ",0123456789abcdef,", "an exclusion entry by path")
  eq(out.ctx.edgeweir_policy.skip_crs, nil); eq(out.ctx.edgeweir_policy.skip_challenges, nil)
  -- Under Attack: a skip with challenges passes without a pass.
  answered({ host = "g.test", uri = "/other" }, 503, "challenge-unavailable", "challenged (no keys here)")
  passes({ host = "g.test", uri = "/open" }, "skip challenges")
end)

test("skip rate_limits: a platform rule skips every rate limit, a site rule only the site's", function()
  passes({ uri = "/pskip/a", addr = "192.0.2.20" })
  passes({ uri = "/pskip/b", addr = "192.0.2.20" }, "platform skip: no rate limit")
  passes({ uri = "/rlskip/a", addr = "192.0.2.21" })
  answered({ uri = "/rlskip/b", addr = "192.0.2.21" }, 429, "policy-denied", "site skip: the platform's rate limit stays")
  eq(#bans.drain(), 0, "the platform's rate limit bans nobody")
end)

test("rate limit ban: the address over the limit banned at site scope with the count, the limit and the window", function()
  passes({ uri = "/rl/a", addr = "192.0.2.30" })
  local out = answered({ uri = "/rl/b", addr = "192.0.2.30" }, 429, "policy-denied", "over the limit: the rate limit's status")
  eq(out.header["retry-after"], "60")
  answered({ uri = "/", addr = "192.0.2.30" }, 403, "ip-banned", "then banned")
  passes({ uri = "/", addr = "192.0.2.31" }, "only the address")
  local list = bans.drain()
  eq(#list, 1)
  eq(list[1].reason, "rate_limit"); eq(list[1].metric, "rate_limit"); eq(list[1].rule_id, "r-rl")
  eq(list[1].prefix_len, 32); eq(list[1].observed, 2); eq(list[1].threshold, 1); eq(list[1].window_seconds, 60)
  -- Exempt: the rate limit still answers, nobody is banned.
  passes({ uri = "/rl/a", addr = "10.9.9.9" })
  answered({ uri = "/rl/b", addr = "10.9.9.9" }, 429, "policy-denied", "trusted proxy")
  eq(#bans.drain(), 0)
end)

test("log rules ask for an access log line: their ids, at most 8, once each", function()
  local out = passes({ uri = "/log/x" })
  eq(cjson.encode(out.ctx.edgeweir_policy.log_rules), '["r-log","r-log2"]')
  eq(passes({ uri = "/x" }).ctx.edgeweir_policy.log_rules, nil)
end)

test("request body: read only when evaluated, within the limit, never for sites that do not read it", function()
  reads = 0
  passes({ host = "plain.test", uri = "/", method = "POST", body = "user=admin", headers = { ["content-type"] = "application/x-www-form-urlencoded" } })
  passes({ host = "plain.test", uri = "/", method = "POST", body = '{"cmd":["rm"]}', headers = { ["content-type"] = "application/json" } })
  eq(reads, 0, "a site whose rules do not read the body")
  passes({ uri = "/x" })
  eq(reads, 0, "r-json asks for every request's body, but an HTTP/1.1 GET has none to read")
  passes({ uri = "/x", method = "PUT", body = "{}", headers = { ["content-type"] = "application/json" } })
  eq(reads, 1, "r-json reads a body it evaluates")
end)

test("request body: form, JSON and truncated bodies, read once per request", function()
  reads = 0
  answered({ uri = "/f", method = "POST", body = "a=1&user=admin", headers = { ["content-type"] = "application/x-www-form-urlencoded" } },
    403, "policy-denied", "form field")
  eq(reads, 1, "once for two rules")
  passes({ uri = "/f", method = "POST", body = "user=root", headers = { ["content-type"] = "application/x-www-form-urlencoded" } })
  answered({ uri = "/j", method = "POST", body = '{"cmd":["rm -rf /"]}', headers = { ["content-type"] = "application/json" } }, 451, "policy-denied")
  passes({ uri = "/j", method = "POST", body = '{"cmd":["ls"]}', headers = { ["content-type"] = "application/json" } })
  reads = 0
  local big = string.rep("x", 2000)
  answered({ uri = "/upload", method = "POST", body = big, headers = { ["content-type"] = "application/octet-stream" } }, 403, "policy-denied",
    "over the site's limit: truncated")
  eq(reads, 0, "never read")
  answered({ uri = "/upload", method = "POST", headers = { ["transfer-encoding"] = "chunked" } }, 403, "policy-denied", "chunked: truncated")
  answered({ uri = "/upload", version = 2.0 }, 403, "policy-denied", "HTTP/2 without Content-Length: truncated")
  passes({ uri = "/upload" }, "HTTP/1.1 without a body: not truncated")
  -- A rewrite or header rule changes nothing about the lazy fields: the
  -- copy reads the same state.
  eq(reads, 0)
end)

test("verified crawlers skip Under Attack on sites that allow them; bot fields in rules", function()
  local function fake(addr)
    bots.new_resolver = function()
      return {
        reverse_query = function() return { { type = resolver.TYPE_PTR, ptrdname = "crawl.googlebot.com." } } end,
        query = function() return { { type = resolver.TYPE_A, address = addr } } end,
      }
    end
  end
  local real = bots.new_resolver
  local ok, err = pcall(function()
    fake("66.249.66.1")
    passes({ host = "g.test", uri = "/", addr = "66.249.66.1", headers = { ["user-agent"] = "Googlebot/2.1" } }, "verified")
    answered({ host = "g.test", uri = "/", addr = "66.249.66.9", headers = { ["user-agent"] = "Googlebot/2.1" } }, 503, "challenge-unavailable",
      "a claim the forward lookup does not back")
    answered({ host = "g.test", uri = "/", addr = "66.249.66.1", headers = { ["user-agent"] = "Mozilla/5.0" } }, 503, "challenge-unavailable",
      "no claim")
    answered({ host = "g2.test", uri = "/", addr = "66.249.66.1", headers = { ["user-agent"] = "Googlebot/2.1" } }, 503, "challenge-unavailable",
      "a site that does not allow them")
    local out = answered({ uri = "/botonly", addr = "66.249.66.1", headers = { ["user-agent"] = "Googlebot/2.1" } }, 200, nil)
    eq(out.body, "crawler", "http.request.bot.name")
    passes({ uri = "/botonly", addr = "66.249.66.9", headers = { ["user-agent"] = "Googlebot/2.1" } }, "not verified")
  end)
  bots.new_resolver = real
  assert(ok, err)
end)

test("site tables: body and crawler flags from the site's and the platform's rules", function()
  eq(store.site_current("w")._body, true)
  eq(store.site_current("w")._bots, true)
  eq(store.site_current("plain")._body, nil)
  eq(store.site_current("g")._bots, nil)
  local s = store.prepare(site("p", "p.test", { rules = { rule("x", "waf-custom", call_eq("form_value", "a", "eq", "b"), { kind = "log" }) } }))
  eq(s._body, true, "a body function")
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
