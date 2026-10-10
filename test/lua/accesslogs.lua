-- Access logs and statistics of proto v0.30.0 (ADR-0041): block reasons at
-- every refusal (edgeweir.reasons), requests refused before the site was
-- set counted and logged for it, the new and optional log fields, forced
-- lines of sites with log_blocked sharing the budget of log rules, the
-- live view (edgeweir.tap), soft GeoIP lookups, their place and budget
-- (edgeweir.geoip), the user agent classification table (edgeweir.uaclass,
-- test/lua/ua_vectors.json) and the bounded statistics dimensions
-- (edgeweir.topstats, stats.drain), challenges issued and passed. Run with
-- `make lua-test`:
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_policy_logs 1m' --shdict 'edgeweir_stats 4m' --shdict 'edgeweir_topstats 4m' \
--     --shdict 'edgeweir_logs 32m' --shdict 'edgeweir_tap 4m' --shdict 'edgeweir_bans 1m' --shdict 'edgeweir_cc 1m' \
--     --shdict 'edgeweir_challenge 1m' --shdict 'edgeweir_purge 1m' --shdict 'edgeweir_tags 1m' \
--     --shdict 'edgeweir_auth 1m' --shdict 'edgeweir_purge_rate 1m' --shdict 'edgeweir_rate_6c6f67 256k' test/lua/accesslogs.lua
local cjson = require("cjson.safe")
local store = require("edgeweir.store")
local router = require("edgeweir.router")
local stats = require("edgeweir.stats")
local top = require("edgeweir.topstats")
local tap = require("edgeweir.tap")
local accesslogs = require("edgeweir.accesslogs")
local uaclass = require("edgeweir.uaclass")
local geoip = require("edgeweir.geoip")
local origin = require("edgeweir.origin")
local access = require("edgeweir.access")
local bans = require("edgeweir.bans")
local cc = require("edgeweir.cc")
local challenge = require("edgeweir.challenge")
local ratelimit = require("edgeweir.ratelimit")

local passed, failed = 0, 0

local function test(name, fn)
  ngx.shared.edgeweir_bans:flush_all()
  ngx.shared.edgeweir_logs:flush_all()
  ngx.shared.edgeweir_tap:flush_all()
  ngx.shared.edgeweir_stats:flush_all()
  ngx.shared.edgeweir_topstats:flush_all()
  ngx.shared[ratelimit.dict_name("log")]:flush_all()
  bans.forget()
  top.reset()
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

local function size(t)
  local n = 0
  for _ in pairs(t or {}) do n = n + 1 end
  return n
end

-- Expression IR.
local function path_is(p) return { op = "eq", field = "http.request.uri.path", value_type = "string", value = p } end
local function rule(id, phase, expression, action) return { id = id, phase = phase, expression = expression, action = action } end

local function site(id, domain, extra)
  local s = { id = id, cache_zone = "edgeweir_default", cache_generation = "1", load_balance = "weighted_random",
    domains = { { name = domain } }, origins = { { id = "o1", scheme = "http", address = "origin.test", port = 80, weight = 1 } } }
  for k, v in pairs(extra or {}) do s[k] = v end
  return s
end

local KEY = "0123456789abcdef0123456789abcdef"
local LOG_RULES = {
  rule("r-rw", "request-transform", path_is("/rw"), { kind = "rewrite", value = "/other", preserve_query = false }),
  rule("r-block", "waf-custom", path_is("/blocked"), { kind = "block", status_code = 403 }),
  rule("r-ban", "waf-custom", path_is("/ban"), { kind = "ban", ban_seconds = 600 }),
  rule("r-teapot", "waf-custom", path_is("/teapot"), { kind = "respond", status_code = 418, content_type = "text/plain", body = "tea" }),
  rule("r-ok", "waf-custom", path_is("/ok"), { kind = "respond", status_code = 200, content_type = "text/plain", body = "ok" }),
  rule("r-close", "waf-custom", path_is("/close"), { kind = "close" }),
  rule("r-ch", "waf-custom", path_is("/ch"), { kind = "challenge", challenge = "js" }),
  rule("r-log", "waf-custom", path_is("/logged"), { kind = "log", access_log = true }),
  rule("r-rl", "ratelimit", path_is("/rl"), { kind = "rate_limit", status_code = 429, limit = 1, window_seconds = 60, key = "ip.src" }),
}

local function install()
  assert(store.replace({ revision = "1", content_hash = "1",
    ip_lists = {
      { id = "platform-block", kind = "block", platform = true, entries = { "198.51.100.66/32" } },
      { id = "site-block", kind = "collection", entries = { "192.0.2.77/32" } },
    },
    sites = {
      site("log", "log.test", { rules = LOG_RULES, log_blocked = true, log_query = true, log_headers = { "accept-language", "x-trace-id" },
        log_peer = true, websocket = false }),
      site("plain", "plain.test", { log_sample_rate = 10000, rules = { rule("p-block", "waf-custom", path_is("/blocked"), { kind = "block", status_code = 403 }) } }),
      site("maint", "maint.test", { log_blocked = true, log_query = true, maintenance = { retry_after = 60 },
        auth_rules = { { id = "mau", kind = "url_a", secret_version = 1, path_prefixes = { "/secure/" },
          url = { validity_seconds = 1800, skew_seconds = 300, sign_param = "sign", time_param = "t" }, keys = { KEY } } } }),
      site("cert", "cert.test", { log_blocked = true, log_query = true, client_certificate = { mode = "required" } }),
      site("ac", "ac.test", { log_blocked = true, access_control = {
        block_list_ids = { "site-block" },
        hotlink = { allow_empty = true, allowed = { "friend.test" }, extensions = { "png" } },
        user_agents = { rules = { { pattern = "*badbot*" } } },
        cors = { allowed_origins = { "https://app.test" }, allowed_methods = { "GET" } },
        websocket = { origins = { "https://chat.test" } },
      } }),
      site("redir", "redir.test", { access_control = { hotlink = { redirect_url = "/hotlink.png" } } }),
      site("auth", "auth.test", { auth_rules = { { id = "au", kind = "url_a", secret_version = 1, path_prefixes = { "/secure/" },
        url = { validity_seconds = 1800, skew_seconds = 300, sign_param = "sign", time_param = "t" }, keys = { KEY } } } }),
      site("ua", "ua.test", { protection = { under_attack = true, under_attack_challenge = "cookie302", pass_ttl = 600 } }),
      site("js", "js.test", { protection = { under_attack = true, under_attack_challenge = "js", pass_ttl = 600 } }),
      site("cc", "cc.test", { protection = { under_attack_challenge = "js", pass_ttl = 3600, cc = { ip_qps = 1, ip_ban = 60 } } }),
      site("https", "https.test", { tls = { force_https = true } }),
      site("limit", "limit.test", { body_limit = 10 }),
      site("purge", "purge.test", { purge = true }),
    } }))
  assert(challenge.replace_keys({ id = "set-a", current = "a", keys = { { id = "a", secret = ngx.encode_base64(string.rep("a", 32)) } } }))
end
install()

local function header_table()
  local raw = {}
  return setmetatable({}, {
    __index = function(_, k) return raw[k:lower()] end,
    __newindex = function(_, k, v) raw[k:lower()] = v end,
  }), raw
end

local counter = 0

-- request runs edgeweir.router.access with a stand-in ngx: req = { host,
-- uri (with the query), method, addr, peer, headers, scheme, sni, verify,
-- protocol, tls, body_length, post, local }. Returns { passed, status,
-- code, header, body, exit, ctx, var, err }.
local function request(req)
  local runtime = ngx
  counter = counter + 1
  local header, raw = header_table()
  local out = { header = raw, body = {} }
  local headers = {}
  for k, v in pairs(req.headers or {}) do headers[k:lower()] = v end
  if req.body_length then headers["content-length"] = tostring(req.body_length) end
  local uri = req.uri or "/"
  local path, args = uri:match("^([^?]*)%??(.*)$")
  local host = req.host or "log.test"
  local var = {
    scheme = req.scheme or "http", host = host, http_host = host, uri = path, request_uri = uri,
    args = args ~= "" and args or nil, server_port = req.scheme == "https" and "443" or "80",
    remote_addr = req.addr or "192.0.2.1", realip_remote_addr = req.peer or req.addr or "192.0.2.1",
    edgeweir_request_id = "req-" .. counter, request_id = string.format("%032x", counter),
    edgeweir_local = req["local"] and "1" or "", edgeweir_site = "", edgeweir_ctx_ref = "",
    http_upgrade = headers.upgrade, http_user_agent = headers["user-agent"], http_referer = headers.referer,
    http_origin = headers.origin, http_access_control_request_method = headers["access-control-request-method"],
    http_content_length = headers["content-length"], http_content_type = headers["content-type"],
    http_accept_language = headers["accept-language"], request_method = req.method or "GET",
    server_protocol = req.protocol or "HTTP/1.1", ssl_protocol = req.tls, ssl_server_name = req.sni,
    ssl_client_verify = req.verify,
  }
  local ctx = {}
  local fake = setmetatable({
    var = var, ctx = ctx, header = header, is_subrequest = false,
    req = {
      get_method = function() return req.method or "GET" end,
      get_headers = function() local copy = {}; for k, v in pairs(headers) do copy[k] = v end; return copy end,
      clear_header = function(k) headers[k:lower()] = nil end,
      set_header = function(k, v) headers[k:lower()] = v end,
      set_uri = function(p) var.uri = p end,
      set_uri_args = function(a) var.args = a end,
      start_time = function() return 0 end,
      http_version = function() return 1.1 end,
      read_body = function() end,
      get_body_data = function() return nil end,
      get_body_file = function() return nil end,
      get_post_args = function() return req.post or {} end,
    },
    print = function(...) for _, v in ipairs({ ... }) do out.body[#out.body + 1] = tostring(v) end end,
    -- Every answer returns right after ngx.exit and ngx.redirect, also
    -- inside pcall (challenges): they record and return.
    exit = function(code) out.exit = out.exit or code end,
    exec = function(name) out.exec = name end,
    redirect = function(location, status) out.location, out.redirect = location, status end,
    log = function(...) if os.getenv("DEBUG") then print(...) end end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(router.access)
  _G.ngx = runtime
  out.passed = ok and out.exit == nil and out.redirect == nil
  out.err = not ok and err or nil
  out.status = rawget(fake, "status") or out.redirect or out.exit
  if out.passed then out.status = 200 end
  out.code = raw["x-edgeweir-error"]
  out.ctx, out.var, out.headers = ctx, var, headers
  out.body = table.concat(out.body)
  return out
end

-- log runs the edge layer's log phase (edgeweir.stats.log) for a request
-- request() ran; resp sets the response: status, bytes, cache, upstream
-- status / time / addr, content type, waf (a CRS location: rules, blocked).
local function log(out, resp)
  resp = resp or {}
  local runtime = ngx
  local var = out.var
  var.bytes_sent = tostring(resp.bytes or 100)
  var.request_time = "0.012"
  var.request_length = tostring(resp.request_length or 80)
  var.upstream_cache_status = resp.cache
  var.upstream_status = resp.upstream_status
  var.upstream_response_time = resp.upstream_time
  var.upstream_http_x_edgeweir_upstream = resp.upstream_addr
  var.sent_http_content_type = resp.content_type
  if resp.waf then
    out.ctx.edgeweir_waf = true
    var.modsecurity_triggered_rules = resp.waf.rules or ""
    var.modsecurity_intervention = resp.waf.blocked and "1" or "0"
  end
  local fake = setmetatable({
    var = var, ctx = out.ctx, status = resp.status or out.status or 200, is_subrequest = false,
    req = { get_headers = function() return out.headers end },
    log = function() end,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(stats.log, resp.waf ~= nil)
  _G.ngx = runtime
  assert(ok, err)
end

local function reason_of(out)
  return out.ctx.edgeweir_reason, out.ctx.edgeweir_reason_rule
end

-- bucket returns the drained minute bucket of site (completed minutes).
local function bucket(site_id)
  local now = ngx.time() + 60
  top.flush(now)
  for _, b in ipairs(stats.drain(now)) do
    if b.site_id == site_id then return b end
  end
end

-- UA classification table -------------------------------------------------

test("the user agent classification table classifies the vectors and covers every class", function()
  local f = assert(io.open("/t/ua_vectors.json"))
  local v = assert(cjson.decode(f:read("*a")))
  f:close()
  assert(#v.vectors >= 40, "at least 40 vectors")
  local seen = { browser = {}, os = {}, device = {} }
  for _, c in ipairs(v.vectors) do
    local got = uaclass.classify(c.ua)
    eq(got.browser .. "/" .. got.os .. "/" .. got.device, c.browser .. "/" .. c.os .. "/" .. c.device, c.ua)
    seen.browser[c.browser], seen.os[c.os], seen.device[c.device] = true, true, true
  end
  for kind, list in pairs({ browser = uaclass.BROWSERS, os = uaclass.OSES, device = uaclass.DEVICES }) do
    for _, class in ipairs(list) do assert(seen[kind][class], "no vector for " .. kind .. " " .. class) end
  end
  eq(uaclass.classify(nil).browser, "other")
  eq(uaclass.classify({ "curl/8.0", "x" }).browser, "tool", "the first of several lines")
  local ua = v.vectors[1].ua
  eq(uaclass.classify(ua), uaclass.classify(ua), "cached per worker")
  -- Only the first 512 bytes are read.
  eq(uaclass.classify(string.rep("x", 512) .. " curl/8.0").browser, "other")
  eq(uaclass.classify(string.rep("x", 400) .. " curl/8.0").browser, "tool")
end)

-- Helpers of the log fields -----------------------------------------------

test("log field helpers: media type, Referer, UTF-8 cuts, GeoIP fields, upstream values and addresses", function()
  eq(accesslogs.media_type("Text/HTML; charset=utf-8"), "text/html")
  eq(accesslogs.media_type(" application/vnd.api+json "), "application/vnd.api+json")
  eq(accesslogs.media_type("garbage"), "")
  eq(accesslogs.media_type(nil), "")
  eq(accesslogs.media_type("text/" .. string.rep("a", 130)), "", "over 128 bytes")
  eq(accesslogs.referer("https://ref.test/a/b?token=secret#frag"), "https://ref.test/a/b")
  eq(accesslogs.referer("https://ref.test/#x?y"), "https://ref.test/")
  eq(#accesslogs.referer("https://r.test/" .. string.rep("p", 2000)), 1024)
  eq(accesslogs.text("a\tb\1c", 10), "abc", "control characters stripped")
  eq(accesslogs.cut("ab€", 4), "ab", "a cut never splits a UTF-8 sequence")
  eq(accesslogs.cut("ab€", 5), "ab€")
  local c, a, n = accesslogs.geo_fields({ country = "NZ", asnum = 64512, as_name = "Synthetic " .. string.rep("n", 200) })
  eq(c, "NZ"); eq(a, 64512); eq(#n, 128)
  c, a, n = accesslogs.geo_fields({ country = "nz", asnum = 0, as_name = "x" })
  eq(c, ""); eq(a, 0); eq(n, "")
  c, a = accesslogs.geo_fields(nil)
  eq(c, ""); eq(a, 0)
  local addr, status, ms = accesslogs.upstream({ upstream_status = "502, 200", upstream_response_time = "0.010, 0.0204",
    upstream_cache_status = "MISS", upstream_http_x_edgeweir_upstream = "10.0.0.5:8080" })
  eq(addr, "10.0.0.5:8080"); eq(status, 200); eq(ms, 20)
  addr, status, ms = accesslogs.upstream({ upstream_status = "200 : 304", upstream_response_time = "0.001 : 1.5", upstream_cache_status = "REVALIDATED" })
  eq(addr, ""); eq(status, 304); eq(ms, 1500)
  -- After a 304 nginx reads the stored headers again: their address is the
  -- stored object's origin, not this request's.
  addr, status, ms = accesslogs.upstream({ upstream_status = "304", upstream_response_time = "0.020", upstream_cache_status = "REVALIDATED",
    upstream_http_x_edgeweir_upstream = "10.0.0.5:8080" })
  eq(addr, "", "REVALIDATED: no address"); eq(status, 304); eq(ms, 20)
  for _, cs in ipairs({ "MISS", "EXPIRED", "BYPASS" }) do
    addr = accesslogs.upstream({ upstream_status = "200", upstream_response_time = "0.1", upstream_cache_status = cs,
      upstream_http_x_edgeweir_upstream = "10.0.0.5:80" })
    eq(addr, "10.0.0.5:80", cs .. ": this request's origin")
  end
  for _, cs in ipairs({ "HIT", "STALE", "UPDATING" }) do
    addr, status, ms = accesslogs.upstream({ upstream_status = "200", upstream_response_time = "0.1", upstream_cache_status = cs,
      upstream_http_x_edgeweir_upstream = "10.0.0.5:80" })
    eq(addr .. status .. ms, "00", cs .. ": the stored response's")
  end
  addr, status = accesslogs.upstream({ upstream_status = "" })
  eq(status, 0, "the node's own answer")
  eq(origin.last_upstream("192.0.2.1:80, 192.0.2.2:443"), "192.0.2.2:443")
  eq(origin.last_upstream("192.0.2.1:80 : [2001:db8::1]:8443"), "[2001:db8::1]:8443")
  eq(origin.last_upstream("unix:/run/o.sock"), "unix:/run/o.sock")
  eq(origin.last_upstream("edgeweir_balancer"), nil, "a group name")
  eq(origin.last_upstream(""), nil)
end)

-- Block reasons ---------------------------------------------------------------

test("block reasons: rules, rate limits and challenges with their rule; refusals without a reason", function()
  local out = request({ uri = "/blocked" })
  eq(out.status, 403); eq(select(1, reason_of(out)), "rule"); eq(select(2, reason_of(out)), "r-block")
  out = request({ uri = "/teapot" })
  eq(out.status, 418); eq(select(2, reason_of(out)), "r-teapot")
  out = request({ uri = "/ok" })
  eq(out.status, 200); eq(reason_of(out), nil, "a 200 respond is no block")
  out = request({ uri = "/close" })
  eq(out.exit, 444); eq(select(2, reason_of(out)), "r-close")
  out = request({ uri = "/ban", addr = "192.0.2.30" })
  eq(out.code, "ip-banned"); eq(select(1, reason_of(out)), "rule"); eq(select(2, reason_of(out)), "r-ban")
  out = request({ uri = "/", addr = "192.0.2.30" })
  eq(out.code, "ip-banned"); eq(select(1, reason_of(out)), "ip_banned"); eq(select(2, reason_of(out)), nil, "the ban, not the rule")
  request({ uri = "/rl", addr = "192.0.2.31" })
  out = request({ uri = "/rl", addr = "192.0.2.31" })
  eq(out.status, 429); eq(select(1, reason_of(out)), "rate_limit"); eq(select(2, reason_of(out)), "r-rl")
  out = request({ uri = "/ch" })
  eq(out.status, 403); eq(out.header["x-edgeweir-challenge"], "js")
  eq(select(1, reason_of(out)), "challenge"); eq(select(2, reason_of(out)), "r-ch")
  out = request({ uri = "/ch", method = "POST" })
  eq(out.header["x-edgeweir-challenge"], "required"); eq(select(1, reason_of(out)), "challenge")
  out = request({ host = "ua.test" })
  eq(out.status, 302); eq(out.header["x-edgeweir-challenge"], "cookie302")
  eq(select(1, reason_of(out)), "challenge"); eq(select(2, reason_of(out)), nil, "Under Attack: no rule")
  out = request({ host = "js.test" })
  eq(out.status, 403); eq(select(1, reason_of(out)), "challenge")
  out = request({ uri = "/x", headers = { upgrade = "websocket" } })
  eq(out.code, "websocket-disabled"); eq(reason_of(out), nil, "a closed WebSocket is no block")
  out = request({ host = "https.test" })
  eq(out.status, 503); eq(reason_of(out), nil, "Force HTTPS without a certificate is no block")
  out = request({ host = "limit.test", method = "POST", body_length = 100 })
  eq(out.code, "body-too-large"); eq(reason_of(out), nil)
  out = request({ host = "log.test", scheme = "https", sni = "other.test" })
  eq(out.code, "sni-host-mismatch"); eq(reason_of(out), nil)
  out = request({ host = "nowhere.test" })
  eq(out.status, 404); eq(reason_of(out), nil)
end)

test("block reasons: bans, platform lists, client certificates, maintenance, access control, authentication, CC", function()
  local out = request({ addr = "198.51.100.66" })
  eq(out.status, 403); eq(select(1, reason_of(out)), "ip_blocked"); eq(select(2, reason_of(out)), nil)
  out = request({ host = "cert.test", scheme = "https", sni = "cert.test", verify = "NONE" })
  eq(out.code, "client-cert-required"); eq(select(1, reason_of(out)), "client_cert")
  out = request({ host = "maint.test" })
  eq(out.status, 503); eq(select(1, reason_of(out)), "maintenance")
  out = request({ host = "ac.test", addr = "192.0.2.77" })
  eq(out.code, "ip-blocked"); eq(select(1, reason_of(out)), "ip_blocked")
  out = request({ host = "ac.test", uri = "/a.png", headers = { referer = "https://evil.test/" } })
  eq(out.code, "hotlink-denied"); eq(select(1, reason_of(out)), "referer")
  out = request({ host = "redir.test", uri = "/a.png", headers = { referer = "https://evil.test/" } })
  eq(out.status, 302); eq(select(1, reason_of(out)), "referer", "the hotlink redirect")
  out = request({ host = "ac.test", headers = { ["user-agent"] = "BadBot/1" } })
  eq(out.code, "ua-denied"); eq(select(1, reason_of(out)), "user_agent")
  out = request({ host = "ac.test", method = "OPTIONS", headers = { origin = "https://evil.test", ["access-control-request-method"] = "GET" } })
  eq(out.code, "cors-origin-denied"); eq(select(1, reason_of(out)), "cors")
  out = request({ host = "ac.test", method = "OPTIONS", headers = { origin = "https://app.test", ["access-control-request-method"] = "GET" } })
  eq(out.exit, 204); eq(reason_of(out), nil, "an allowed preflight")
  out = request({ host = "ac.test", headers = { upgrade = "websocket", origin = "https://evil.test" } })
  eq(out.code, "websocket-origin-denied"); eq(select(1, reason_of(out)), "websocket_origin")
  -- Geo: the record comes from the rules' values here.
  local s = store.site_current("ac")
  local geo = access.compile_geo({ countries = { "CN" } })
  eq(geo ~= nil, true)
  local saved = s._access.geo
  s._access.geo = geo
  local ok, r = pcall(access.check, s, { ["ip.src"] = "192.0.2.1", ["http.request.uri.path"] = "/", ["ip.geoip.country"] = "CN",
    ["ip.geoip.subdivision"] = "", ["ip.geoip.asnum"] = 0 }, false, false)
  s._access.geo = saved
  assert(ok, r)
  eq(r.code, "geo-denied"); eq(r.reason, "region")
  out = request({ host = "auth.test", uri = "/secure/a" })
  eq(out.code, "auth-denied"); eq(select(1, reason_of(out)), "auth"); eq(select(2, reason_of(out)), "au")
  -- CC: an address over its rate (stand-ins for the counters).
  local count, check_ip = cc.count, cc.check_ip
  cc.count = function() return 1, 1, ngx.now() end
  cc.check_ip = function() return true end
  ok, r = pcall(function()
    local o = request({ host = "cc.test" })
    eq(o.code, "ip-banned"); eq(select(1, reason_of(o)), "cc")
    o = request({ host = "cc.test", uri = "/.edgeweir/x" })
    eq(o.code, "ip-banned"); eq(select(1, reason_of(o)), "cc", "reserved prefix")
  end)
  cc.count, cc.check_ip = count, check_ip
  assert(ok, r)
end)

test("block reasons: the first one wins, unknown reasons are ignored, CRS blocks in the log phase", function()
  local reasons = require("edgeweir.reasons")
  local runtime = ngx
  local ctx = {}
  _G.ngx = setmetatable({ ctx = ctx }, { __index = runtime })
  reasons.set("bogus")
  reasons.set("rule", "r1")
  reasons.set("cc")
  local r, id = reasons.get()
  _G.ngx = runtime
  eq(r, "rule"); eq(id, "r1")
  local out = request({ host = "plain.test", uri = "/x?id=1" })
  assert(out.passed)
  log(out, { status = 403, waf = { rules = "942100,949110", blocked = true } })
  local lines = accesslogs.drain()
  eq(#lines, 1); eq(lines[1].block_reason, "crs"); eq(lines[1].block_rule_id, ""); eq(lines[1].waf_blocked, true)
end)

-- Early refusals --------------------------------------------------------------

test("requests refused before the site was set count and log for it; SNI mismatches, PURGE and unknown hosts do not", function()
  for _, req in ipairs({
    { host = "maint.test" },
    { host = "cert.test", scheme = "https", sni = "cert.test", verify = "NONE" },
  }) do
    local out = request(req)
    eq(out.var.edgeweir_site, "", "refused before $edgeweir_site")
    log(out, { status = out.status })
  end
  request({ uri = "/ban", addr = "192.0.2.40" })
  eq(select(1, reason_of(request({ host = "maint.test", addr = "192.0.2.40" }))), "maintenance", "a site ban stays on its site")
  local out = request({ uri = "/", addr = "192.0.2.40" })
  eq(select(1, reason_of(out)), "ip_banned"); eq(out.var.edgeweir_site, "")
  log(out, { status = 403 })
  local purge = require("edgeweir.purgemethod")
  local handle = purge.handle
  purge.handle = function() ngx.status = 200; return ngx.exit(200) end
  local ok, err = pcall(function()
    log(request({ host = "purge.test", method = "PURGE" }), { status = 200 })
    log(request({ host = "log.test", scheme = "https", sni = "other.test" }), { status = 421 })
    log(request({ host = "nowhere.test" }), { status = 404 })
  end)
  purge.handle = handle
  assert(ok, err)
  local now = ngx.time() + 60
  top.flush(now)
  local by = {}
  for _, b in ipairs(stats.drain(now)) do by[b.site_id] = b end
  eq(by.purge, nil, "PURGE requests are not counted")
  eq(by[""], nil, "requests of no site are not counted")
  local m, c, l = assert(by.maint), assert(by.cert), assert(by.log)
  eq(m.requests, 1); eq(m.status_codes["503"], 1); eq(m.block_reasons.maintenance, 1)
  eq(c.requests, 1); eq(c.status_codes["403"], 1); eq(c.block_reasons.client_cert, 1)
  eq(l.requests, 1, "the banned request, not the SNI mismatch"); eq(l.status_codes["421"], nil); eq(l.block_reasons.ip_banned, 1)
  -- Lines of sites with log_blocked.
  local lines = {}
  for _, line in ipairs(accesslogs.drain()) do lines[line.site_id .. " " .. line.block_reason] = line end
  assert(lines["maint maintenance"], "the maintenance refusal has a line")
  assert(lines["cert client_cert"], "the client certificate refusal has a line")
  assert(lines["log ip_banned"], "the banned request has a line")
  eq(lines["maint maintenance"].sample_rate, 10000)
  eq(lines["log ip_banned"].path, "/")
end)

-- Log fields ------------------------------------------------------------------

test("lines carry the new fields, the site's optional fields, and the client's query and headers", function()
  ngx.shared.edgeweir_logs:set("forced|log|" .. math.floor(ngx.now()), 0, 2)
  local out = request({ uri = "/rw?a=1&b=%01x", scheme = "https", sni = "log.test", protocol = "HTTP/2.0", tls = "TLSv1.3",
    addr = "203.0.113.7", peer = "10.0.0.9", headers = {
      ["user-agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
      referer = "https://ref.test/page?token=secret#frag", ["x-trace-id"] = "trace-1", ["accept-language"] = { "en", "de" },
      cookie = "secret=1",
    } })
  assert(out.passed, out.err)
  eq(out.var.args, "", "the rule rewrote the query")
  out.ctx.edgeweir_policy.log_rules = { "r-log" } -- a line whatever the rate
  out.ctx.edgeweir_geo = { country = "NZ", asnum = 64512, as_name = "Synthetic AS64512" }
  log(out, { status = 200, cache = "MISS", upstream_status = "200", upstream_time = "0.034", upstream_addr = "10.0.0.5:8080",
    content_type = "Text/HTML; charset=utf-8", request_length = 321, bytes = 5000 })
  local lines = accesslogs.drain()
  eq(#lines, 1)
  local l = lines[1]
  eq(l.user_agent, "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
  eq(l.referer, "https://ref.test/page")
  eq(l.http_version, "2"); eq(l.scheme, "https"); eq(l.tls_version, "1.3")
  eq(l.country, "NZ"); eq(l.asn, 64512); eq(l.as_name, "Synthetic AS64512")
  eq(l.upstream_addr, "10.0.0.5:8080"); eq(l.upstream_status, 200); eq(l.upstream_ms, 34)
  eq(l.request_bytes, 321); eq(l.content_type, "text/html")
  eq(l.block_reason, ""); eq(l.block_rule_id, "")
  eq(l.query, "a=1&b=%01x", "the client's query, before the rewrite")
  eq(l.headers["x-trace-id"], "trace-1"); eq(l.headers["accept-language"], "en, de")
  eq(l.headers.cookie, nil, "only the recorded headers")
  eq(l.peer_ip, "10.0.0.9")
  eq(l.path, "/rw", "the original path")
  -- A cache hit: no upstream fields; another site: no optional fields.
  out = request({ host = "plain.test", uri = "/p?x=1", addr = "203.0.113.8", headers = { referer = "http://plain.test/x" } })
  log(out, { status = 200, cache = "HIT", upstream_status = "200", upstream_time = "0.5", upstream_addr = "10.0.0.5:80" })
  l = accesslogs.drain()[1]
  eq(l.upstream_addr, ""); eq(l.upstream_status, 0); eq(l.upstream_ms, 0)
  -- Revalidated: the origin's status and time, no address.
  log(request({ host = "plain.test", uri = "/r" }), { status = 200, cache = "REVALIDATED", upstream_status = "304", upstream_time = "0.007",
    upstream_addr = "10.0.0.6:80" })
  local rv = accesslogs.drain()[1]
  eq(rv.cache_status, "REVALIDATED"); eq(rv.upstream_addr, ""); eq(rv.upstream_status, 304); eq(rv.upstream_ms, 7)
  eq(l.query, nil); eq(l.headers, nil); eq(l.peer_ip, nil)
  eq(l.http_version, "1.1"); eq(l.scheme, "http"); eq(l.tls_version, ""); eq(l.country, ""); eq(l.asn, 0)
  eq(l.sample_rate, 10000)
  -- The peer only when it differs (and never the local listeners' "unix:").
  out = request({ uri = "/logged", addr = "203.0.113.9" })
  out.ctx.edgeweir_policy.log_rules = { "r-log" }
  log(out, { status = 200 })
  l = accesslogs.drain()[1]
  eq(l.peer_ip, nil, "same as the client"); eq(l.headers, nil, "none of the recorded headers"); eq(l.query, "")
end)

test("lines take the query string and headers the access phase took from the client, never the request's current ones", function()
  local sign = "1800000000-r4nd-0123456789abcdef0123456789abcdef"
  -- Refused before the query string is taken (a ban, a client
  -- certificate): a signed URL's signature would still be in it.
  request({ uri = "/ban", addr = "192.0.2.50" })
  local out = request({ uri = "/secure/f?x=1&sign=" .. sign, addr = "192.0.2.50", headers = { ["x-trace-id"] = "t1" } })
  eq(select(1, reason_of(out)), "ip_banned"); eq(out.ctx.edgeweir_original_args, nil)
  log(out, { status = 403 })
  out = request({ host = "cert.test", uri = "/?x=2&sign=" .. sign, scheme = "https", sni = "cert.test", verify = "NONE" })
  eq(out.code, "client-cert-required")
  log(out, { status = 403 })
  -- Maintenance comes after the signature's removal: the rest is logged.
  out = request({ host = "maint.test", uri = "/secure/f?x=3&sign=" .. sign })
  eq(out.status, 503); eq(out.var.args, "x=3")
  log(out, { status = 503 })
  local lines = {}
  for _, l in ipairs(accesslogs.drain()) do lines[l.site_id .. " " .. l.block_reason] = l end
  local ban, cert, maint = assert(lines["log ip_banned"]), assert(lines["cert client_cert"]), assert(lines["maint maintenance"])
  eq(ban.query, nil, "no query string before it was taken"); eq(cert.query, nil)
  eq(maint.query, "x=3", "without the signature")
  eq(ban.headers["x-trace-id"], "t1", "headers are taken once the site is known")
  -- None of the recorded headers sent: none logged, whatever rules or
  -- forward authentication add later.
  out = request({ uri = "/logged", addr = "203.0.113.40" })
  eq(out.ctx.edgeweir_log_headers, false, "taken, none present")
  out.ctx.edgeweir_policy.log_rules = { "r-log" }
  out.headers["x-trace-id"] = "injected"
  log(out, { status = 200 })
  eq(accesslogs.drain()[1].headers, nil, "never the request's current headers")
  -- A context the access phase never filled: no headers, no query string.
  out = request({ uri = "/logged?y=1", addr = "203.0.113.41", headers = { ["x-trace-id"] = "client" } })
  out.ctx.edgeweir_log_headers, out.ctx.edgeweir_original_args = nil, nil
  out.ctx.edgeweir_policy.log_rules = { "r-log" }
  log(out, { status = 200 })
  local l = accesslogs.drain()[1]
  eq(l.headers, nil, "nothing taken, no headers"); eq(l.query, nil)
end)

test("log_blocked: blocked requests get a line whatever the rate, sharing 100 a second with log rules", function()
  local logs = ngx.shared.edgeweir_logs
  local out = request({ uri = "/blocked" })
  log(out, { status = 403 })
  out = request({ uri = "/" })
  assert(out.passed)
  log(out, { status = 200 })
  local lines = accesslogs.drain()
  eq(#lines, 1, "only the blocked request (rate 0)")
  eq(lines[1].block_reason, "rule"); eq(lines[1].block_rule_id, "r-block"); eq(lines[1].sample_rate, 10000); eq(lines[1].status, 403)
  -- The shared budget: 99 used this second, one more blocked line, then none.
  ngx.update_time()
  local second = math.floor(ngx.now())
  logs:set("forced|log|" .. second, accesslogs.MAX_FORCED - 1, 2)
  log(request({ uri = "/blocked" }), { status = 403 })
  log(request({ uri = "/blocked" }), { status = 403 })
  local logged = request({ uri = "/logged" })
  log(logged, { status = 200 })
  ngx.update_time()
  if math.floor(ngx.now()) == second then
    eq(#accesslogs.drain(), 1, "the budget is shared with log rules")
  end
  -- Sites without log_blocked keep the rate (plain samples everything).
  logs:flush_all()
  out = request({ host = "maint.test" })
  eq(out.status, 503)
  out.ctx.edgeweir_site = { id = "maint", log_sample_rate = 0 }
  log(out, { status = 503 })
  eq(#accesslogs.drain(), 0, "no log_blocked: no line")
end)

test("the queue holds 2000 lines with client-sized path, User-Agent and Referer in edgeweir_logs as rendered (32 MiB)", function()
  local logs = ngx.shared.edgeweir_logs
  eq(logs:capacity() >= 32 * 1024 * 1024, true, "run with edgeweir_logs 32m, as internal/render declares it")
  -- plain.test samples every request.
  local out = request({ host = "plain.test", uri = "/" .. string.rep("a", 2047), headers = {
    ["user-agent"] = string.rep("u", 512), referer = "https://r.test/" .. string.rep("r", 1009) } })
  assert(out.passed, out.err)
  for _ = 1, accesslogs.MAX_PENDING do log(out, { status = 200 }) end
  eq(logs:llen("pending"), accesslogs.MAX_PENDING)
  eq(logs:get("dropped"), nil, "every line fits")
  log(out, { status = 200 })
  eq(logs:llen("pending"), accesslogs.MAX_PENDING, "the queue's bound")
  eq(logs:get("dropped"), 1)
  local lines = accesslogs.drain()
  eq(#lines, 1000)
  eq(#lines[1].path, 2048); eq(#lines[1].user_agent, 512); eq(#lines[1].referer, 1024)
  eq(#cjson.encode(lines[1]) > 3800, true, "lines of about 4 KB")
end)

-- The live view ---------------------------------------------------------------

test("the live view records nothing without viewers, per site or every request while watched, by sequence", function()
  local d = ngx.shared.edgeweir_tap
  eq(tap.watching("log"), false)
  log(request({ uri = "/" }), { status = 200 })
  eq(d:get("seq"), nil, "no viewer: nothing numbered")
  local first = tap.read(0, "log")
  eq(first.seq, 1, "numbers start at 1"); eq(#first.entries, 0); eq(first.missed, 0)
  assert(d:ttl("on|log") <= tap.ON_TTL, "the mark expires")
  eq(tap.watching("log"), true); eq(tap.watching("plain"), false); eq(tap.watching(""), false)
  log(request({ uri = "/blocked", headers = { ["user-agent"] = "curl/8" } }), { status = 403 })
  log(request({ host = "plain.test", uri = "/" }), { status = 200 })
  local r = tap.read(first.seq, "log")
  eq(#r.entries, 1); eq(r.missed, 0)
  local e = r.entries[1]
  eq(e.site_id, "log"); eq(e.path, "/blocked"); eq(e.status, 403); eq(e.block_reason, "rule"); eq(e.user_agent, "curl/8")
  eq(e.query, nil, "no optional fields"); eq(e.headers, nil); eq(e.sample_rate, nil)
  eq(#accesslogs.drain(), 2, "the sampled queue keeps its lines (the forced one, plain.test samples all)")
  -- Every request: unknown hosts too (site ""), not the probes' or the local listeners'.
  local all = tap.read(0)
  log(request({ host = "nowhere.test", uri = "/scan" }), { status = 404 })
  local probe = request({ host = "nowhere.test", uri = "/.edgeweir/health" })
  log(probe, { status = 200 })
  log(request({ uri = "/", ["local"] = true }), { status = 200 })
  r = tap.read(all.seq)
  eq(#r.entries, 1); eq(r.entries[1].site_id, ""); eq(r.entries[1].path, "/scan")
  eq(#tap.read(all.seq, "log").entries, 0, "a site's viewer does not see them")
  -- Requests no site counts carry the site that was found, and get no
  -- sampled line (plain.test samples everything).
  local purge = require("edgeweir.purgemethod")
  local handle = purge.handle
  purge.handle = function() ngx.status = 200; return ngx.exit(200) end
  local before = tap.read(0).seq
  local ok, err = pcall(function()
    log(request({ host = "purge.test", method = "PURGE", uri = "/purged" }), { status = 200 })
    log(request({ host = "plain.test", scheme = "https", sni = "other.test", uri = "/sni" }), { status = 421 })
  end)
  purge.handle = handle
  assert(ok, err)
  r = tap.read(before)
  eq(#r.entries, 2); eq(r.entries[1].site_id, "purge"); eq(r.entries[2].site_id, "plain"); eq(r.entries[2].status, 421)
  eq(#tap.read(before, "plain").entries, 1, "the site's viewer sees its uncounted requests")
  ngx.shared.edgeweir_logs:flush_all()
  log(request({ host = "plain.test", scheme = "https", sni = "other.test" }), { status = 421 })
  eq(#accesslogs.drain(), 0, "no sampled line for a request the site does not count")
end)

-- at runs fn with ngx.now() returning t (the live view's clock).
local function at(t, fn)
  local runtime = ngx
  _G.ngx = setmetatable({ now = function() return t end }, { __index = runtime })
  local ok, r = pcall(fn)
  _G.ngx = runtime
  assert(ok, r)
  return r
end

test("the live view counts expired numbers as missed and requests over the rate as dropped, catches up, resets after a restart", function()
  local d = ngx.shared.edgeweir_tap
  ngx.update_time()
  local now = ngx.now()
  local start = tap.read(0).seq
  for i = 1, 3 do log(request({ uri = "/n" .. i }), { status = 200 }) end
  d:delete("e|" .. (start + 2)) -- expired
  -- Read later: no number of the last second, none still being written.
  local r = at(now + 5, function() return tap.read(start) end)
  eq(#r.entries, 2); eq(r.missed, 1); eq(r.seq, start + 3); eq(r.dropped, 0)
  -- Over the rate: no number, counted as dropped (dense numbers).
  ngx.update_time()
  local second = math.floor(ngx.now())
  d:set("rate|" .. second, tap.MAX_PER_SECOND, 2)
  d:set("rate|" .. (second + 1), tap.MAX_PER_SECOND, 3)
  log(request({ uri = "/over" }), { status = 200 })
  local r2 = tap.read(r.seq)
  eq(#r2.entries, 0); eq(r2.missed, 0, "no number taken"); eq(r2.seq, r.seq); eq(r2.dropped, 1)
  eq(d:get("seq"), start + 3, "numbers stay dense")
  -- Far behind: the numbers beyond the window are missed at once.
  d:set("seq", r2.seq + tap.WINDOW + 10)
  local r3 = tap.read(r2.seq)
  eq(r3.missed >= 10, true); eq(r3.seq, r2.seq + 10 + tap.MAX_SCAN)
  -- A viewer ahead of the node (nginx restarted): the current number.
  d:set("seq", 5)
  local r4 = tap.read(1000)
  eq(r4.seq, 5); eq(#r4.entries, 0); eq(r4.missed, 0); eq(r4.dropped, 1)
  -- At most MAX_ENTRIES entries per call.
  d:flush_all()
  for i = 1, tap.MAX_ENTRIES + 5 do tap.record({ site_id = "log", i = i }) end
  eq(#tap.read(0).entries, 0, "a first call")
  local r5 = tap.read(1)
  eq(#r5.entries, tap.MAX_ENTRIES); eq(r5.seq, tap.MAX_ENTRIES + 1); eq(r5.entries[1].i, 1)
  r5 = tap.read(r5.seq, "log")
  eq(#r5.entries, 5, "the rest, for the site's viewer")
end)

test("the live view stops before a number another worker is still storing and shows it next time; older or farther gaps are missed", function()
  local d = ngx.shared.edgeweir_tap
  local t = math.floor(ngx.now()) + 100.5
  -- take stands in for another worker that took a number and has not
  -- stored its entry yet.
  local function take(now)
    return at(now, function() d:incr("rate|" .. math.floor(now), 1, 0, 2); return d:incr("seq", 1) end)
  end
  local function record(now, i) at(now, function() tap.record({ site_id = "log", i = i }) end) end
  local start = at(t, function() return tap.read(0).seq end)
  record(t, 1)
  local taken = take(t)
  record(t, 3)
  local r = at(t + 0.1, function() return tap.read(start) end)
  eq(#r.entries, 1); eq(r.entries[1].i, 1); eq(r.missed, 0); eq(r.seq, taken - 1, "stops before the number being stored")
  d:set("e|" .. taken, cjson.encode({ site_id = "log", i = 2 }), tap.ENTRY_TTL)
  r = at(t + 0.2, function() return tap.read(r.seq) end)
  eq(#r.entries, 2); eq(r.entries[1].i, 2); eq(r.entries[2].i, 3); eq(r.missed, 0); eq(r.seq, taken + 1)
  -- Still missing after about a second: lost, missed.
  local lost = take(t)
  record(t, 5)
  r = at(t + 0.4, function() return tap.read(lost - 1) end)
  eq(r.seq, lost - 1, "young: wait"); eq(#r.entries, 0); eq(r.missed, 0)
  r = at(t + 2.5, function() return tap.read(lost - 1) end)
  eq(#r.entries, 1); eq(r.entries[1].i, 5); eq(r.missed, 1); eq(r.seq, lost + 1)
  -- HEAD_GAP numbers or more behind the head: missed however young.
  local far = take(t + 3)
  for i = 1, tap.HEAD_GAP do record(t + 3, 100 + i) end
  r = at(t + 3.1, function() return tap.read(far - 1) end)
  eq(#r.entries, tap.HEAD_GAP); eq(r.missed, 1); eq(r.seq, far + tap.HEAD_GAP)
  -- The head itself, being stored: the read waits there.
  local head = take(t + 3)
  r = at(t + 3.2, function() return tap.read(head - 1) end)
  eq(r.seq, head - 1); eq(r.missed, 0)
  r = at(t + 5, function() return tap.read(head - 1) end)
  eq(r.seq, head); eq(r.missed, 1, "the head, taken long ago")
end)

test("the control API's live view: GET /v1/logs/tap with a sequence number and an optional site", function()
  local control = require("edgeweir.control")
  local function call(method, args)
    local runtime = ngx
    local out = { body = {} }
    local fake = setmetatable({
      var = { uri = "/v1/logs/tap" }, header = {},
      req = { get_method = function() return method end, get_uri_args = function() return args end },
      print = function(b) out.body[#out.body + 1] = b end,
      exit = function() end,
    }, { __index = runtime })
    _G.ngx = fake
    local ok, err = pcall(control.handle)
    _G.ngx = runtime
    assert(ok, err)
    local raw = table.concat(out.body)
    return rawget(fake, "status"), cjson.decode(raw), raw
  end
  local status, body, raw = call("GET", { after = "0" })
  eq(status, 200); eq(body.seq, 1); eq(body.missed, 0); eq(body.dropped, 0)
  assert(raw:find('"entries":[]', 1, true), "entries as a JSON array: " .. raw)
  eq(tap.watching("any"), true, "every request watched")
  status, body = call("GET", { after = "1", site = "log" })
  eq(status, 200); eq(body.seq, 1)
  eq((call("GET", { after = "-1" })), 400)
  eq((call("GET", {})), 400)
  eq((call("GET", { after = "1", site = "a/b" })), 400)
  eq((call("GET", { after = "1", site = { "a", "b" } })), 400)
  eq((call("POST", { after = "1" })), 405)
end)

-- Soft GeoIP lookups ------------------------------------------------------------

test("soft GeoIP lookups wait 50 ms and back off 5 s after a failure; hard ones wait 200 ms and never back off", function()
  local runtime = ngx
  local connects, timeouts, answer = 0, {}, nil
  local now = 1000
  local function fake_socket()
    local lines = {}
    return {
      settimeout = function(_, ms) timeouts[#timeouts + 1] = ms end,
      connect = function() connects = connects + 1; if not answer then return nil, "refused" end; lines = { "HTTP/1.1 200 OK", "Content-Type: application/json", "", answer }; return 1 end,
      send = function() return 1 end,
      receive = function() return table.remove(lines, 1) end,
      close = function() end,
    }
  end
  local fake = setmetatable({ socket = { tcp = fake_socket }, now = function() return now end }, { __index = runtime })
  geoip.reset()
  local socket = geoip.socket
  geoip.socket = "/nonexistent/geo.sock"
  _G.ngx = fake
  local ok, err = pcall(function()
    eq(geoip.lookup("203.0.113.1", true), nil)
    eq(connects, 1); eq(timeouts[1], 50)
    eq(geoip.lookup("203.0.113.2", true), nil, "backing off")
    eq(connects, 1, "no socket while backing off")
    eq(geoip.lookup("203.0.113.3"), nil, "a hard lookup still asks")
    eq(connects, 2); eq(timeouts[2], 200)
    now = now + 5.1
    answer = '{"country":"NZ","subdivision":"","asnum":64512,"as_name":"Synthetic AS64512"}'
    local rec = geoip.lookup("203.0.113.4", true)
    eq(rec and rec.country, "NZ", "after the backoff")
    eq(connects, 3)
    eq(geoip.lookup("203.0.113.4", true).asnum, 64512)
    eq(connects, 3, "cached")
    eq(geoip.peek("203.0.113.4").as_name, "Synthetic AS64512")
    eq(geoip.peek("203.0.113.5"), nil, "peek never asks")
    eq(connects, 3)
  end)
  _G.ngx = runtime
  geoip.socket = socket
  geoip.reset()
  assert(ok, err)
  -- Without a GeoIP socket nothing is asked and nothing waits.
  eq(geoip.lookup("203.0.113.9", true), nil)
end)

test("the access phase looks GeoIP up softly once the site is known, not on the local listeners or for sites whose rules read it", function()
  local lookup = geoip.lookup
  local calls = {}
  geoip.lookup = function(ip, soft) calls[#calls + 1] = { ip = ip, soft = soft }; return { country = "NZ", asnum = 64512, as_name = "S" } end
  local ok, err = pcall(function()
    local out = request({ uri = "/", addr = "203.0.113.20" })
    eq(#calls, 1); eq(calls[1].soft, true); eq(out.ctx.edgeweir_geo.country, "NZ")
    request({ uri = "/", ["local"] = true })
    eq(#calls, 1, "local listener")
    request({ host = "nowhere.test" })
    eq(#calls, 1, "no site")
    local s = store.site_current("plain")
    s._geo = true
    out = request({ host = "plain.test", uri = "/" })
    s._geo = nil
    eq(out.ctx.edgeweir_geo, nil, "the rules' lookup instead")
  end)
  geoip.lookup = lookup
  assert(ok, err)
end)

test("soft lookups that miss the cache are budgeted at 200 a second per worker, without backoff; cache hits and hard lookups are not", function()
  local runtime = ngx
  local connects, now, refuse = 0, 2000, false
  local function fake_socket()
    local lines = {}
    return {
      settimeout = function() end,
      connect = function()
        connects = connects + 1
        if refuse then return nil, "refused" end
        lines = { "HTTP/1.1 200 OK", "", '{"country":"NZ","subdivision":"","asnum":64512,"as_name":"S"}' }
        return 1
      end,
      send = function() return 1 end,
      receive = function() return table.remove(lines, 1) end,
      close = function() end,
    }
  end
  local fake = setmetatable({ socket = { tcp = fake_socket }, now = function() return now end }, { __index = runtime })
  geoip.reset()
  local socket = geoip.socket
  geoip.socket = "/nonexistent/geo.sock"
  _G.ngx = fake
  local n = 0
  local function addr() n = n + 1; return string.format("198.18.%d.%d", math.floor(n / 256), n % 256) end
  local ok, err = pcall(function()
    eq(geoip.SOFT_BUDGET, 200)
    local first = addr()
    eq(geoip.lookup(first, true).country, "NZ")
    for _ = 2, geoip.SOFT_BUDGET do assert(geoip.lookup(addr(), true), "within the budget") end
    eq(connects, geoip.SOFT_BUDGET)
    eq(geoip.lookup(addr(), true), nil, "over the budget: unknown")
    eq(connects, geoip.SOFT_BUDGET, "no socket over the budget")
    eq(geoip.lookup(first, true).country, "NZ", "a cache hit needs no budget")
    assert(geoip.lookup(addr()), "a hard lookup still asks")
    eq(connects, geoip.SOFT_BUDGET + 1)
    -- No backoff: the bucket refills at 200 a second (3.125 tokens in 1/64 s).
    now = now + 1 / 64
    for _ = 1, 3 do assert(geoip.lookup(addr(), true), "refilled") end
    eq(geoip.lookup(addr(), true), nil, "three tokens in 1/64 s")
    eq(connects, geoip.SOFT_BUDGET + 4)
    -- The bucket holds at most one second's budget.
    now = now + 60
    local asked = connects
    for _ = 1, geoip.SOFT_BUDGET do assert(geoip.lookup(addr(), true), "a full bucket") end
    eq(geoip.lookup(addr(), true), nil, "never more than the budget at once")
    eq(connects - asked, geoip.SOFT_BUDGET)
    -- A failure still backs off, whatever the budget left.
    now = now + 1
    refuse = true
    asked = connects
    eq(geoip.lookup(addr(), true), nil, "refused")
    eq(geoip.lookup(addr(), true), nil, "backing off")
    eq(connects - asked, 1, "no socket while backing off")
  end)
  _G.ngx = runtime
  geoip.socket = socket
  geoip.reset()
  assert(ok, err)
end)

test("the soft lookup comes after the bans, the client certificate and maintenance; requests refused before read the worker's cache", function()
  local lookup, peek = geoip.lookup, geoip.peek
  local calls = 0
  geoip.lookup = function() calls = calls + 1; return { country = "NZ", asnum = 64512, as_name = "S" } end
  geoip.peek = function(ip) if ip == "203.0.113.30" then return { country = "AU", asnum = 64513, as_name = "Cached" } end end
  local ok, err = pcall(function()
    local out = request({ host = "maint.test", addr = "203.0.113.30" })
    eq(out.status, 503); eq(calls, 0, "maintenance"); eq(out.ctx.edgeweir_geo, nil)
    log(out, { status = 503 })
    out = request({ host = "cert.test", scheme = "https", sni = "cert.test", verify = "NONE", addr = "203.0.113.30" })
    eq(out.code, "client-cert-required"); eq(calls, 0, "client certificate")
    log(out, { status = 403 })
    out = request({ uri = "/ban", addr = "203.0.113.31" })
    eq(out.code, "ip-banned"); eq(calls, 1, "a rule's ban comes after the lookup")
    out = request({ uri = "/", addr = "203.0.113.31" })
    eq(select(1, reason_of(out)), "ip_banned"); eq(calls, 1, "a banned address")
    out = request({ uri = "/", addr = "203.0.113.32" })
    assert(out.passed, out.err); eq(calls, 2); eq(out.ctx.edgeweir_geo.country, "NZ")
    local lines = {}
    for _, l in ipairs(accesslogs.drain()) do lines[l.site_id .. " " .. l.block_reason] = l end
    local m, c = assert(lines["maint maintenance"]), assert(lines["cert client_cert"])
    eq(m.country, "AU", "the worker's cache"); eq(m.asn, 64513); eq(c.country, "AU")
  end)
  geoip.lookup, geoip.peek = lookup, peek
  assert(ok, err)
end)

-- Statistics dimensions -----------------------------------------------------------

test("a request's dimensions reach its site's minute: country, network, referring host, classes, versions, reason", function()
  local out = request({ uri = "/blocked", scheme = "https", sni = "log.test", protocol = "HTTP/2.0", tls = "TLSv1.3",
    headers = { ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
      referer = "https://News.Example.org:8443/a?b" } })
  out.ctx.edgeweir_geo = { country = "NZ", asnum = 64512, as_name = "Synthetic AS64512" }
  log(out, { status = 403, bytes = 1234 })
  out = request({ uri = "/", headers = { referer = "http://log.test/self", ["user-agent"] = "curl/8" } })
  out.ctx.edgeweir_geo = false
  log(out, { status = 200, bytes = 10 })
  local b = assert(bucket("log"))
  eq(b.requests, 2)
  eq(b.countries.NZ.requests, 1); eq(b.countries.NZ.bytes_sent, 1234)
  eq(b.countries[""].requests, 1, "unknown"); eq(b.countries[""].bytes_sent, 10)
  eq(b.asns["64512"].requests, 1); eq(b.asns["64512"].name, "Synthetic AS64512")
  eq(b.referers["news.example.org"], 1); eq(size(b.referers), 1, "the site's own host is not a referring host")
  eq(b.browsers.firefox, 1); eq(b.browsers.tool, 1); eq(b.operating_systems.windows, 1); eq(b.operating_systems.other, 1)
  eq(b.devices.desktop, 1); eq(b.devices.other, 1)
  eq(b.http_versions["2"], 1); eq(b.http_versions["1.1"], 1)
  eq(b.tls_versions["1.3"], 1); eq(b.tls_versions.none, 1)
  eq(b.block_reasons.rule, 1); eq(size(b.block_reasons), 1)
  local encoded = assert(cjson.decode(cjson.encode(b)))
  eq(encoded.countries[""].requests, 1, "the unknown country survives JSON")
end)

test("dimension bounds: 250 countries, 64 candidates per worker and 50 reported networks and referring hosts", function()
  local minute = math.floor(ngx.time() / 60) * 60
  local letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  local function dims(country, asn, referer)
    return { country = country, bytes = 10, asn = asn, as_name = asn and ("AS" .. asn) or "", referer = referer,
      browser = "chrome", os = "linux", device = "desktop", http = "1.1", tls = "none" }
  end
  for i = 1, 26 do
    for j = 1, 12 do
      top.log("dims", minute, "/", "192.0.2.1", dims(letters:sub(i, i) .. letters:sub(j, j), nil, nil))
    end
  end
  for _ = 1, 20 do top.log("dims", minute, "/", "192.0.2.1", dims("NZ", "64512", "heavy.test")) end
  for i = 1, 200 do top.log("dims", minute, "/", "192.0.2.1", dims("NZ", tostring(65000 + i), "r" .. i .. ".test")) end
  top.flush(minute + 60)
  local raw = top.drain(minute + 60)
  eq(#raw, 1)
  eq(size(raw[1].asns), top.DIM_CAPACITY, "Space-Saving candidates per worker")
  eq(size(raw[1].referers), top.DIM_CAPACITY)
  assert(size(raw[1].asn_names) <= top.DIM_CAPACITY, "names of evicted networks go")
  -- Merge the summary again with a second worker's.
  local d = ngx.shared.edgeweir_topstats
  d:set(minute .. "|dims|1", cjson.encode(raw[1]))
  d:set(minute .. "|dims|2", cjson.encode({ minute = minute, site_id = "dims", urls = {}, ips = {},
    countries = { NZ = { 5, 50 }, ["zz"] = { 9, 9 } }, asns = { ["64512"] = 3 }, asn_names = { ["64512"] = "Synthetic" },
    browsers = { chrome = 2, netscape = 7 }, oses = { linux = 1 }, devices = { desktop = 1, fridge = 1 },
    http = { ["1.1"] = 1, ["0.9"] = 1 }, tls = { none = 1 }, reasons = { rule = 2, bogus = 1 }, ch_issued = 4, ch_passed = 1 }))
  local b
  for _, x in ipairs(stats.drain(minute + 60)) do if x.site_id == "dims" then b = x end end
  assert(b, "no bucket")
  eq(size(b.countries), stats.MAX_COUNTRIES, "at most 250 countries")
  eq(b.countries.NZ.requests, 225, "the heaviest first, summed across workers")
  eq(b.countries.zz, nil, "invalid countries dropped")
  eq(size(b.asns), stats.MAX_TOP_DIMENSIONS); eq(b.asns["64512"].requests, 23); eq(b.asns["64512"].name, "Synthetic")
  eq(size(b.referers), stats.MAX_TOP_DIMENSIONS); eq(b.referers["heavy.test"], 20)
  eq(b.browsers.chrome, 2 + 312 + 220); eq(b.browsers.netscape, nil, "unknown keys dropped")
  eq(b.devices.fridge, nil); eq(b.http_versions["0.9"], nil); eq(b.block_reasons.bogus, nil); eq(b.block_reasons.rule, 2)
  eq(b.challenges_issued, 4); eq(b.challenges_passed, 1)
  -- Buckets without dimensions report none.
  ngx.shared.edgeweir_stats:incr((minute - 60) .. "|bare|req", 1, 0)
  for _, x in ipairs(stats.drain(minute + 60)) do
    if x.site_id == "bare" then eq(x.countries, nil); eq(x.browsers, nil); eq(x.challenges_issued, nil) end
  end
end)

test("a worker keeps at most 128 site summaries a minute", function()
  local minute = math.floor(ngx.time() / 60) * 60
  for i = 1, top.MAX_BUCKETS + 10 do top.log("s" .. i, minute, "/", "192.0.2.1") end
  local runtime = ngx
  _G.ngx = setmetatable({ var = {} }, { __index = runtime })
  local ok, err = pcall(top.challenge, "late", "issued")
  _G.ngx = runtime
  assert(ok, err)
  top.flush(minute + 60)
  eq(#top.drain(minute + 60), top.MAX_BUCKETS)
end)

test("challenges issued (pages, cookie302) and passed (verified answers), not on the local listeners", function()
  request({ host = "ua.test" })
  local page = request({ host = "js.test" })
  request({ host = "js.test", method = "POST" }) -- 403 required: no page
  request({ host = "js.test", ["local"] = true })
  local token = page.body:match('name="t" value="([^"]+)"')
  assert(token, "no token on the page")
  local ok = request({ host = "js.test", uri = "/.edgeweir/challenge/verify", method = "POST",
    headers = { ["content-length"] = "10" }, post = { t = token, a = challenge.sha256_hex(token), r = "/" } })
  eq(ok.status, 303); assert(ok.header["set-cookie"], "a pass")
  local bad = request({ host = "js.test", uri = "/.edgeweir/challenge/verify", method = "POST", post = { t = "forged", a = "0", r = "/" } })
  eq(bad.status, 303)
  request({ host = "js.test", uri = "/.edgeweir/challenge/verify", method = "POST", ["local"] = true,
    post = { t = token, a = challenge.sha256_hex(token), r = "/" } })
  top.flush(ngx.time() + 60)
  local by = {}
  for _, b in ipairs(stats.drain(ngx.time() + 60)) do by[b.site_id] = b end
  eq(by.ua.challenges_issued, 1)
  eq(by.js.challenges_issued, 1)
  eq(by.js.challenges_passed, 1)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then os.exit(1) end
