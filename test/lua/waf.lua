-- OWASP CRS in the edge layer (edgeweir.waf): the CRS location of a site,
-- the settings header, the request context across the internal redirect,
-- matched rule ids and their per-minute Top-K in the statistics and the
-- sampled access logs. Run with `make lua-test` (shared dicts
-- edgeweir_stats, edgeweir_topstats and edgeweir_logs).
local cjson = require("cjson.safe")
local waf = require("edgeweir.waf")
local stats = require("edgeweir.stats")

local passed = 0
local function eq(got, want, msg)
  if got ~= want then
    error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2)
  end
end
local function test(name, fn)
  fn()
  passed = passed + 1
  print("ok   " .. name)
end

test("location follows the body limits of the loaded nginx.conf", function()
  waf.init({ 0, 131072, 1048576 })
  eq(waf.location({ request_body_limit = 131072 }), "@edgeweir_waf_131072")
  eq(waf.location({ request_body_limit = 0 }), "@edgeweir_waf_0")
  eq(waf.location({ request_body_limit = 4096 }), "@edgeweir_waf_1048576",
    "a limit nginx.conf does not have yet: still inspected, with the largest limit")
  waf.init({})
  eq(waf.location({ request_body_limit = 131072 }), nil, "no CRS location: not inspected")
  waf.init({ "65536", -1, 1.5, "x" })
  eq(waf.location({ request_body_limit = 65536 }), "@edgeweir_waf_65536")
  eq(waf.location({ request_body_limit = 1 }), "@edgeweir_waf_65536", "invalid limits are ignored")
  waf.init(nil)
  eq(waf.location({ request_body_limit = 0 }), nil)
end)

test("header_value carries site, mode, paranoia level and threshold", function()
  eq(waf.header_value("site-a", { mode = "detect", paranoia_level = 2, anomaly_threshold = 10 }), "site-a;detect;2;10")
  eq(waf.header_value("s_1", { mode = "block", paranoia_level = 4, anomaly_threshold = 1000 }), "s_1;block;4;1000")
end)

test("request contexts survive the internal redirect once", function()
  local before = waf.stashed_count()
  local ctx = { edgeweir_site = { id = "site-a" } }
  local ref = waf.stash_ctx(ctx, 1000)
  eq(waf.stashed_count(), before + 1)
  eq(waf.take_ctx(ref), ctx)
  eq(waf.take_ctx(ref), nil, "taken once")
  eq(waf.stashed_count(), before)
  eq(waf.take_ctx("no-such-ref"), nil)
end)

test("stale contexts of aborted requests are swept", function()
  for i = 1, 10001 do waf.stash_ctx({ i = i }, 1000) end
  eq(waf.stashed_count(), 10001)
  local ref = waf.stash_ctx({}, 2000) -- beyond 10000 entries: sweep entries older than 5 minutes
  eq(waf.stashed_count(), 1)
  waf.take_ctx(ref)
  eq(waf.stashed_count(), 0)
end)

test("rule_ids parses $modsecurity_triggered_rules", function()
  local ids = waf.rule_ids("920350,941100,941100,949110")
  eq(#ids, 3, "duplicates count once")
  eq(ids[1], 920350); eq(ids[2], 941100); eq(ids[3], 949110)
  eq(#waf.rule_ids(""), 0)
  eq(#waf.rule_ids(nil), 0)
  local many = {}
  for i = 1, 40 do many[#many + 1] = tostring(900000 + i) end
  eq(#waf.rule_ids(table.concat(many, ",")), 16, "at most 16 per request")
  eq(#waf.rule_ids(table.concat(many, ","), 5), 5)
  eq(#waf.rule_ids("0,99999999999"), 0, "ids outside uint32 are dropped")
end)

-- log a request of site "crs" through stats.log in a CRS location, with a
-- fake ngx that reads the ModSecurity variables.
local function log_request(triggered, intervention, sample)
  local runtime = ngx
  local var = {
    edgeweir_site = "crs", edgeweir_ctx_ref = "", uri = "/", remote_addr = "192.0.2.10",
    bytes_sent = "100", request_length = "50", upstream_cache_status = "HIT",
    modsecurity_triggered_rules = triggered, modsecurity_intervention = intervention,
    request_id = "0123456789abcdef", request_method = "GET", host = "crs.test", request_time = "0.001",
  }
  local fake = setmetatable({
    var = var,
    ctx = { edgeweir_waf = true, edgeweir_site = { id = "crs", log_sample_rate = sample or 0 } },
    status = intervention == "1" and 403 or 200,
    is_subrequest = false,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(stats.log, true)
  _G.ngx = runtime
  assert(ok, err)
end

test("matched CRS rules are counted per site and minute, heaviest first", function()
  ngx.shared.edgeweir_stats:flush_all()
  for i = 1, 30 do
    log_request("920350," .. tostring(941000 + i) .. (i % 2 == 0 and ",949110" or ""), "0")
  end
  log_request("942100,949110", "1")
  local now = ngx.time() + 60
  local buckets = stats.drain(now)
  local bucket
  for _, b in ipairs(buckets) do if b.site_id == "crs" then bucket = b end end
  assert(bucket, "no bucket for the CRS site")
  eq(bucket.requests, 31)
  eq(bucket.waf_rules["920350"], 30)
  eq(bucket.waf_rules["949110"], 16)
  local n = 0
  for _ in pairs(bucket.waf_rules) do n = n + 1 end
  eq(n, stats.MAX_WAF_RULES, "bounded Top-K")
  eq(bucket.waf_rules["941001"], 1)
  eq(bucket.waf_rules["941030"], nil, "ties keep the lowest ids, the rest is dropped")
  eq(bucket.waf_rules["942100"], nil)
  local encoded = cjson.decode(cjson.encode(bucket))
  eq(encoded.waf_rules["920350"], 30)
end)

test("requests without CRS matches add no rule counters", function()
  ngx.shared.edgeweir_stats:flush_all()
  log_request(nil, "0")
  local found = false
  for _, b in ipairs(stats.drain(ngx.time() + 60)) do
    if b.site_id == "crs" and b.requests == 1 then
      found = true
      eq(b.waf_rules, nil)
    end
  end
  assert(found, "no bucket for the request")
end)

test("sampled access logs carry the matched rules and the block", function()
  local logs = ngx.shared.edgeweir_logs
  logs:flush_all()
  log_request("941100,949110", "1", 10000)
  log_request(nil, "0", 10000)
  local entries = require("edgeweir.accesslogs").drain()
  eq(#entries, 2)
  eq(#entries[1].waf_rule_ids, 2)
  eq(entries[1].waf_rule_ids[1], 941100)
  eq(entries[1].waf_blocked, true)
  eq(entries[2].waf_rule_ids, nil)
  eq(entries[2].waf_blocked, nil)
end)

-- waf-v2 (proto v0.29.0): exclusion entries by path, the config rules'
-- CRS mode and skip actions.
test("exclusion entries match the normalized path exactly, as a byte prefix or always", function()
  local w = { mode = "block", exclusions = {
    { path = "/api/", token = "aaaaaaaaaaaaaaaa" },
    { path = "/login", exact = true, token = "bbbbbbbbbbbbbbbb" },
    { path = "", token = "cccccccccccccccc" },
    { path = "/bad", token = "not hex," },
  } }
  eq(waf.exclusion_value(w, "/api/x"), ",aaaaaaaaaaaaaaaa,cccccccccccccccc,")
  eq(waf.exclusion_value(w, "/api"), ",cccccccccccccccc,", "a prefix of the path, not of the entry")
  eq(waf.exclusion_value(w, "/login"), ",bbbbbbbbbbbbbbbb,cccccccccccccccc,")
  eq(waf.exclusion_value(w, "/login/x"), ",cccccccccccccccc,", "exact")
  eq(waf.exclusion_value(w, "/bad"), ",cccccccccccccccc,", "an invalid token is left out")
  eq(waf.exclusion_value({ exclusions = { { path = "/a", token = "dddddddddddddddd" } } }, "/b"), nil)
  eq(waf.exclusion_value({ mode = "block" }, "/a"), nil, "no entries")
  eq(waf.exclusion_value(w, nil), nil)
end)

test("a config rule's CRS mode replaces the site's; off and skip actions keep the request out", function()
  local site = { id = "s", waf = { mode = "block", paranoia_level = 1, anomaly_threshold = 5 } }
  eq(waf.mode(site, nil), "block")
  eq(waf.mode(site, { crs = "detect" }), "detect")
  eq(waf.mode(site, { crs = "off" }), nil)
  eq(waf.mode(site, { skip_crs = true, crs = "block" }), nil)
  eq(waf.header_value("s", site.waf, "detect"), "s;detect;1;5")
end)

test("enter: the settings and exclusion headers, or no CRS location at all", function()
  waf.init({ 0 })
  local runtime = ngx
  local function enter(site, pctx, path)
    local headers, exec = {}, nil
    local fake = setmetatable({
      ctx = { edgeweir_policy = pctx, edgeweir_original_path = path },
      var = { uri = "/rewritten", edgeweir_ctx_ref = "" },
      req = { set_header = function(k, v) headers[k] = v end },
      exec = function(name) exec = name end,
    }, { __index = runtime })
    _G.ngx = fake
    local ok, err = pcall(waf.enter, site)
    _G.ngx = runtime
    assert(ok, err)
    if fake.var.edgeweir_ctx_ref ~= "" then waf.take_ctx(fake.var.edgeweir_ctx_ref) end
    return exec, headers
  end
  local site = { id = "s", waf = { mode = "block", paranoia_level = 2, anomaly_threshold = 7, request_body_limit = 0,
    exclusions = { { path = "/up", token = "0123456789abcdef" } } } }
  local exec, h = enter(site, nil, "/up/load")
  eq(exec, "@edgeweir_waf_0")
  eq(h["X-Edgeweir-Waf"], "s;block;2;7")
  eq(h["X-Edgeweir-Waf-Ex"], ",0123456789abcdef,", "the client's normalized path, not the rewritten one")
  exec, h = enter(site, { crs = "detect" }, "/other")
  eq(h["X-Edgeweir-Waf"], "s;detect;2;7")
  eq(h["X-Edgeweir-Waf-Ex"], nil)
  exec, h = enter(site, { crs = "off" }, "/up")
  eq(exec, nil); eq(h["X-Edgeweir-Waf"], nil)
  exec = enter(site, { skip_crs = true }, "/up")
  eq(exec, nil, "skip crs")
  waf.init({})
end)

-- log a request of site "rules" with the log rules of its policy context.
local function log_forced(rules, sample, id)
  local runtime = ngx
  local fake = setmetatable({
    var = { edgeweir_site = "rules", edgeweir_ctx_ref = "", uri = "/", remote_addr = "192.0.2.10", bytes_sent = "1",
      request_length = "1", request_id = id or "0123456789abcdef", request_method = "POST", host = "r.test", request_time = "0" },
    ctx = { edgeweir_site = { id = "rules", log_sample_rate = sample or 0 }, edgeweir_policy = { log_rules = rules } },
    status = 200, is_subrequest = false,
  }, { __index = runtime })
  _G.ngx = fake
  local ok, err = pcall(stats.log)
  _G.ngx = runtime
  assert(ok, err)
end

test("log rules with access_log write lines whatever the rate, at most 100 per site and second", function()
  local logs = ngx.shared.edgeweir_logs
  logs:flush_all()
  local accesslogs = require("edgeweir.accesslogs")
  log_forced({ "r1", "r2" }, 0)
  log_forced(nil, 0)
  log_forced({ "r1" }, 10000)
  local entries = accesslogs.drain()
  eq(#entries, 2, "no line for a request without the rules at rate 0")
  eq(entries[1].sample_rate, 10000, "written only for the rules")
  eq(cjson.encode(entries[1].rule_ids), '["r1","r2"]')
  eq(entries[2].sample_rate, 10000, "sampled anyway")
  eq(entries[2].rule_ids[1], "r1")
  -- The cap: lines written only for the rules, per site and second.
  logs:flush_all()
  ngx.update_time()
  local second = math.floor(ngx.now())
  for _ = 1, 105 do log_forced({ "r1" }, 0) end
  local n = #accesslogs.drain()
  ngx.update_time()
  if math.floor(ngx.now()) == second then
    eq(n, accesslogs.MAX_FORCED, "capped within one second")
  else
    assert(n >= accesslogs.MAX_FORCED and n <= 105, "capped per second: " .. n)
  end
  -- A sampled line does not count against the cap.
  logs:set("forced|rules|" .. math.floor(ngx.now()), 1000, 2)
  log_forced({ "r9" }, 10000)
  eq(#accesslogs.drain(), 1)
end)

print(("OWASP CRS: %d tests passed"):format(passed))
