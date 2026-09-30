-- Lua unit tests for edgeweir.cc with an injected clock (see `make lua-test`):
--
--   resty -I lua --shdict 'edgeweir_cc 8m' --shdict 'edgeweir_bans 4m' test/lua/cc.lua
local cjson = require("cjson.safe")
local cc = require("edgeweir.cc")
local bans = require("edgeweir.bans")

local dict = ngx.shared.edgeweir_cc
local passed, failed = 0, 0
local T = 1790000000
local table_sites = cc.sites

local function reset()
  dict:flush_all()
  dict:flush_expired()
  ngx.shared.edgeweir_bans:flush_all()
  ngx.shared.edgeweir_bans:flush_expired()
  bans.forget()
  cc.forget()
  cc.sites = table_sites
  T = 1790000000
  cc.clock = function() return T end
  bans.clock = function() return T end
end

local function test(name, fn)
  reset()
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

local function site(policy)
  local s = { id = "site-a", protection = { cc = policy } }
  cc.prepare(s)
  return s
end

-- second sends n requests spread over one second, then flushes and
-- evaluates like the timer does.
local function second(s, n, path, addr)
  for i = 1, n do
    T = T + 1 / (n + 1)
    cc.count(s, addr or ("192.0.2." .. (i % 200 + 1)), path or "/")
  end
  T = math.floor(T) + 1
  cc.flush(T)
  cc.evaluate_site(s, T)
end

local function level(s, path)
  return cc.level(s, path or "/")
end

local function events(kind)
  local out = {}
  for _, e in ipairs(cjson.decode(cc.drain(1000))) do
    if not kind or e.kind == kind then out[#out + 1] = e end
  end
  return out
end

test("step: escalation after N seconds, up to the maximum", function()
  local s = { level = 0, hold = 0, calm = 0 }
  eq(cc.step(s, 2, 100, 10, 60, 2), nil, "first second over the threshold")
  eq(cc.step(s, 2, 109, 10, 60, 2), nil, "9 seconds")
  eq(cc.step(s, 2, 110, 10, 60, 2), 0, "10 seconds: one step")
  eq(s.level, 1)
  eq(cc.step(s, 2, 115, 10, 60, 2), nil)
  eq(cc.step(s, 2, 120, 10, 60, 2), 1, "another 10 seconds")
  eq(s.level, 2)
  eq(cc.step(s, 2, 200, 10, 60, 2), nil, "maximum level")
  eq(s.level, 2)
end)

test("step: hysteresis between 80 % and the threshold, cooldown steps down", function()
  local s = { level = 2, hold = 0, calm = 0 }
  eq(cc.step(s, 0.9, 100, 10, 60, 4), nil)
  eq(cc.step(s, 0.9, 500, 10, 60, 4), nil, "80-100 %: the level holds")
  eq(s.level, 2)
  eq(cc.step(s, 0.5, 501, 10, 60, 4), nil, "below 80 %: cooldown starts")
  eq(cc.step(s, 0.85, 540, 10, 60, 4), nil, "back into the band: cooldown restarts")
  eq(cc.step(s, 0.5, 541, 10, 60, 4), nil)
  eq(cc.step(s, 0.5, 600, 10, 60, 4), nil, "59 seconds")
  eq(cc.step(s, 0.5, 601, 10, 60, 4), 2, "60 seconds: one step down")
  eq(s.level, 1)
  eq(cc.step(s, 0.5, 661, 10, 60, 4), 1)
  eq(s.level, 0)
  eq(cc.step(s, 0, 9999, 10, 60, 4), nil, "normal stays normal")
  -- An escalation in progress stops in the band.
  s = { level = 0, hold = 0, calm = 0 }
  cc.step(s, 1.5, 100, 10, 60, 4)
  cc.step(s, 0.95, 105, 10, 60, 4)
  eq(cc.step(s, 1.5, 110, 10, 60, 4), nil, "the band reset the timer")
  eq(cc.step(s, 1.5, 120, 10, 60, 4), 0)
  -- A lowered maximum takes effect at once.
  s = { level = 4, hold = 0, calm = 0 }
  eq(cc.step(s, 5, 100, 10, 60, 2), 4)
  eq(s.level, 2)
end)

test("site QPS escalates the site level and the cooldown lowers it", function()
  local s = site({ window = 5, site_qps = 10, escalate = 3, cooldown = 5, max_level = "js" })
  for _ = 1, 6 do second(s, 5) end
  eq(level(s), 0, "below the threshold")
  local changes = {}
  for i = 1, 20 do
    second(s, 40)
    changes[i] = level(s)
  end
  -- The sliding window reaches 10 rps within a couple of seconds, then
  -- every 3 seconds the level rises, up to js (2).
  eq(changes[20], 2, "maximum level js")
  local first = nil
  for i, l in ipairs(changes) do
    if l == 1 and not first then first = i end
  end
  assert(first and first >= 3 and first <= 6, "first step after about 3 seconds: " .. tostring(first))
  local up = events("site_level")
  eq(#up, 2, "two site level events")
  eq(up[1].previous_level, "normal")
  eq(up[1].level, "cookie302")
  eq(up[2].level, "js")
  eq(up[1].metric, "site_qps")
  eq(up[1].threshold, 10)
  assert(up[1].observed > 10, "observed rate")
  assert(#up[1].top_ips > 0 and #up[1].top_ips <= 10, "top addresses")
  assert(up[1].id ~= up[2].id and up[1].id:match("^[0-9a-f]+%-%d+$"), "unique ids: " .. up[1].id)
  -- Quiet: the window drains, then one step per cooldown.
  local times = {}
  for i = 1, 30 do
    second(s, 0)
    if level(s) < (times.last or 2) then times[#times + 1] = i end
    times.last = level(s)
  end
  eq(level(s), 0, "back to normal")
  eq(#times, 2)
  assert(times[2] - times[1] == 5, "cooldown of 5 seconds between steps: " .. times[1] .. ", " .. times[2])
  local down = events("site_level")
  eq(#down, 2)
  eq(down[1].metric, "cooldown")
  eq(down[2].level, "normal")
end)

test("an attacked path escalates alone", function()
  local s = site({ window = 5, url_qps = 20, escalate = 2, cooldown = 10, max_level = "captcha" })
  for _ = 1, 12 do
    for i = 1, 60 do
      T = T + 1 / 70
      cc.count(s, "192.0.2." .. i, "/login")
      if i % 20 == 0 then cc.count(s, "192.0.2.1", "/home") end
    end
    T = math.floor(T) + 1
    cc.flush(T)
    cc.evaluate_site(s, T)
  end
  assert(level(s, "/login") >= 2, "attacked path escalated: " .. level(s, "/login"))
  eq(level(s, "/home"), 0, "other paths stay normal")
  eq(level(s, "/"), 0)
  local st = dict:get("st|site-a")
  assert(st:match("^0|"), "site level normal: " .. st)
  local e = events("path_level")
  assert(#e >= 2, "path level events")
  eq(e[1].path, "/login")
  eq(e[1].metric, "url_qps")
  eq(e[1].top_paths[1].value, "/login")
  eq(#events("site_level"), 0, "no site event")
end)

test("turning CC off clears the site's state, thresholds changes keep it", function()
  local policy = { window = 5, site_qps = 50, url_qps = 20, escalate = 1, cooldown = 300, max_level = "captcha" }
  local s = site(policy)
  local other = { id = "site-b", protection = { cc = { window = 5, site_qps = 1000 } } }
  cc.prepare(other)
  local on = { s, other }
  cc.sites = function() return on end
  local function attack(seconds)
    for _ = 1, seconds do
      for i = 1, 60 do
        T = T + 1 / 70
        cc.count(s, "192.0.2." .. i, "/login")
      end
      T = math.floor(T) + 1
      cc.flush(T)
      cc.evaluate(T)
    end
  end
  local function escalated()
    for _, e in ipairs(cc.status().sites) do
      if e.site_id == "site-a" then return e.level, e.escalated_paths end
    end
  end
  attack(8)
  local site_level, path_level = level(s, "/"), level(s, "/login")
  assert(site_level >= 1 and path_level >= 1, "site and path escalated: " .. site_level .. ", " .. path_level)
  local name, paths = escalated()
  eq(name, cc.NAMES[site_level])
  eq(paths, 1, "escalated paths")
  -- Other thresholds: the state stays.
  policy.site_qps, policy.url_qps = 100, 100
  s = site(policy)
  on = { s, other }
  T = T + 1
  cc.evaluate(T)
  eq(level(s, "/"), site_level, "site level after a threshold change")
  eq(level(s, "/login"), path_level, "path level after a threshold change")
  -- No site table (before the first push): nothing is cleared.
  cc.sites = function() return nil end
  T = T + 1
  cc.evaluate(T)
  assert(dict:get("st|site-a"), "state kept without a site table")
  cc.sites = function() return on end
  -- Off: the next evaluation drops the site's state, not the other site's.
  on = { other }
  T = T + 1
  cc.evaluate(T)
  for _, k in ipairs({ "st|", "pc|", "xm|", "lv|", "ta|", "ps|", "is|" }) do
    eq(dict:get(k .. "site-a"), nil, k .. "site-a")
  end
  eq(dict:get("#sites"), "site-b")
  assert(dict:get("st|site-b"), "the other site keeps its state")
  eq(escalated(), nil, "not listed without CC")
  -- On again with other thresholds: normal, no escalated path.
  policy.url_qps = 30
  s = site(policy)
  on = { s, other }
  T = T + 1
  cc.evaluate(T)
  eq(level(s, "/"), 0, "site level after off and on")
  eq(level(s, "/login"), 0, "path level after off and on")
  name, paths = escalated()
  eq(name, "normal")
  eq(paths, 0)
  -- An attack escalates the path again under a new version.
  local version = dict:get("xv|site-a")
  attack(3)
  assert(level(s, "/login") >= 1, "path escalated again")
  assert(dict:get("xv|site-a") > version, "the path map version keeps rising")
end)

test("origin error rate needs the minimum requests", function()
  local s = site({ window = 5, error_percent = 50, error_min_requests = 30, escalate = 1, cooldown = 60 })
  local function origin(n, errors)
    for i = 1, n do
      _G.ngx = setmetatable({ var = { upstream_status = i <= errors and "502" or "200" } }, { __index = ngx })
      local ok, err = pcall(cc.log, s)
      _G.ngx = getmetatable(_G.ngx).__index
      assert(ok, err)
    end
  end
  for _ = 1, 3 do
    origin(4, 4) -- 100 % errors but only a few requests
    T = T + 1
    cc.evaluate_site(s, T)
  end
  eq(level(s), 0, "too few origin requests")
  for _ = 1, 3 do
    origin(20, 15)
    T = T + 1
    cc.evaluate_site(s, T)
  end
  assert(level(s) >= 1, "error rate over 50 %")
  local e = events("site_level")
  eq(e[1].metric, "origin_error_rate")
  eq(e[1].threshold, 50)
end)

test("an address over its rate is banned once", function()
  local s = site({ window = 5, ip_qps = 5, ip_ban = 120 })
  local denied, first = 0, nil
  for i = 1, 40 do
    T = T + 0.01
    local n, w, now = cc.count(s, "198.51.100.23", "/")
    if cc.check_ip(s, "198.51.100.23", n, w, now) then
      denied = denied + 1
      first = first or i
    end
  end
  eq(first, 26, "denied past 25 requests in 5 seconds")
  eq(denied, 15)
  local kind = bans.match("site-a", "198.51.100.23")
  eq(kind, "a", "own ban in the ban store")
  local reported = bans.drain(10)
  eq(#reported, 1, "one automatic ban")
  eq(reported[1].reason, "cc_ip_rate")
  eq(reported[1].metric, "ip_qps")
  eq(reported[1].expires_at - reported[1].created_at, 120)
  local e = events("ip_banned")
  eq(#e, 1, "one event")
  eq(e[1].address, "198.51.100.23")
  eq(e[1].threshold, 5)
  -- Another address is not affected.
  local n, w, now = cc.count(s, "198.51.100.24", "/")
  assert(not cc.check_ip(s, "198.51.100.24", n, w, now))
end)

test("the previous window counts for addresses past half their limit", function()
  local s = site({ window = 10, ip_qps = 2 })
  -- 19 requests at the end of one window, then 11 at the start of the next.
  T = 1790000009.5
  for _ = 1, 19 do
    local n, w, now = cc.count(s, "198.51.100.30", "/")
    assert(not cc.check_ip(s, "198.51.100.30", n, w, now))
  end
  T = 1790000010.5
  local over = false
  for _ = 1, 11 do
    local n, w, now = cc.count(s, "198.51.100.30", "/")
    over = over or cc.check_ip(s, "198.51.100.30", n, w, now)
  end
  assert(over, "19 * 0.95 + 11 > 20")
end)

test("Space-Saving summaries stay bounded and keep heavy hitters", function()
  local sum = { counts = {}, n = 0 }
  for i = 1, 5000 do
    cc.observe(sum, "/random/" .. i, 64)
    if i % 3 == 0 then cc.observe(sum, "/hot", 64) end
  end
  eq(sum.n, 64)
  local size = 0
  for _ in pairs(sum.counts) do size = size + 1 end
  eq(size, 64)
  assert(sum.counts["/hot"] and sum.counts["/hot"] >= 1666, "heavy hitter kept: " .. tostring(sum.counts["/hot"]))
end)

test("paths per site are bounded to 64", function()
  local s = site({ window = 5, url_qps = 1000, escalate = 1, cooldown = 60 })
  for sec = 1, 5 do
    for i = 1, 300 do
      T = T + 1 / 400
      cc.count(s, "192.0.2.1", "/p/" .. sec .. "/" .. i)
    end
    T = math.floor(T) + 1
    cc.flush(T)
    cc.evaluate_site(s, T)
  end
  local lines = 0
  for _ in (dict:get("pc|site-a") or ""):gmatch("[^\n]+") do lines = lines + 1 end
  assert(lines <= 64, "tracked paths: " .. lines)
end)

test("events are bounded and drained in order", function()
  cc.EVENTS_MAX = 5
  for i = 1, 8 do cc.push({ kind = "site_level", site_id = "site-a", level = "js", previous_level = "normal", n = i }) end
  cc.EVENTS_MAX = 10000
  local raw = cc.drain(1000)
  local e = cjson.decode(raw)
  eq(#e, 5)
  eq(e[1].n, 4, "oldest dropped")
  eq(dict:get("#evdrop"), 3)
  assert(raw:find('"top_ips":[]', 1, true), "empty lists stay arrays: " .. raw)
  eq(cc.drain(1000), "[]")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
