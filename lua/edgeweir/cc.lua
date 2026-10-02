-- edgeweir.cc: tiered CC mitigation. Every decision is local to this node.
--
-- Levels: 0 normal, then the challenge levels 1-4 (edgeweir.challenge).
-- A site's policy (site.protection.cc) has a sliding window W and
-- thresholds in requests per second (0: trigger off):
--
--   site_qps       site level
--   error_percent  site level, origin 5xx and failed attempts in percent
--                  of origin requests, once there are error_min_requests
--   url_qps        level of that exact path only (attacked paths)
--   ip_qps         the address is banned for ip_ban seconds
--                  (edgeweir.bans.add_auto, reason cc_ip_rate), once per ban
--
-- An address is a client's IPv4 address or IPv6 /64
-- (edgeweir.ipaddr.client_network: "2001:db8:1:2::/64"): one client that
-- holds a /64 and takes a new address for every request is still one
-- address here, and it cannot fill the store with addresses.
--
-- Counting (lua_shared_dict edgeweir_cc, two adjacent windows weighted as
-- a sliding window: prev * (1 - elapsed/W) + current):
--
--   s|<site>|<w>          requests of the site in window w (access phase)
--   i|<site>|<ip>|<w>     requests of one address or /64 (access phase)
--   o|<site>|<w>, e|...   origin requests and errors (log phase)
--   p|<site>|<w>|<path>   requests of a candidate path (flushed each second)
--
-- Paths and addresses are counted per worker in bounded Space-Saving
-- summaries (64 per site); every second each worker adds its path counts
-- to p|, offers the paths as candidates (ps|<site>) and its heaviest
-- addresses (is|<site>). The hot path of a site with CC costs one incr for
-- the site, one for the address (and one read when it is past half its
-- limit) and one read of the site's level.
--
-- Once per second one worker (the first to take #eval|<second>) evaluates
-- every site with CC: a trigger that holds for escalate seconds raises the
-- level one step (up to max_level); below 80 % of every threshold for
-- cooldown seconds lowers it one step; in between nothing moves. Paths
-- are evaluated the same way, at most 64 per site. State:
--
--   st|<site>   "level|hold|calm|site_qps|error_percent" of the site
--   pc|<site>   tracked paths "path\tlevel\thold\tcalm" (at most 64)
--   xm|<site>   escalated paths "level\tpath"; lv|<site> = version * 8 + level
--               (version 0: no escalated path), read on the hot path
--   ta|<site>   heaviest addresses "count\tip" (decaying, at most 64)
--   #sites      ids of the sites evaluated last, one per line
--   #ev         events for the agent (POST /v1/security/drain), at most
--               10000; #evseq and #boot give unique ids
--
-- State survives reloads and threshold changes. A site that has left the
-- sites with CC (policy turned off, or the site removed) loses it at the
-- next evaluation: turned on again it starts from normal. xv| stays (the
-- version must keep rising for the workers' cached path maps); window
-- counters expire on their own and automatic bans at their own expiry.
local cjson = require("cjson.safe")

local _M = {}

local floor, max, min = math.floor, math.max, math.min
local concat, sort = table.concat, table.sort
local find, sub, format = string.find, string.sub, string.format
local tonumber, tostring, pairs, ipairs = tonumber, tostring, pairs, ipairs

_M.CANDIDATES = 64
_M.TOP = 10
_M.EVENTS_MAX = 10000
_M.STATE_TTL = 3600

_M.NAMES = { [0] = "normal", "cookie302", "js", "pow", "captcha" }
local LEVELS = { cookie302 = 1, js = 2, pow = 3, captcha = 4 }

-- clock returns the current time in seconds (replaced in tests).
_M.clock = function()
  return ngx.now()
end

local function dict()
  return ngx.shared.edgeweir_cc
end

-- prepare derives the site's policy (site._cc) from its protection.
function _M.prepare(site)
  local p = site.protection
  local cc = type(p) == "table" and p.cc
  if type(cc) ~= "table" then
    site._cc = nil
    return
  end
  local function n(v, def)
    v = tonumber(v)
    if not v or v < 0 then return def end
    return v
  end
  site._cc = {
    window = max(n(cc.window, 10), 1),
    site_qps = n(cc.site_qps, 0), url_qps = n(cc.url_qps, 0), ip_qps = n(cc.ip_qps, 0),
    ip_ban = max(n(cc.ip_ban, 600), 1),
    error_percent = n(cc.error_percent, 0), error_min = n(cc.error_min_requests, 0),
    escalate = max(n(cc.escalate, 10), 1), cooldown = max(n(cc.cooldown, 60), 1),
    max = LEVELS[cc.max_level] or 4, high_pow = cc.high_pow == true,
  }
end

-- ---------------------------------------------------------------------
-- Worker-local Space-Saving summaries

local locals = {}

-- observe counts value in a bounded Space-Saving summary s = {counts, n}.
function _M.observe(s, value, capacity)
  local counts = s.counts
  local c = counts[value]
  if c then
    counts[value] = c + 1
    return
  end
  if s.n < capacity then
    counts[value] = 1
    s.n = s.n + 1
    return
  end
  local least, victim
  for k, v in pairs(counts) do
    if not least or v < least then least, victim = v, k end
  end
  counts[victim] = nil
  counts[value] = least + 1
end

local function summary()
  return { counts = {}, n = 0 }
end

local function usable_path(path)
  return path and #path <= 512 and not find(path, "[%c?]")
end

-- count accounts one request of a site with CC (access phase); addr is the
-- client's network (edgeweir.ipaddr.client_network). Returns the
-- address's count in its window, the window and the time when the
-- per-address trigger is on (for check_ip), else nil.
function _M.count(site, addr, path)
  local cc = site._cc
  local now = _M.clock()
  local W = cc.window
  local w = floor(now / W)
  local d = dict()
  local id = site.id
  local ttl = 2 * W + 2
  if cc.site_qps > 0 then
    d:incr("s|" .. id .. "|" .. w, 1, 0, ttl)
  end
  local loc = locals[id]
  if not loc then
    loc = { window = W, paths = summary(), ips = summary() }
    locals[id] = loc
  end
  loc.window = W
  if cc.url_qps > 0 and usable_path(path) then
    _M.observe(loc.paths, path, _M.CANDIDATES)
  end
  if addr then
    _M.observe(loc.ips, addr, _M.CANDIDATES)
    if cc.ip_qps > 0 then
      return d:incr("i|" .. id .. "|" .. addr .. "|" .. w, 1, 0, ttl), w, now
    end
  end
end

-- log counts origin requests and origin errors (log phase).
function _M.log(site)
  local cc = site._cc
  if not cc or cc.error_percent <= 0 then return end
  local status = ngx.var.upstream_status
  if not status or status == "" then return end -- served without the origin
  local W = cc.window
  local w = floor(_M.clock() / W)
  local d = dict()
  local ttl = 2 * W + 2
  d:incr("o|" .. site.id .. "|" .. w, 1, 0, ttl)
  local last = tonumber(status:match("(%d+)%s*$"))
  if not last or last >= 500 then
    d:incr("e|" .. site.id .. "|" .. w, 1, 0, ttl)
  end
end

local function top(counts, n)
  local list = {}
  for k, v in pairs(counts) do list[#list + 1] = { k, v } end
  sort(list, function(a, b) return a[2] > b[2] or (a[2] == b[2] and a[1] < b[1]) end)
  local out = {}
  for i = 1, min(n, #list) do out[i] = list[i] end
  return out
end

-- flush hands the worker's summaries of the last second to the shared
-- dict: path counts, path candidates and the heaviest addresses.
function _M.flush(now)
  now = now or _M.clock()
  local d = dict()
  local current = locals
  locals = {}
  for id, loc in pairs(current) do
    local W = loc.window
    local w = floor(now / W)
    local ttl = 2 * W + 2
    if loc.paths.n > 0 then
      local offer = (d:llen("ps|" .. id) or 0) < 4096
      for path, c in pairs(loc.paths.counts) do
        d:incr("p|" .. id .. "|" .. w .. "|" .. path, c, 0, ttl)
        if offer then d:rpush("ps|" .. id, path) end
      end
    end
    if loc.ips.n > 0 and (d:llen("is|" .. id) or 0) < 4096 then
      for _, e in ipairs(top(loc.ips.counts, _M.TOP)) do
        d:rpush("is|" .. id, e[2] .. "\t" .. e[1])
      end
    end
  end
end

-- ---------------------------------------------------------------------
-- Evaluation

-- estimate is the sliding-window count of key pre .. w .. post.
local function estimate(d, pre, post, now, W)
  local w = floor(now / W)
  local cur = d:get(pre .. w .. post) or 0
  local prev = d:get(pre .. (w - 1) .. post) or 0
  return prev * (1 - (now - w * W) / W) + cur
end
_M.estimate = estimate

-- step moves state s = {level, hold, calm} for the ratio of the heaviest
-- trigger to its threshold; returns the previous level when it changed.
function _M.step(s, ratio, now, up_after, down_after, max_level)
  local before = s.level
  if s.level > max_level then
    s.level, s.hold, s.calm = max_level, 0, 0
  elseif ratio > 1 then
    s.calm = 0
    if s.hold == 0 then s.hold = now end
    if s.level < max_level and now - s.hold >= up_after then
      s.level, s.hold = s.level + 1, now
    end
  elseif ratio < 0.8 then
    s.hold = 0
    if s.level == 0 then
      s.calm = 0
    else
      if s.calm == 0 then s.calm = now end
      if now - s.calm >= down_after then
        s.level, s.calm = s.level - 1, now
      end
    end
  else
    s.hold, s.calm = 0, 0
  end
  if s.level ~= before then return before end
end

local function boot_id(d)
  local boot = d:get("#boot")
  if not boot then
    local ok, rand = pcall(require, "resty.openssl.rand")
    local bytes = ok and rand.bytes(6)
    boot = bytes and require("resty.string").to_hex(bytes) or format("%x%x", ngx.now() * 1000, ngx.worker.pid())
    d:safe_add("#boot", boot)
    boot = d:get("#boot") or boot
  end
  return boot
end

local function array(t)
  if cjson.empty_array_mt and #t == 0 then return setmetatable(t, cjson.empty_array_mt) end
  if cjson.array_mt then return setmetatable(t, cjson.array_mt) end
  return t
end

-- push queues an event for the agent (unique id "<boot>-<n>").
function _M.push(e)
  local d = dict()
  e.id = boot_id(d) .. "-" .. tostring(d:incr("#evseq", 1, 0))
  e.top_ips = array(e.top_ips or {})
  e.top_paths = array(e.top_paths or {})
  local raw = cjson.encode(e)
  if not raw then return end
  if (d:llen("#ev") or 0) >= _M.EVENTS_MAX then
    d:lpop("#ev")
    d:incr("#evdrop", 1, 0)
  end
  d:rpush("#ev", raw)
end

-- drain returns and deletes up to n queued events as a JSON array (the
-- events as queued: empty lists stay arrays).
function _M.drain(n)
  local d = dict()
  local out = {}
  for _ = 1, n or 1000 do
    local raw = d:lpop("#ev")
    if not raw then break end
    out[#out + 1] = raw
  end
  return "[" .. concat(out, ",") .. "]"
end

local function load_state(d, id)
  local raw = d:get("st|" .. id)
  local s = { level = 0, hold = 0, calm = 0, site_qps = 0, error_percent = 0 }
  if raw then
    local l, h, c, q, e = raw:match("^(%d+)|([%d.]+)|([%d.]+)|([%d.]+)|([%d.]+)$")
    if l then
      s.level, s.hold, s.calm, s.site_qps, s.error_percent = tonumber(l), tonumber(h), tonumber(c), tonumber(q), tonumber(e)
    end
  end
  return s
end

local function save_state(d, id, s)
  d:set("st|" .. id, format("%d|%.3f|%.3f|%.3f|%.3f", s.level, s.hold, s.calm, s.site_qps, s.error_percent), _M.STATE_TTL)
end

local function load_paths(d, id)
  local list = {}
  for line in (d:get("pc|" .. id) or ""):gmatch("[^\n]+") do
    local path, l, h, c = line:match("^([^\t]+)\t(%d+)\t([%d.]+)\t([%d.]+)$")
    if path then list[#list + 1] = { path = path, level = tonumber(l), hold = tonumber(h), calm = tonumber(c) } end
  end
  return list
end

-- top_addresses folds the offered addresses into the decaying aggregate
-- and returns it sorted.
local function top_addresses(d, id, W)
  local agg = {}
  local keep = 1 - 1 / W
  for line in (d:get("ta|" .. id) or ""):gmatch("[^\n]+") do
    local c, ip = line:match("^([%d.]+)\t(.+)$")
    if c then agg[ip] = tonumber(c) * keep end
  end
  for _ = 1, 4096 do
    local e = d:lpop("is|" .. id)
    if not e then break end
    local c, ip = e:match("^(%d+)\t(.+)$")
    if c then agg[ip] = (agg[ip] or 0) + tonumber(c) end
  end
  local list = top(agg, _M.CANDIDATES)
  local lines = {}
  for _, e in ipairs(list) do
    if e[2] >= 0.5 then lines[#lines + 1] = format("%.2f\t%s", e[2], e[1]) end
  end
  d:set("ta|" .. id, concat(lines, "\n"), _M.STATE_TTL)
  return list
end

local function counters(list, n)
  local out = {}
  for i = 1, min(n, #list) do
    local c = floor(list[i][2] + 0.5)
    if c > 0 then out[#out + 1] = { value = list[i][1], count = c } end
  end
  return out
end

-- evaluate_site runs one evaluation of a site with CC at time now.
function _M.evaluate_site(site, now)
  local cc = site._cc
  local d = dict()
  local id = site.id
  local W = cc.window
  local s = load_state(d, id)

  -- Site triggers: the heaviest one decides.
  local ratio, metric, observed, threshold = 0, "site_qps", 0, cc.site_qps
  if cc.site_qps > 0 then
    local q = estimate(d, "s|" .. id .. "|", "", now, W) / W
    s.site_qps = q
    ratio, observed = q / cc.site_qps, q
  end
  if cc.error_percent > 0 then
    local requests = estimate(d, "o|" .. id .. "|", "", now, W)
    local pct = 0
    if requests > 0 and requests >= cc.error_min then
      pct = estimate(d, "e|" .. id .. "|", "", now, W) * 100 / requests
    end
    s.error_percent = pct
    if pct / cc.error_percent > ratio then
      ratio, metric, observed, threshold = pct / cc.error_percent, "origin_error_rate", pct, cc.error_percent
    end
  end

  local addresses = top_addresses(d, id, W)

  -- Paths.
  local tracked = {}
  local paths_changed = {}
  if cc.url_qps > 0 then
    tracked = load_paths(d, id)
    local index = {}
    for _, p in ipairs(tracked) do index[p.path] = p end
    for _ = 1, 4096 do
      local path = d:lpop("ps|" .. id)
      if not path then break end
      if not index[path] then
        local p = { path = path, level = 0, hold = 0, calm = 0 }
        index[path] = p
        tracked[#tracked + 1] = p
      end
    end
    for _, p in ipairs(tracked) do
      p.count = estimate(d, "p|" .. id .. "|", "|" .. p.path, now, W)
      p.rate = p.count / W
      local before = _M.step(p, p.rate / cc.url_qps, now, cc.escalate, cc.cooldown, cc.max)
      if before then paths_changed[#paths_changed + 1] = { p, before } end
    end
    -- Escalated paths first, then the heaviest; at most 64 and none idle.
    sort(tracked, function(a, b)
      if (a.level > 0) ~= (b.level > 0) then return a.level > 0 end
      if a.rate ~= b.rate then return a.rate > b.rate end
      return a.path < b.path
    end)
    local kept, lines = {}, {}
    for _, p in ipairs(tracked) do
      if #kept >= _M.CANDIDATES then break end
      if p.level > 0 or p.hold > 0 or p.rate > 0 then
        kept[#kept + 1] = p
        lines[#lines + 1] = p.path .. "\t" .. p.level .. "\t" .. format("%.3f", p.hold) .. "\t" .. format("%.3f", p.calm)
      end
    end
    tracked = kept
    d:set("pc|" .. id, concat(lines, "\n"), _M.STATE_TTL)
  else
    d:delete("pc|" .. id)
  end

  local top_paths = {}
  do
    local list = {}
    for _, p in ipairs(tracked) do list[#list + 1] = { p.path, p.count or 0 } end
    sort(list, function(a, b) return a[2] > b[2] or (a[2] == b[2] and a[1] < b[1]) end)
    top_paths = counters(list, _M.TOP)
  end
  local top_ips = counters(addresses, _M.TOP)

  local before = _M.step(s, ratio, now, cc.escalate, cc.cooldown, cc.max)
  save_state(d, id, s)
  if before then
    _M.push({
      kind = "site_level", site_id = id, time = now, level = _M.NAMES[s.level], previous_level = _M.NAMES[before],
      metric = s.level > before and metric or "cooldown", observed = observed, threshold = threshold,
      top_ips = top_ips, top_paths = top_paths,
    })
  end
  for _, change in ipairs(paths_changed) do
    local p = change[1]
    _M.push({
      kind = "path_level", site_id = id, time = now, level = _M.NAMES[p.level], previous_level = _M.NAMES[change[2]],
      path = p.path, metric = p.level > change[2] and "url_qps" or "cooldown", observed = p.rate, threshold = cc.url_qps,
      top_ips = top_ips, top_paths = top_paths,
    })
  end

  -- What the hot path reads.
  local escalated = {}
  for _, p in ipairs(tracked) do
    if p.level > 0 then escalated[#escalated + 1] = p.level .. "\t" .. p.path end
  end
  sort(escalated)
  local map = concat(escalated, "\n")
  local version = 0
  if #escalated > 0 then
    if d:get("xm|" .. id) ~= map then
      d:set("xm|" .. id, map, _M.STATE_TTL)
      d:incr("xv|" .. id, 1, 0)
    else
      d:expire("xm|" .. id, _M.STATE_TTL)
    end
    version = d:get("xv|" .. id) or 1
  else
    d:delete("xm|" .. id)
  end
  d:set("lv|" .. id, version * 8 + s.level, _M.STATE_TTL)
end

-- check_ip applies the per-address trigger after count(): an address over
-- ip_qps is banned once per ban period and its request refused (true).
function _M.check_ip(site, addr, n, w, now)
  local cc = site._cc
  local W = cc.window
  local limit = cc.ip_qps * W
  local est = n
  if n <= limit then
    -- Below half the limit in the current window alone the previous
    -- window is not read: an address that exceeds the limit crosses half
    -- of it right after.
    if n * 2 <= limit then return false end
    local prev = dict():get("i|" .. site.id .. "|" .. addr .. "|" .. (w - 1)) or 0
    est = prev * (1 - (now - w * W) / W) + n
    if est <= limit then return false end
  end
  local d = dict()
  if d:safe_add("b|" .. site.id .. "|" .. addr, true, cc.ip_ban) then
    local rate = est / W
    require("edgeweir.bans").add_auto(site.id, addr, cc.ip_ban, {
      reason = "cc_ip_rate", metric = "ip_qps", observed = rate, threshold = cc.ip_qps, window_seconds = W,
    })
    local s = load_state(d, site.id)
    local name = _M.NAMES[s.level]
    _M.push({
      kind = "ip_banned", site_id = site.id, time = now, level = name, previous_level = name, address = addr,
      metric = "ip_qps", observed = rate, threshold = cc.ip_qps,
      top_ips = { { value = addr, count = floor(est + 0.5) } },
    })
  end
  return true
end

local pmaps = {}

-- level returns the CC level of a request: the site's, or the path's when
-- the path is escalated above it.
function _M.level(site, path)
  local v = dict():get("lv|" .. site.id)
  if not v then return 0 end
  local level = v % 8
  local version = (v - level) / 8
  if version > 0 and path then
    local m = pmaps[site.id]
    if not m or m.version ~= version then
      m = { version = version, paths = {} }
      for line in (dict():get("xm|" .. site.id) or ""):gmatch("[^\n]+") do
        local l, p = line:match("^(%d)\t(.+)$")
        if l then m.paths[p] = tonumber(l) end
      end
      pmaps[site.id] = m
    end
    local pl = m.paths[path]
    if pl and pl > level then level = pl end
  end
  return level
end

-- forget drops worker-local state (tests).
function _M.forget()
  locals, pmaps = {}, {}
end

-- sites returns the current sites with CC (from the site table), or nil
-- before the first table (replaced in tests).
_M.sites = function()
  local store = require("edgeweir.store")
  local ids = store.config().cc_sites
  if not ids then return nil end
  local out = {}
  for _, id in ipairs(ids) do
    local site = store.site_current(id)
    if site and site._cc then out[#out + 1] = site end
  end
  return out
end

local CLEARED = { "st|", "pc|", "xm|", "lv|", "ta|", "ps|", "is|" }

-- sweep clears the state of the sites evaluated last that are no longer
-- in list (their policy went away) and records list as #sites.
local function sweep(d, list)
  local ids = {}
  for i, site in ipairs(list) do ids[i] = site.id end
  local current = concat(ids, "\n")
  local last = d:get("#sites")
  if last == current then return end
  if last then
    local on = {}
    for _, id in ipairs(ids) do on[id] = true end
    for id in last:gmatch("[^\n]+") do
      if not on[id] then
        for _, prefix in ipairs(CLEARED) do d:delete(prefix .. id) end
      end
    end
  end
  d:set("#sites", current)
end

-- evaluate runs one evaluation of every site with CC.
function _M.evaluate(now)
  local list = _M.sites()
  if not list then return end
  sweep(dict(), list)
  for _, site in ipairs(list) do
    local ok, err = pcall(_M.evaluate_site, site, now)
    if not ok then ngx.log(ngx.ERR, "edgeweir: CC evaluation failed site=", site.id, ": ", err) end
  end
end

-- tick runs every second in every worker: flush, then evaluate in the one
-- worker that takes this second.
function _M.tick()
  local now = _M.clock()
  _M.flush(now)
  if ngx.worker.exiting() then return end
  if dict():add("#eval|" .. floor(now), true, 10) then
    _M.evaluate(now)
  end
end

function _M.init_worker()
  local ok, err = ngx.timer.every(1, function(premature)
    if not premature then
      local fine, e = pcall(_M.tick)
      if not fine then ngx.log(ngx.ERR, "edgeweir: CC tick failed: ", e) end
    end
  end)
  if not ok then ngx.log(ngx.ERR, "edgeweir: CC timer unavailable: ", err) end
end

-- status is GET /v1/security: every site with CC, its level, escalated
-- paths and the last observed rates, and the event queue.
function _M.status()
  local d = dict()
  local sites = {}
  for _, site in ipairs(_M.sites() or {}) do
    local s = load_state(d, site.id)
    local paths = {}
    for line in (d:get("xm|" .. site.id) or ""):gmatch("[^\n]+") do
      local l, p = line:match("^(%d)\t(.+)$")
      if l then paths[#paths + 1] = { path = p, level = _M.NAMES[tonumber(l)] } end
    end
    sites[#sites + 1] = {
      site_id = site.id, level = _M.NAMES[s.level] or "normal", escalated_paths = #paths, paths = array(paths),
      site_qps = s.site_qps, error_percent = s.error_percent,
    }
  end
  return {
    sites = array(sites), pending_events = d:llen("#ev") or 0, dropped_events = d:get("#evdrop") or 0,
  }
end

return _M
