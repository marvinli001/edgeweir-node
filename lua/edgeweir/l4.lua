-- edgeweir.l4: layer-4 (TCP / UDP) applications in the stream subsystem.
--
-- nginx.conf has one stream server per (port, protocol) (internal/render);
-- everything else about an application comes from the layer-4 table the
-- agent pushes through the control socket (edgeweir.l4control), so
-- changing origins, timeouts, IP lists or limits never reloads nginx:
--
--   preread  finds the application of $protocol:$server_port and checks
--            the client address (from the PROXY protocol header when the
--            listener accepts one) against its allow lists (when set, only
--            their addresses pass) and block lists, then the new
--            connections per second and the concurrent connections on this
--            node; a refusal ends the session before anything is forwarded
--            (TCP: the connection is closed, UDP: the datagram dropped;
--            session status 403) and counts as refused. It then orders the
--            origins (order()) and resolves host names with the origin
--            address policy (edgeweir.dns).
--   balance  (balancer_by_lua) one origin per attempt; a failed connect is
--            a passive health failure and the next origin is tried
--            (set_more_tries, at most MAX_TRIES attempts); the connect
--            timeout and the idle timeout (proxy_timeout) of the
--            application are set per session.
--   relay    (content_by_lua, TCP applications that accept and send the
--            PROXY protocol) connects itself, writes the PROXY header with
--            the client's address and copies both directions with two
--            light threads until one side closes or neither moved data for
--            the idle timeout (nginx's proxy_timeout semantics).
--   log      passive health of the last attempt, statistics, the
--            connection count.
--
-- Shared dicts (all workers, kept across reloads):
--
-- edgeweir_l4 (--l4-dict-mb): the table, written only with safe_set so
-- that nothing evicts it:
--
--   version, t:<N>          the current table (JSON, version N; N-1 is
--                           kept for workers that read the old version)
--   revision, content_hash, pushed_at, #lock
--
-- edgeweir_l4_state:
--
--   f|<app>|<origin>        consecutive failures; the counter expires
--                           fail_timeout after the first one
--   d|<app>|<origin>        down until (epoch s, expires then): reached
--                           max_fails within fail_timeout
--   c|<app>                 concurrent connections or UDP sessions
--   p|<pid>|<app>           ... of one worker process, and pid|<pid> (its
--                           start time): a worker that died without its log
--                           phases (crash) has its count taken back by the
--                           next sweep, so a limit never stays used up
--   n|<app>|<second>        new connections or sessions in that second
--   #sweep                  held by the worker that sweeps
--
-- lua_shared_dict edgeweir_l4_stats: "<minute>|<app>|<metric>" counters
-- (conn, refused, peak, rx, tx), drained by the agent per completed
-- minute (drain()). Bytes are counted while a connection runs: every
-- worker samples the byte counters of its open sessions every
-- SAMPLE_INTERVAL seconds and counts the growth in the current minute;
-- the log phase counts the rest. Old workers after a reload keep sampling
-- until their last session ends.
--
-- Selection (order()): weighted random among the healthy primaries; the
-- backups (weighted) only when every primary is down; when every origin
-- is down all of them, primaries first (fail open: a success ends the
-- down period early). Origins with special-purpose IP literals outside the
-- allow list (forbidden) are never used.
local cjson = require("cjson.safe")
local ipaddr = require("edgeweir.ipaddr")
local expressions = require("edgeweir.expressions")
local dns = require("edgeweir.dns")
local proxyproto = require("edgeweir.proxyproto")

local _M = {}

_M.MAX_TRIES = 3
_M.SAMPLE_INTERVAL = 10
-- Sweeps run every SWEEP_EVERY samples; registrations younger than
-- SWEEP_MIN_AGE seconds are left alone (a new worker may not be known to
-- the others yet).
_M.SWEEP_EVERY = 3
_M.SWEEP_MIN_AGE = 60
_M.STATS_TTL = 7200
_M.RELAY_BUFFER = 65536
_M.RELAY_TICK_MS = 10000

local floor, find, lower, sub = math.floor, string.find, string.lower, string.sub
local random = math.random
local tonumber, tostring, type = tonumber, tostring, type

local function dict()
  return ngx.shared.edgeweir_l4
end

local function state()
  return ngx.shared.edgeweir_l4_state
end

local function sdict()
  return ngx.shared.edgeweir_l4_stats
end

local function valid_id(s)
  return type(s) == "string" and #s > 0 and #s <= 128 and not find(s, "[^A-Za-z0-9_-]")
end

local function whole(v, min, max)
  return type(v) == "number" and v == floor(v) and v >= min and v <= max
end

------------------------------------------------------------------------
-- The table.

-- prepare checks a decoded table and indexes it for lookups (pure):
-- by_port["tcp:9000"] = application; each application gets _allow and
-- _block (lists of address matchers) and the parsed origin allow list as
-- doc.allowed. Returns doc or nil and an error.
function _M.prepare(doc)
  if type(doc) ~= "table" or type(doc.apps) ~= "table" then
    return nil, "table must be an object with apps"
  end
  local lists = {}
  for i, l in ipairs(type(doc.ip_lists) == "table" and doc.ip_lists or {}) do
    if type(l) ~= "table" or not valid_id(l.id) or type(l.entries) ~= "table" then
      return nil, "invalid IP list #" .. i
    end
    for _, e in ipairs(l.entries) do
      if not ipaddr.parse_prefix(e) then
        return nil, "IP list " .. l.id .. ": invalid entry " .. tostring(e)
      end
    end
    lists[l.id] = expressions.ip_set(l.entries)
  end
  doc.by_port = {}
  for i, a in ipairs(doc.apps) do
    if type(a) ~= "table" or not valid_id(a.id) or (a.protocol ~= "tcp" and a.protocol ~= "udp") or not whole(a.port, 1, 65535) then
      return nil, "invalid application #" .. i
    end
    if not whole(a.max_fails, 1, 100) or not whole(a.fail_timeout, 1, 3600) or not whole(a.connect_timeout_ms, 1, 60000)
        or not whole(a.idle_timeout, 1, 86400) then
      return nil, "application " .. a.id .. ": invalid health check or timeouts"
    end
    a.max_connections = tonumber(a.max_connections) or 0
    a.new_connections_per_second = tonumber(a.new_connections_per_second) or 0
    a.proxy_protocol_version = tonumber(a.proxy_protocol_version) or 0
    if type(a.origins) ~= "table" or #a.origins == 0 then
      return nil, "application " .. a.id .. ": no origins"
    end
    for j, o in ipairs(a.origins) do
      if type(o) ~= "table" or not valid_id(o.id) or type(o.address) ~= "string" or o.address == "" or not whole(o.port, 1, 65535)
          or not whole(o.weight, 1, 100) then
        return nil, "application " .. a.id .. ": invalid origin #" .. j
      end
    end
    for _, kind in ipairs({ "allow", "block" }) do
      local ids = a[kind .. "_lists"]
      if ids ~= nil and ids ~= cjson.null then
        if type(ids) ~= "table" then
          return nil, "application " .. a.id .. ": invalid " .. kind .. " lists"
        end
        local matchers = {}
        for _, id in ipairs(ids) do
          if not lists[id] then
            return nil, "application " .. a.id .. ": unknown " .. kind .. " list " .. tostring(id)
          end
          matchers[#matchers + 1] = lists[id]
        end
        if #matchers > 0 then
          a["_" .. kind] = matchers
        end
      end
    end
    local key = a.protocol .. ":" .. a.port
    if doc.by_port[key] then
      return nil, "two applications on " .. key
    end
    doc.by_port[key] = a
  end
  doc.allowed = ipaddr.prefixes(doc.origin_allowed_cidrs)
  return doc
end

local cache = { version = nil, doc = nil }

-- current returns the prepared table this worker serves (nil before the
-- first push after nginx started).
function _M.current()
  local d = dict()
  local version = d:get("version")
  if not version then
    return nil
  end
  if cache.version == version then
    return cache.doc
  end
  local doc = _M.prepare(cjson.decode(d:get("t:" .. version) or ""))
  if not doc then
    ngx.log(ngx.ERR, "edgeweir: cannot read layer-4 table version ", version)
    return cache.doc
  end
  cache.version, cache.doc = version, doc
  return doc
end

-- replace installs a new table (the body of PUT /v1/l4). Returns the
-- status or nil, an error and an HTTP status.
function _M.replace(raw)
  local doc, derr = cjson.decode(raw or "")
  if type(doc) ~= "table" then
    return nil, "invalid JSON: " .. tostring(derr), 400
  end
  local ok, perr = _M.prepare(doc)
  if not ok then
    return nil, perr, 400
  end
  if type(doc.revision) ~= "string" or not find(doc.revision, "^%d+$") then
    return nil, "revision must be a decimal string", 400
  end
  local d = dict()
  local locked, lerr = d:add("#lock", true, 30)
  if not locked then
    if lerr == "exists" then
      return nil, "another update is in progress", 409
    end
    return nil, "lock: " .. tostring(lerr), 500
  end
  local version = (d:get("version") or 0) + 1
  local function fail(err)
    d:delete("t:" .. version)
    d:delete("#lock")
    return nil, "shared dict edgeweir_l4: " .. tostring(err), err == "no memory" and 507 or 500
  end
  local sok, serr = d:safe_set("t:" .. version, raw)
  if not sok then
    return fail(serr)
  end
  for _, kv in ipairs({ { "revision", doc.revision }, { "content_hash", type(doc.content_hash) == "string" and doc.content_hash or "" },
    { "pushed_at", ngx.now() } }) do
    sok, serr = d:safe_set(kv[1], kv[2])
    if not sok then
      return fail(serr)
    end
  end
  -- The flip: workers read the new table from their next connection on.
  sok, serr = d:safe_set("version", version)
  if not sok then
    return fail(serr)
  end
  d:delete("t:" .. (version - 2))
  d:delete("#lock")
  return _M.status()
end

-- status describes the table and the origins the passive check holds
-- down.
function _M.status(now)
  now = now or ngx.now()
  local d = dict()
  local out = {
    version = d:get("version") or 0,
    revision = d:get("revision") or "0",
    content_hash = d:get("content_hash") or "",
    pushed_at = d:get("pushed_at") or 0,
    apps = 0,
  }
  local doc = _M.current()
  if doc then
    out.apps = #doc.apps
    local down = {}
    local st = state()
    for _, a in ipairs(doc.apps) do
      for _, o in ipairs(a.origins) do
        local untl = st:get("d|" .. a.id .. "|" .. o.id)
        if untl and untl > now then
          down[#down + 1] = { app_id = a.id, origin_id = o.id, down_until = untl }
        end
      end
    end
    if #down > 0 then
      out.down = down
    end
  end
  return out
end

------------------------------------------------------------------------
-- Passive health.

function _M.is_down(app_id, origin_id, now)
  local untl = state():get("d|" .. app_id .. "|" .. origin_id)
  return untl ~= nil and untl > (now or ngx.now())
end

-- failure records a failed attempt (connect error or timeout, DNS
-- failure, refused address); returns true when the origin goes down.
function _M.failure(app, origin_id, now, why)
  now = now or ngx.now()
  local d = state()
  local k = app.id .. "|" .. origin_id
  local n = d:incr("f|" .. k, 1, 0, app.fail_timeout)
  if n and n >= app.max_fails then
    d:set("d|" .. k, now + app.fail_timeout, app.fail_timeout)
    d:delete("f|" .. k)
    ngx.log(ngx.WARN, "edgeweir: layer-4 application ", app.id, " origin ", origin_id, " down for ",
      app.fail_timeout, " s after ", n, " failure(s)", why and (": " .. why) or "")
    return true
  end
  return false
end

-- success ends an origin's failure count (and a down period: fail open).
function _M.success(app, origin_id)
  local d = state()
  local k = app.id .. "|" .. origin_id
  if d:get("f|" .. k) then
    d:delete("f|" .. k)
  end
  if d:get("d|" .. k) then
    d:delete("d|" .. k)
  end
end

------------------------------------------------------------------------
-- Selection.

-- weighted_order samples without replacement, proportionally to weight
-- (rand() in [0, 1), math.random by default).
function _M.weighted_order(list, rand)
  rand = rand or random
  local rest, out = {}, {}
  for i = 1, #list do
    rest[i] = list[i]
  end
  while #rest > 0 do
    local total = 0
    for i = 1, #rest do
      total = total + rest[i].weight
    end
    local r = rand() * total
    local idx = #rest
    for i = 1, #rest do
      r = r - rest[i].weight
      if r < 0 then
        idx = i
        break
      end
    end
    out[#out + 1] = table.remove(rest, idx)
  end
  return out
end

-- order returns the origins to try for a new connection, best first, at
-- most MAX_TRIES (see the module comment). is_down(app_id, origin_id, now)
-- defaults to the passive check.
function _M.order(app, now, is_down, rand)
  is_down = is_down or _M.is_down
  local prim, back, hp, hb = {}, {}, {}, {}
  for _, o in ipairs(app.origins) do
    if not o.forbidden then
      local up = not is_down(app.id, o.id, now)
      if o.backup then
        back[#back + 1] = o
        if up then
          hb[#hb + 1] = o
        end
      else
        prim[#prim + 1] = o
        if up then
          hp[#hp + 1] = o
        end
      end
    end
  end
  local out
  if #hp > 0 then
    out = _M.weighted_order(hp, rand)
  elseif #hb > 0 then
    out = _M.weighted_order(hb, rand)
  else
    out = _M.weighted_order(prim, rand)
    local rest = _M.weighted_order(back, rand)
    for i = 1, #rest do
      out[#out + 1] = rest[i]
    end
  end
  for i = #out, _M.MAX_TRIES + 1, -1 do
    out[i] = nil
  end
  return out
end

-- peers resolves the ordered origins: {origin, ip, port} each; an origin
-- whose name does not resolve (or only to refused addresses) is a
-- failure and is skipped.
function _M.peers(app, doc, now)
  local out = {}
  for _, o in ipairs(_M.order(app, now)) do
    local ip, err = dns.resolve(o.address, doc.allowed)
    if ip then
      out[#out + 1] = { origin = o, ip = ip, port = o.port }
    else
      _M.failure(app, o.id, now, err)
    end
  end
  return out
end

------------------------------------------------------------------------
-- Admission.

local function listed(matchers, addr)
  for i = 1, #matchers do
    if matchers[i](addr) then
      return true
    end
  end
  return false
end

-- admit decides a new connection or session from addr. Returns nil and
-- the node's concurrent count when it may proceed, or the reason of the
-- refusal: "allow_list", "block_list", "rate", "limit".
function _M.admit(app, addr, now, pid)
  if app._allow and not listed(app._allow, addr) then
    return "allow_list"
  end
  if app._block and listed(app._block, addr) then
    return "block_list"
  end
  local d = state()
  if app.new_connections_per_second > 0 then
    local n = d:incr("n|" .. app.id .. "|" .. floor(now), 1, 0, 2)
    if n and n > app.new_connections_per_second then
      return "rate"
    end
  end
  local c = d:incr("c|" .. app.id, 1, 0) or 1
  if app.max_connections > 0 and c > app.max_connections then
    d:incr("c|" .. app.id, -1, 0)
    return "limit"
  end
  d:incr("p|" .. pid .. "|" .. app.id, 1, 0)
  return nil, c
end

-- release ends an admitted connection of worker pid.
function _M.release(app_id, pid)
  local d = state()
  local c = d:incr("c|" .. app_id, -1, 0)
  if c and c < 0 then
    -- A sweep took back a count this worker still held (it cannot tell a
    -- dead worker from one it did not know yet); never below zero.
    d:incr("c|" .. app_id, -c, 0)
  end
  local p = d:incr("p|" .. pid .. "|" .. app_id, -1, 0)
  if p and p <= 0 then
    d:delete("p|" .. pid .. "|" .. app_id)
  end
end

-- sweep takes back the counts of worker processes that are gone (pids:
-- the live workers, old ones of a reload included); registrations
-- younger than SWEEP_MIN_AGE are skipped.
function _M.sweep(pids, now)
  local d = state()
  local alive = {}
  for _, pid in ipairs(pids) do
    alive[tostring(pid)] = true
  end
  local dead = {}
  for _, k in ipairs(d:get_keys(0)) do
    if sub(k, 1, 4) == "pid|" then
      local pid = sub(k, 5)
      local since = d:get(k)
      if not alive[pid] and since and now - since >= _M.SWEEP_MIN_AGE then
        dead[pid] = true
        d:delete(k)
      end
    end
  end
  if next(dead) == nil then
    return 0
  end
  local taken = 0
  for _, k in ipairs(d:get_keys(0)) do
    if sub(k, 1, 2) == "p|" then
      local pid, app = k:match("^p|(%d+)|(.+)$")
      if pid and dead[pid] then
        local n = d:get(k) or 0
        d:delete(k)
        if n > 0 then
          local c = d:incr("c|" .. app, -n, 0)
          if c and c < 0 then
            d:incr("c|" .. app, -c, 0)
          end
          taken = taken + n
          ngx.log(ngx.WARN, "edgeweir: layer-4 application ", app, ": ", n,
            " connection(s) of worker ", pid, " that ended without logging them released")
        end
      end
    end
  end
  return taken
end

------------------------------------------------------------------------
-- Statistics.

local function minute(now)
  return floor(now / 60) * 60
end

-- count adds n to a metric of the application's current minute.
function _M.count(app_id, metric, n, now)
  if n and n > 0 then
    sdict():incr(minute(now) .. "|" .. app_id .. "|" .. metric, n, 0, _M.STATS_TTL)
  end
end

-- peak records a concurrent count seen in the current minute.
function _M.peak(app_id, value, now)
  local s = sdict()
  local k = minute(now) .. "|" .. app_id .. "|peak"
  local cur = s:get(k)
  if not cur or value > cur then
    s:set(k, value, _M.STATS_TTL)
  end
end

-- account counts the growth of a session's byte counters (rx: from the
-- client, tx: to the client) since the last call.
function _M.account(e, rx, tx, now)
  rx, tx = tonumber(rx), tonumber(tx)
  if rx and rx > e.rx then
    _M.count(e.app, "rx", rx - e.rx, now)
    e.rx = rx
  end
  if tx and tx > e.tx then
    _M.count(e.app, "tx", tx - e.tx, now)
    e.tx = tx
  end
end

local FIELDS = { conn = "connections", refused = "refused", peak = "peak_concurrent", rx = "bytes_received", tx = "bytes_sent" }

-- drain returns and deletes the counters of completed minutes (before the
-- minute of now): {minute, app_id, connections, refused, peak_concurrent,
-- bytes_received, bytes_sent} per application and minute.
function _M.drain(now)
  local s = sdict()
  local current = minute(now or ngx.time())
  local buckets, list = {}, {}
  for _, k in ipairs(s:get_keys(0)) do
    local m, app, metric = k:match("^(%d+)|(.+)|(%a+)$")
    local field = FIELDS[metric]
    m = tonumber(m)
    if m and field and m < current then
      local v = s:get(k)
      s:delete(k)
      local bk = m .. "|" .. app
      local b = buckets[bk]
      if not b then
        b = { minute = m, app_id = app, connections = 0, refused = 0, peak_concurrent = 0, bytes_received = 0, bytes_sent = 0 }
        buckets[bk] = b
        list[#list + 1] = b
      end
      b[field] = b[field] + (v or 0)
    end
  end
  table.sort(list, function(a, b)
    return a.minute < b.minute or (a.minute == b.minute and a.app_id < b.app_id)
  end)
  if cjson.array_mt then
    setmetatable(list, cjson.array_mt)
  end
  return list
end

------------------------------------------------------------------------
-- Open sessions of this worker: [$connection] = {app, r (the session's
-- request, read with read_bytes) or relay (the relay's counters), rx, tx
-- (bytes counted so far)}.

local live = {}
_M.live = live

-- read_bytes(r) returns the byte counters of a running session from its
-- request object (set in the stream subsystem): nginx's $bytes_received
-- and $bytes_sent through the variable API that ngx.var uses. A session
-- is read only while it is in live: log() removes it before nginx frees
-- the request.
_M.read_bytes = nil
local get_request

if ngx.config.subsystem == "stream" then
  local ffi = require("ffi")
  local base = require("resty.core.base")
  require("resty.core.var") -- declares ngx_stream_lua_ffi_var_get
  local C = ffi.C
  local value_ptr = ffi.new("unsigned char *[1]")
  local errmsg = base.get_errmsg_ptr()
  get_request = base.get_request
  local function var(r, name)
    local len = base.get_size_ptr()
    local rc = C.ngx_stream_lua_ffi_var_get(r, name, #name, base.get_string_buf(#name), 0, value_ptr, len, errmsg)
    if rc ~= 0 then
      return nil
    end
    return tonumber(ffi.string(value_ptr[0], len[0]))
  end
  _M.read_bytes = function(r)
    return var(r, "bytes_received"), var(r, "bytes_sent")
  end
end

-- sample counts the bytes of this worker's open sessions and the
-- applications' concurrent counts.
function _M.sample(now)
  for _, e in pairs(live) do
    if e.relay then
      _M.account(e, e.relay.rx, e.relay.tx, now)
    elseif e.r and _M.read_bytes then
      local rx, tx = _M.read_bytes(e.r)
      _M.account(e, rx, tx, now)
    end
  end
  local doc = _M.current()
  if doc then
    local d = state()
    for _, a in ipairs(doc.apps) do
      local c = d:get("c|" .. a.id)
      if c and c > 0 then
        _M.peak(a.id, c, now)
      end
    end
  end
end

------------------------------------------------------------------------
-- nginx hooks.

function _M.init(opts)
  opts = opts or {}
  _M.conf_id = type(opts.conf_id) == "string" and opts.conf_id or ""
  dns.configure(opts.resolvers, opts.ipv6)
  require("edgeweir.l4control")
end

local function sampler(premature)
  if premature then
    return
  end
  local pid = ngx.worker.pid()
  local ticks = 0
  while true do
    ngx.sleep(_M.SAMPLE_INTERVAL)
    local now = ngx.now()
    local ok, err = pcall(_M.sample, now)
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: layer-4 sampling failed: ", err)
    end
    ticks = ticks + 1
    if ticks % _M.SWEEP_EVERY == 0 then
      local pids = ngx.worker.pids and ngx.worker.pids()
      if pids and #pids > 0 and state():add("#sweep", pid, _M.SAMPLE_INTERVAL * _M.SWEEP_EVERY - 1) then
        ok, err = pcall(_M.sweep, pids, now)
        if not ok then
          ngx.log(ngx.ERR, "edgeweir: layer-4 connection sweep failed: ", err)
        end
      end
    end
    -- Old workers of a reload keep counting until their last session
    -- ends (they exit then).
    if ngx.worker.exiting() and next(live) == nil then
      return
    end
  end
end

function _M.init_worker()
  math.randomseed(ngx.now() * 1000 + ngx.worker.pid())
  state():set("pid|" .. ngx.worker.pid(), ngx.now())
  local ok, err = ngx.timer.at(0, sampler)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: cannot start the layer-4 sampler: ", err)
  end
end

local warned = {}

local function warn_once(key, ...)
  local now = ngx.now()
  if (warned[key] or 0) + 60 <= now then
    warned[key] = now
    ngx.log(ngx.WARN, ...)
  end
end

-- client returns the client's address and port: the PROXY protocol
-- header's when the listener accepts one (and it carries addresses), the
-- TCP or UDP peer's otherwise.
local function client(var)
  local addr = var.proxy_protocol_addr
  if addr and addr ~= "" then
    return addr, var.proxy_protocol_port, var.proxy_protocol_server_addr, var.proxy_protocol_server_port
  end
  return var.remote_addr, var.remote_port, var.server_addr, var.server_port
end

function _M.preread()
  local var = ngx.var
  local now = ngx.now()
  local doc = _M.current()
  local key = lower(var.protocol or "") .. ":" .. tostring(var.server_port)
  local app = doc and doc.by_port[key]
  if not app then
    warn_once(key, "edgeweir: no layer-4 application for ", key, " (yet); connection closed")
    return ngx.exit(ngx.ERROR)
  end
  local ctx = { app = app, try = 0 }
  ngx.ctx.edgeweir_l4 = ctx
  local addr = client(var)
  local pid = ngx.worker.pid()
  local refused, concurrent = _M.admit(app, addr, now, pid)
  if refused then
    ctx.refused = true
    _M.count(app.id, "refused", 1, now)
    return ngx.exit(403)
  end
  ctx.pid = pid
  _M.count(app.id, "conn", 1, now)
  _M.peak(app.id, concurrent, now)
  live[var.connection] = { app = app.id, r = get_request and get_request(), rx = 0, tx = 0 }
  ctx.peers = _M.peers(app, doc, now)
  if #ctx.peers == 0 then
    warn_once("none:" .. app.id, "edgeweir: layer-4 application ", app.id, ": no usable origin")
    return ngx.exit(502)
  end
end

local balancer

function _M.balance()
  local ctx = ngx.ctx.edgeweir_l4
  if not ctx or not ctx.peers then
    error("edgeweir: layer-4 session without origins")
  end
  balancer = balancer or require("ngx.balancer")
  local app, i = ctx.app, ctx.try + 1
  if i > 1 then
    -- nginx retries only when connecting failed.
    _M.failure(app, ctx.peers[i - 1].origin.id, ngx.now(), "connect failed")
  end
  local peer = ctx.peers[i]
  if not peer then
    error("edgeweir: layer-4 session out of origins")
  end
  ctx.try = i
  if i == 1 then
    if #ctx.peers > 1 then
      balancer.set_more_tries(#ctx.peers - 1)
    end
    local ok, err = balancer.set_timeouts(app.connect_timeout_ms / 1000, app.idle_timeout, app.idle_timeout)
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: layer-4 timeouts: ", err)
    end
  end
  local ok, err = balancer.set_current_peer(peer.ip, peer.port)
  if not ok then
    error("edgeweir: layer-4 peer " .. peer.ip .. ":" .. peer.port .. ": " .. tostring(err))
  end
end

-- pipe copies from one socket to the other until a side closes, a write
-- fails, or neither direction moved data for the idle timeout (state.last
-- is the last activity of either direction).
local function pipe(from, to, counters, field, state, idle)
  while true do
    local data, err = from:receiveany(_M.RELAY_BUFFER)
    if data then
      counters[field] = counters[field] + #data
      state.last = ngx.now()
      local ok = to:send(data)
      if not ok then
        return
      end
      state.last = ngx.now()
    elseif err == "timeout" then
      if ngx.now() - state.last >= idle then
        return
      end
    else
      return
    end
  end
end

function _M.relay()
  local ctx = ngx.ctx.edgeweir_l4
  if not ctx or not ctx.peers then
    return ngx.exit(ngx.ERROR)
  end
  local app = ctx.app
  local idle_ms = app.idle_timeout * 1000
  local up, peer
  for i, p in ipairs(ctx.peers) do
    local sock = ngx.socket.tcp()
    sock:settimeouts(app.connect_timeout_ms, idle_ms, math.min(idle_ms, _M.RELAY_TICK_MS))
    ctx.try = i
    local ok, err = sock:connect(p.ip, p.port)
    if ok then
      up, peer = sock, p
      break
    end
    _M.failure(app, p.origin.id, ngx.now(), "connect: " .. tostring(err))
  end
  ctx.relayed = true
  if not up then
    return ngx.exit(502)
  end
  _M.success(app, peer.origin.id)
  local var = ngx.var
  local src, sport, dst, dport = client(var)
  local header
  if app.proxy_protocol_version == 2 then
    header = proxyproto.v2(src, dst, sport, dport)
  else
    header = proxyproto.v1(src, dst, sport, dport)
  end
  local counters = { rx = 0, tx = 0 }
  local e = live[var.connection]
  if e then
    e.r, e.relay = nil, counters
  end
  ctx.counters = counters
  if not up:send(header) then
    up:close()
    return
  end
  local down = ngx.req.socket(true)
  down:settimeouts(app.connect_timeout_ms, idle_ms, math.min(idle_ms, _M.RELAY_TICK_MS))
  local state = { last = ngx.now() }
  local idle = app.idle_timeout
  local t1 = ngx.thread.spawn(pipe, down, up, counters, "rx", state, idle)
  local t2 = ngx.thread.spawn(pipe, up, down, counters, "tx", state, idle)
  ngx.thread.wait(t1, t2)
  -- The other direction may still wait for data: stop it before closing.
  ngx.thread.kill(t1)
  ngx.thread.kill(t2)
  up:close()
end

function _M.log()
  local ctx = ngx.ctx.edgeweir_l4
  if not ctx or ctx.refused or not ctx.pid then
    return
  end
  local var = ngx.var
  local now = ngx.now()
  local app = ctx.app
  local e = live[var.connection]
  live[var.connection] = nil
  if e then
    if ctx.counters then
      _M.account(e, ctx.counters.rx, ctx.counters.tx, now)
    else
      _M.account(e, var.bytes_received, var.bytes_sent, now)
    end
  end
  _M.release(app.id, ctx.pid)
  -- The relay recorded its own attempts; nginx's last attempt connected
  -- unless the session ended with 502 (no origin could be reached).
  if not ctx.relayed and ctx.try > 0 then
    local last = ctx.peers[ctx.try].origin.id
    if var.status == "502" then
      _M.failure(app, last, now, "connect failed")
    else
      _M.success(app, last)
    end
  end
end

return _M
