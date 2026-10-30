-- edgeweir.ext: node extensions (extensions-v1), signed Lua packages the
-- operator installed in the console (docs/reference/extensions.md in the
-- console repository: format edgeweir-node-extension-v1, Lua API 1).
--
-- The agent verifies and unpacks each package (internal/agent/extensions.go)
-- and lists the loadable ones in nginx.conf (init: id, dir, sha256, in hook
-- order). Each worker loads them on start in an environment of their own
-- (sandbox(): hygiene, not a security boundary) and runs an extension's
-- init hook on its first use. The site table names the settings (kill
-- switch, per extension enabled, failure mode and global configuration,
-- edgeweir.store: cfg.extensions) and each site the extensions it turns on
-- with their site configuration (site._ext); both change without a reload.
--
-- edgeweir.router calls the hooks: endpoint() for /.edgeweir/ext/<id>/...,
-- access() before access control, rules and challenges, access_late()
-- after them, header_filter() and body_filter() on the response; and
-- edgeweir.stats log() before the access log. Every hook call runs under
-- pcall; an error or a call over its budget is a fault, 20 faults within a
-- minute trip the extension in this worker for a minute, and a failing or
-- tripped extension is skipped (failure mode open) or answers 503
-- X-Edgeweir-Error: extension in access, access_late and endpoint (closed).
local cjson = require("cjson.safe")
local reasons = require("edgeweir.reasons")

local _M = {}

local byte, find, sub, lower, gsub, format = string.byte, string.find, string.sub, string.lower, string.gsub, string.format
local concat = table.concat

-- API is the highest Lua API this node runs; packages may require 1..API
-- (extensions-v1, extensions-v2).
_M.API = 2
_M.PREFIX = "/.edgeweir/ext/"
-- Budgets of a hook call in seconds (wall time): IO_BUDGET for the hooks
-- of extensions with http_client that may wait on cosockets.
_M.BUDGET = 0.010
_M.IO_BUDGET = 1.0
_M.MAX_FAULTS = 20
_M.FAULT_WINDOW = 60
_M.TRIP_SECONDS = 60
_M.MAX_INJECT = 8192
_M.HEAD_SCAN = 65536
_M.TAIL = 512
_M.MAX_LOG_FIELD = 256
_M.MAX_STRING_FIELD = 4096
_M.MAX_BODY = 65536

-- LIST is the extensions of nginx.conf in hook order ({id, dir, sha256});
-- EXT the loaded ones by id (also failed loads: err set).
local LIST = {}
local EXT = {}
_M.EXT = EXT

local VERDICT = {}
local function verdict(kind, t)
  t = t or {}
  t[VERDICT] = kind
  return t
end

local CONTENT_TYPES = {
  js = "text/javascript; charset=utf-8", mjs = "text/javascript; charset=utf-8", css = "text/css; charset=utf-8",
  json = "application/json", svg = "image/svg+xml", png = "image/png", jpg = "image/jpeg", jpeg = "image/jpeg",
  webp = "image/webp", woff2 = "font/woff2", txt = "text/plain; charset=utf-8", html = "text/html; charset=utf-8",
}

-- Modules an extension may require besides its own (lua/<name>.lua).
local LIBRARIES = {
  ["cjson.safe"] = true, ["resty.sha256"] = true, ["resty.string"] = true, ["resty.random"] = true,
  ["resty.lrucache"] = true, ["ngx.re"] = true,
}

local function meta() return ngx.shared.edgeweir_meta end

local function shared_key(e, what)
  return "ext|" .. e.id .. "|" .. e.sha256 .. "|" .. what
end

-- Rate-limited logging of the node's own messages about an extension and
-- of ew.log: at most 10 lines per extension and second in a worker.
local function ext_log(e, level, msg)
  local now = ngx.time()
  if e.log_second ~= now then e.log_second, e.log_lines = now, 0 end
  e.log_lines = e.log_lines + 1
  if e.log_lines > 10 then return end
  ngx.log(level, "[ext ", e.id, "] ", msg)
end

local function read_file(path, max)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read(max and (max + 1) or "*a")
  f:close()
  if data and max and #data > max then return nil end
  return data
end

local function copy(t, skip)
  local out = {}
  for k, v in pairs(t) do
    if not (skip and skip[k]) then out[k] = v end
  end
  return out
end

local BASE = {
  "assert", "error", "ipairs", "next", "pairs", "pcall", "select", "tonumber", "tostring", "type", "unpack",
  "xpcall", "rawequal", "rawget", "rawset", "setmetatable",
}

-- sandbox builds the environment of an extension's code: standard
-- functions, its own modules and the allowed libraries. No ngx, io, os
-- beyond time/clock/date, debug, ffi, jit, package, bytecode, setfenv /
-- getfenv or collectgarbage. Hygiene against accidents, not a boundary.
local function sandbox(e)
  local env = {}
  for _, name in ipairs(BASE) do env[name] = _G[name] end
  env.getmetatable = function(v)
    if type(v) == "string" then return nil end
    return getmetatable(v)
  end
  env.string = copy(string, { dump = true })
  env.table = copy(table)
  env.math = copy(math)
  env.bit = copy(require("bit"))
  env.os = { time = os.time, clock = os.clock, date = os.date }
  env._G = env
  env._VERSION = _VERSION
  local loaded = {}
  env.load = function(chunk, name)
    if type(chunk) ~= "string" or byte(chunk, 1) == 27 then return nil, "only source text can be loaded" end
    return load(chunk, "=" .. e.id .. ":" .. tostring(name or "load"), "t", env)
  end
  env.require = function(name)
    if type(name) ~= "string" then error("module name must be a string", 2) end
    if LIBRARIES[name] then return require(name) end
    if loaded[name] ~= nil then return loaded[name] end
    if not name:match("^[a-z0-9_]+$") and not name:match("^[a-z0-9_]+[%.a-z0-9_]*[a-z0-9_]$") then
      error("module " .. name .. " not found", 2)
    end
    local file = "lua/" .. gsub(name, "%.", "/") .. ".lua"
    local src = read_file(e.dir .. "/" .. file)
    if not src or byte(src, 1) == 27 then error("module " .. name .. " not found", 2) end
    local fn, err = load(src, "@" .. e.id .. "/" .. file, "t", env)
    if not fn then error(err, 2) end
    loaded[name] = true
    local v = fn(name)
    if v == nil then v = true end
    loaded[name] = v
    return v
  end
  return env
end

local function set_of(list)
  local out = {}
  for _, v in ipairs(list or {}) do out[v] = true end
  return out
end

-- load_one loads an unpacked package: manifest.json and lua/main.lua.
local function load_one(spec)
  local e = { id = spec.id, dir = spec.dir, sha256 = spec.sha256, log_second = 0, log_lines = 0,
    faults = 0, window = 0, tripped = 0, inited = false }
  local raw = read_file(spec.dir .. "/manifest.json", 65536)
  local m = raw and cjson.decode(raw)
  if type(m) ~= "table" or m.id ~= spec.id then
    e.err = "manifest unreadable"
    return e
  end
  local lua_api = tonumber(type(m.requires) == "table" and m.requires.lua_api)
  if lua_api ~= 1 and lua_api ~= _M.API then
    e.err = "unsupported Lua API"
    return e
  end
  e.lua_api = lua_api
  e.version, e.manifest = m.version, m
  e.hooks, e.caps = set_of(m.hooks), set_of(m.capabilities)
  e.fields = {}
  for _, f in ipairs(m.fields or {}) do e.fields[f.name] = f.type end
  e.log_fields, e.counters = set_of(m.log_fields), set_of(m.counters)
  e.endpoints = {}
  for _, ep in ipairs(m.endpoints or {}) do
    e.endpoints[ep.path] = { methods = set_of(ep.methods), max_body = tonumber(ep.max_body) or 4096 }
  end
  e.dicts = {}
  for _, d in ipairs(m.shared_dicts or {}) do
    e.dicts[d.name] = ngx.shared["ewx_" .. gsub(e.id, ".", function(c) return format("%02x", byte(c)) end) .. "_" .. d.name]
  end
  local src = read_file(spec.dir .. "/lua/main.lua")
  if not src or byte(src, 1) == 27 then
    e.err = "lua/main.lua unreadable"
    return e
  end
  local env = sandbox(e)
  local fn, err = load(src, "@" .. e.id .. "/lua/main.lua", "t", env)
  if not fn then
    e.err = "load: " .. tostring(err)
    return e
  end
  local ok, mod = pcall(fn)
  if not ok or type(mod) ~= "table" then
    e.err = ok and "lua/main.lua must return a table" or ("load: " .. tostring(mod))
    return e
  end
  e.mod = mod
  return e
end

-- init(list): the master's list from nginx.conf (edgeweir.init).
function _M.init(list)
  LIST = {}
  if type(list) ~= "table" then return end
  for _, spec in ipairs(list) do
    if type(spec) == "table" and type(spec.id) == "string" and type(spec.dir) == "string" and type(spec.sha256) == "string" then
      LIST[#LIST + 1] = spec
    end
  end
end

-- init_worker loads every listed package in this worker.
function _M.init_worker()
  for _, spec in ipairs(LIST) do
    local ok, e = pcall(load_one, spec)
    if not ok then e = { id = spec.id, sha256 = spec.sha256, dir = spec.dir, err = "load: " .. tostring(e), log_second = 0, log_lines = 0 } end
    EXT[spec.id] = e
    if e.err then
      ngx.log(ngx.ERR, "[ext ", spec.id, "] ", e.err)
      local d = meta()
      if d then d:set(shared_key(e, "err"), e.err) end
    end
  end
end

-- compile(doc) turns the site table's extensions part into the settings by
-- id ({disabled, by_id = {id = {enabled, failure_mode, config, state}}});
-- nil without one (edgeweir.store.config).
function _M.compile(doc)
  if type(doc) ~= "table" or type(doc.list) ~= "table" then return nil end
  local out = { disabled = doc.disabled == true, by_id = {} }
  if type(doc.node) == "table" then out.node = doc.node end
  for i, x in ipairs(doc.list) do
    if type(x) == "table" and type(x.id) == "string" then
      out.by_id[x.id] = {
        order = i, enabled = x.enabled == true, closed = x.failure_mode == "closed", sha256 = x.sha256,
        config = type(x.config) == "table" and x.config or {}, state = x.state,
      }
    end
  end
  return out
end

-- prepare(s) orders a site's extensions (edgeweir.store.prepare): s._ext is
-- {{id, config}} in hook order, nil without any.
function _M.prepare(s)
  s._ext = nil
  if type(s.extensions) ~= "table" or #s.extensions == 0 then return end
  local list = {}
  for _, x in ipairs(s.extensions) do
    if type(x) == "table" and type(x.id) == "string" then
      list[#list + 1] = { id = x.id, config = type(x.config) == "table" and x.config or {} }
    end
  end
  if #list > 0 then s._ext = list end
end

-- Per-request state: ngx.ctx.edgeweir_ext = { [id] = {ew, hook, ctx} },
-- edgeweir_ext_fields (rule fields), edgeweir_ext_log (log fields),
-- edgeweir_ext_counts (counters by stats name), edgeweir_ext_inject.

local function req_state(id)
  local ctx = ngx.ctx
  local all = ctx.edgeweir_ext
  if not all then all = {}; ctx.edgeweir_ext = all end
  local st = all[id]
  if not st then st = {}; all[id] = st end
  return st
end

local function current_hook(e)
  local st = ngx.ctx.edgeweir_ext
  st = st and st[e.id]
  return st and st.hook
end

local function need(e, cap)
  if not e.caps[cap] then error("capability " .. cap .. " not declared", 3) end
end

local function in_hooks(e, list)
  local hook = current_hook(e)
  for i = 1, #list do
    if hook == list[i] then return hook end
  end
  error("not allowed in hook " .. tostring(hook), 3)
end

local function count(name, n)
  local ctx = ngx.ctx
  local counts = ctx.edgeweir_ext_counts
  if not counts then counts = {}; ctx.edgeweir_ext_counts = counts end
  counts[name] = (counts[name] or 0) + n
end

local function header_value(v)
  if type(v) == "table" then return concat(v, ", ") end
  return v
end

local function valid_header(name, value)
  if type(name) ~= "string" or not name:match("^[%w!#$%%&'*+.^_`|~-]+$") then error("invalid header name", 3) end
  if value ~= nil and (type(value) ~= "string" or find(value, "[\r\n%z]")) then error("invalid header value", 3) end
  local l = lower(name)
  if sub(l, 1, 11) == "x-edgeweir-" or l == "content-length" or l == "transfer-encoding" or l == "connection" then
    error("header " .. name .. " is reserved", 3)
  end
end

local function attr(s)
  return (gsub(s, "[&\"<>]", { ["&"] = "&amp;", ['"'] = "&quot;", ["<"] = "&lt;", [">"] = "&gt;" }))
end

-- csp_script returns how a script may be injected under the response's
-- Content-Security-Policy headers: true (as is), a nonce, or false.
function _M.csp_script(policies, src)
  if policies == nil then return true end
  if type(policies) ~= "table" then policies = { policies } end
  local nonce
  for _, policy in ipairs(policies) do
    local directives = {}
    for d in (policy .. ";"):gmatch("([^;]*);") do
      local name, value = d:match("^%s*([%w-]+)%s*(.-)%s*$")
      if name then
        name = lower(name)
        if directives[name] == nil then directives[name] = " " .. value .. " " end
      end
    end
    local list = directives["script-src"] or directives["default-src"]
    if list then
      local n = list:match("%s'nonce%-([%w+/=_-]+)'%s")
      if n then
        if nonce and nonce ~= n then return false end
        nonce = n
      elseif not (src and find(list, "%s'self'%s") and not find(lower(list), "'strict-dynamic'", 1, true)) then
        return false
      end
    end
  end
  return nonce or true
end

-- client_geo is the client's GeoIP record: looked up (softly) in the
-- request phases, the worker's cache in the response phases (they cannot
-- yield).
local function client_geo()
  local geo = ngx.ctx.edgeweir_geo
  if geo then return geo end
  local geoip = require("edgeweir.geoip")
  local addr = ngx.var.remote_addr
  local phase = ngx.get_phase()
  if phase == "access" or phase == "timer" then return geoip.lookup(addr, true) end
  return geoip.peek(addr)
end

local function queue_html(position, html)
  local ctx = ngx.ctx
  local q = ctx.edgeweir_ext_inject
  if not q then q = { head_end = {}, body_end = {} }; ctx.edgeweir_ext_inject = q end
  local list = q[position]
  list[#list + 1] = html
end

-- api builds an extension's API object, shared by its requests; ew()
-- gives each request its own table that reads through to it.
-- upstream_last returns the last value of an upstream variable listing
-- every origin attempt ("502, 200" or "x : y"), nil without one.
local function upstream_last(v)
  if v == nil or v == "" then return nil end
  local last = v:match("([^,:%s]+)%s*$")
  if last == nil or last == "-" then return nil end
  return last
end

local HTTP_VERSIONS = { [1.0] = "1.0", [1.1] = "1.1", [2.0] = "2", [3.0] = "3" }

-- api2 adds the calls of Lua API 2 to a (extension version 1.1).
local function api2(e, a)
  local var = function(name) return ngx.var[name] end
  local function num(name) return tonumber(var(name)) end
  a.req.http_version = function() return HTTP_VERSIONS[ngx.req.http_version()] or "" end
  a.req.request_length = function()
    in_hooks(e, { "log" })
    return num("request_length")
  end
  a.req.request_time = function()
    in_hooks(e, { "log" })
    return num("request_time")
  end
  a.req.verified_bot = function()
    in_hooks(e, { "access", "access_late" })
    ngx.update_time()
    local started = ngx.now()
    local ok, verified, name = pcall(require("edgeweir.bots").request)
    ngx.update_time()
    local st = req_state(e.id)
    st.excluded = (st.excluded or 0) + (ngx.now() - started)
    if ok and verified then return name end
    return nil
  end
  a.req.exempt = function()
    in_hooks(e, { "access", "access_late" })
    local site, addr = ngx.ctx.edgeweir_site, var("remote_addr")
    if not site then return false end
    return require("edgeweir.router").platform_allowed(site, addr) or require("edgeweir.access").site_allowed(site, addr)
  end
  a.resp.bytes_sent = function()
    in_hooks(e, { "log" })
    return num("bytes_sent")
  end
  for _, name in ipairs({ "response_time", "connect_time", "header_time" }) do
    a.resp["upstream_" .. name] = function()
      in_hooks(e, { "log" })
      return tonumber(upstream_last(var("upstream_" .. name)))
    end
  end
  a.resp.upstream_status = function()
    in_hooks(e, { "log" })
    return tonumber(upstream_last(var("upstream_status")))
  end
  a.resp.reason = function()
    local reason, rule = require("edgeweir.reasons").get()
    return reason or "", rule or ""
  end
  local function node()
    local x = require("edgeweir.store").config().extensions
    return x and x.node or {}
  end
  a.node = {
    id = function() return node().id or "" end,
    name = function() return node().name or "" end,
    cluster_id = function() return node().cluster_id or "" end,
    version = function() return node().version or "" end,
    connections = function()
      if current_hook(e) == "timer" then return nil end
      return { active = num("connections_active") or 0, reading = num("connections_reading") or 0,
        writing = num("connections_writing") or 0, waiting = num("connections_waiting") or 0 }
    end,
    status = function()
      local d = meta()
      local raw = d and d:get("ext_node_status")
      return raw and cjson.decode(raw) or nil
    end,
  }
  a.equal = function(x, y)
    if type(x) ~= "string" or type(y) ~= "string" then error("equal takes strings", 2) end
    -- Constant time in the content; the length is not secret.
    if #x ~= #y then return false end
    local bit = require("bit")
    local diff = 0
    for i = 1, #x do diff = bit.bor(diff, bit.bxor(byte(x, i), byte(y, i))) end
    return diff == 0
  end
end

local function api(e)
  local a = { id = e.id, version = e.version, api = e.lua_api or 1 }
  local var = function(name) return ngx.var[name] end

  a.req = {
    method = function() return ngx.req.get_method() end,
    host = function() return var("host") end,
    path = function() return var("uri") end,
    query = function() return var("args") or "" end,
    uri = function() return var("request_uri") end,
    scheme = function() return var("scheme") end,
    header = function(name) return header_value(ngx.req.get_headers(0)[name]) end,
    headers = function()
      local out = {}
      for k, v in pairs(ngx.req.get_headers(0)) do out[k] = header_value(v) end
      return out
    end,
    cookie = function(name)
      if type(name) ~= "string" or not name:match("^[%w!#$%%&'*+.^_`|~-]+$") then return nil end
      return var("cookie_" .. name)
    end,
    arg = function(name)
      local v = ngx.req.get_uri_args(100)[name]
      if type(v) == "table" then v = v[1] end
      if v == true then v = "" end
      return v
    end,
    client_ip = function() return var("remote_addr") end,
    country = function()
      local geo = client_geo()
      return geo and geo.country or ""
    end,
    asn = function()
      local geo = client_geo()
      return geo and geo.asnum or 0
    end,
    ja4 = function() return require("edgeweir.ja4").value() end,
    request_id = function() return var("edgeweir_request_id") or var("request_id") end,
    pass_level = function()
      local site = ngx.ctx.edgeweir_site
      return site and require("edgeweir.challenge").pass_level(site) or 0
    end,
    body = function()
      need(e, "request_body")
      local hook = in_hooks(e, { "access", "access_late", "endpoint" })
      local limit = _M.MAX_BODY
      if hook == "endpoint" then limit = req_state(e.id).max_body or 0 end
      local len = tonumber(var("http_content_length"))
      if not len or len > limit then return nil, "truncated" end
      if len == 0 then return "" end
      ngx.req.read_body()
      local data = ngx.req.get_body_data()
      if not data then return nil, "truncated" end
      return data
    end,
    set_header = function(name, value)
      need(e, "request_headers")
      in_hooks(e, { "access", "access_late" })
      valid_header(name, value)
      ngx.req.set_header(name, value)
    end,
    clear_header = function(name)
      need(e, "request_headers")
      in_hooks(e, { "access", "access_late" })
      valid_header(name)
      ngx.req.clear_header(name)
    end,
  }

  a.resp = {
    status = function() return ngx.status end,
    header = function(name) return header_value(ngx.header[name]) end,
    content_type = function() return header_value(ngx.header["Content-Type"]) end,
    cache_status = function() return var("upstream_cache_status") or "" end,
    set_header = function(name, value)
      need(e, "response_headers")
      in_hooks(e, { "header_filter" })
      valid_header(name, value)
      ngx.header[name] = value
    end,
    add_header = function(name, value)
      need(e, "response_headers")
      in_hooks(e, { "header_filter" })
      valid_header(name, value)
      local old = ngx.header[name]
      if old == nil then
        ngx.header[name] = value
      elseif type(old) == "table" then
        old[#old + 1] = value
        ngx.header[name] = old
      else
        ngx.header[name] = { old, value }
      end
    end,
    clear_header = function(name)
      need(e, "response_headers")
      in_hooks(e, { "header_filter" })
      valid_header(name)
      ngx.header[name] = nil
    end,
  }

  local function injected_bytes(n)
    local st = req_state(e.id)
    st.injected = (st.injected or 0) + n
    if st.injected > _M.MAX_INJECT then error("more than 8 KiB of HTML injected", 3) end
  end
  a.html = {
    inject = function(position, html)
      need(e, "html_inject")
      in_hooks(e, { "header_filter" })
      if position ~= "head_end" and position ~= "body_end" then error("invalid position", 2) end
      if type(html) ~= "string" then error("html must be a string", 2) end
      injected_bytes(#html)
      queue_html(position, html)
      return true
    end,
    script = function(opts)
      need(e, "html_inject")
      in_hooks(e, { "header_filter" })
      if type(opts) ~= "table" or (opts.src == nil) == (opts.inline == nil) then error("script needs src or inline", 2) end
      local src, inline = opts.src, opts.inline
      if src ~= nil and (type(src) ~= "string" or find(src, "[%c]")) then error("invalid src", 2) end
      if inline ~= nil and (type(inline) ~= "string" or find(lower(inline), "</script", 1, true)) then error("invalid inline script", 2) end
      if opts.type ~= nil and (type(opts.type) ~= "string" or not opts.type:match("^[%w/+.-]+$")) then error("invalid type", 2) end
      local same_origin = src and sub(src, 1, 1) == "/" and sub(src, 2, 2) ~= "/"
      local allowed = _M.csp_script(ngx.header["Content-Security-Policy"], same_origin)
      if allowed == false or (inline and allowed == true and ngx.header["Content-Security-Policy"] ~= nil) then
        return false
      end
      local parts = { "<script" }
      if opts.type then parts[#parts + 1] = ' type="' .. attr(opts.type) .. '"' end
      if type(allowed) == "string" then parts[#parts + 1] = ' nonce="' .. attr(allowed) .. '"' end
      if src then parts[#parts + 1] = ' src="' .. attr(src) .. '"' end
      if opts.defer then parts[#parts + 1] = " defer" end
      if opts.async then parts[#parts + 1] = " async" end
      parts[#parts + 1] = ">" .. (inline or "") .. "</script>"
      local html = concat(parts)
      injected_bytes(#html)
      queue_html("head_end", html)
      return true
    end,
  }

  a.field = function(name, value)
    in_hooks(e, { "access" })
    local typ = e.fields[name]
    if not typ then error("field " .. tostring(name) .. " not declared", 2) end
    if type(value) ~= typ or (typ == "number" and (value ~= value or value == math.huge or value == -math.huge)) then
      error("field " .. name .. " must be a " .. typ, 2)
    end
    if typ == "string" and #value > _M.MAX_STRING_FIELD then error("field " .. name .. " is too long", 2) end
    local ctx = ngx.ctx
    local fields = ctx.edgeweir_ext_fields
    if not fields then fields = {}; ctx.edgeweir_ext_fields = fields end
    fields["ext." .. e.id .. "." .. name] = value
  end
  a.log_field = function(name, value)
    if not e.log_fields[name] then error("log field " .. tostring(name) .. " not declared", 2) end
    if type(value) == "number" or type(value) == "boolean" then value = tostring(value) end
    if type(value) ~= "string" then error("log field " .. name .. " must be a string", 2) end
    if #value > _M.MAX_LOG_FIELD then value = sub(value, 1, _M.MAX_LOG_FIELD) end
    local ctx = ngx.ctx
    local log = ctx.edgeweir_ext_log
    if not log then log = {}; ctx.edgeweir_ext_log = log end
    log["ext." .. e.id .. "." .. name] = value
  end
  a.count = function(name, n)
    if not e.counters[name] then error("counter " .. tostring(name) .. " not declared", 2) end
    n = n == nil and 1 or n
    if type(n) ~= "number" or n < 0 or n ~= n or n == math.huge or n % 1 ~= 0 then error("invalid count", 2) end
    if current_hook(e) == "timer" then return end
    count(e.id .. "." .. name, n)
  end
  a.shared = function(name)
    local d = e.dicts[name]
    if not d then error("shared dict " .. tostring(name) .. " not declared", 2) end
    return d
  end
  local LEVELS = { err = ngx.ERR, warn = ngx.WARN, info = ngx.INFO }
  a.log = function(level, ...)
    local l = LEVELS[level]
    if not l then error("invalid log level", 2) end
    local parts = { ... }
    for i = 1, select("#", ...) do parts[i] = tostring(parts[i]) end
    ext_log(e, l, concat(parts, " "))
  end

  a.now = function() return ngx.now() end
  a.sha256 = function(s)
    local h = require("resty.sha256"):new()
    h:update(s)
    return h:final()
  end
  a.hmac_sha256 = function(key, s) return _M.hmac_sha256(key, s) end
  a.random_bytes = function(n)
    if type(n) ~= "number" or n < 1 or n > 1024 then error("invalid length", 2) end
    return require("resty.random").bytes(n, true)
  end
  a.b64url_encode = function(s) return (gsub(ngx.encode_base64(s), "[+/=]", { ["+"] = "-", ["/"] = "_", ["="] = "" })) end
  a.b64url_decode = function(s)
    if type(s) ~= "string" then return nil end
    s = gsub(s, "[-_]", { ["-"] = "+", ["_"] = "/" })
    local pad = #s % 4
    if pad == 1 then return nil end
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
  end
  a.json_encode = function(v) return cjson.encode(v) end
  a.json_decode = function(s) return cjson.decode(s) end
  a.tcp = function()
    need(e, "http_client")
    in_hooks(e, { "access", "access_late", "endpoint", "timer" })
    return ngx.socket.tcp()
  end
  a.timer = function(delay, fn)
    need(e, "timers")
    in_hooks(e, { "init", "timer" })
    if type(delay) ~= "number" or delay < 0 or type(fn) ~= "function" then error("invalid timer", 2) end
    return ngx.timer.at(delay, function(premature)
      if premature then return end
      local st = req_state(e.id)
      st.hook = "timer"
      local ew = setmetatable({ global_config = e.global_config, ctx = {} }, { __index = a })
      ngx.update_time()
      local started = ngx.now()
      local ok, err = pcall(fn, ew)
      ngx.update_time()
      if not ok then
        _M.fault(e, nil, "timer: " .. tostring(err))
      elseif ngx.now() - started > (e.caps.http_client and _M.IO_BUDGET or _M.BUDGET) then
        _M.fault(e, nil, "timer over its budget")
      end
    end)
  end

  a.deny = function(status)
    need(e, "verdicts")
    status = status == nil and 403 or status
    if type(status) ~= "number" or status < 400 or status > 499 or status % 1 ~= 0 then error("deny status must be 400-499", 2) end
    return verdict("deny", { status = status })
  end
  a.challenge = function(level)
    need(e, "verdicts")
    local challenge = require("edgeweir.challenge")
    if not challenge.LEVELS[level] then error("invalid challenge level", 2) end
    return verdict("challenge", { kind = level, level = challenge.LEVELS[level] })
  end
  a.allow = function()
    need(e, "verdicts")
    return verdict("allow")
  end
  a.respond = function(status, body, headers)
    if current_hook(e) ~= "endpoint" then need(e, "verdicts") end
    if type(status) ~= "number" or status < 200 or status > 599 or status % 1 ~= 0 then error("invalid status", 2) end
    if body ~= nil and type(body) ~= "string" then error("body must be a string", 2) end
    if headers ~= nil then
      if type(headers) ~= "table" then error("headers must be a table", 2) end
      for k, v in pairs(headers) do valid_header(k, v) end
    end
    return verdict("respond", { status = status, body = body, headers = headers })
  end
  if (e.lua_api or 1) >= 2 then api2(e, a) end
  return a
end

function _M.hmac_sha256(key, s)
  if type(key) ~= "string" or type(s) ~= "string" then error("hmac_sha256 takes strings", 2) end
  local sha = require("resty.sha256")
  if #key > 64 then
    local h = sha:new(); h:update(key); key = h:final()
  end
  key = key .. string.rep("\0", 64 - #key)
  local bxor = require("bit").bxor
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local b = byte(key, i)
    ipad[i] = string.char(bxor(b, 0x36))
    opad[i] = string.char(bxor(b, 0x5c))
  end
  local inner = sha:new(); inner:update(concat(ipad)); inner:update(s)
  local outer = sha:new(); outer:update(concat(opad)); outer:update(inner:final())
  return outer:final()
end

-- fault records a failing hook call: logged, counted for the site's minute
-- (site_id: nil outside requests) and across workers, and trips the
-- extension in this worker after MAX_FAULTS within FAULT_WINDOW.
function _M.fault(e, site_id, msg)
  ext_log(e, ngx.ERR, msg)
  local d = meta()
  if d then d:incr(shared_key(e, "faults"), 1, 0) end
  if site_id then count(e.id .. ".faults", 1) end
  local now = ngx.now()
  if now - e.window > _M.FAULT_WINDOW then e.window, e.faults = now, 0 end
  e.faults = e.faults + 1
  if e.faults >= _M.MAX_FAULTS and e.tripped <= now then
    e.tripped = now + _M.TRIP_SECONDS
    e.faults = 0
    ext_log(e, ngx.ERR, "tripped for " .. _M.TRIP_SECONDS .. " seconds after " .. _M.MAX_FAULTS .. " faults")
    if d then d:incr(shared_key(e, "trips"), 1, 0) end
  end
end

-- settings returns the cluster's settings of extension id (nil: unknown
-- or the kill switch is on).
local function settings(id)
  local cfg = require("edgeweir.store").config()
  local x = cfg.extensions
  if not x or x.disabled then return nil end
  return x.by_id[id]
end

-- usable returns the loaded extension and its settings when it should run
-- on this request; else nil and whether that fails closed.
local function usable(id)
  local set = settings(id)
  if not set or not set.enabled then return nil, nil, false end
  local e = EXT[id]
  if not e or e.err or not e.mod or e.sha256 ~= set.sha256 then return nil, set, set.closed end
  if e.tripped > ngx.now() then return nil, set, set.closed end
  return e, set, false
end

-- call runs hook of e with args under pcall and the budget; returns ok and
-- the hook's first result.
local function call(e, set, site, hook, ...)
  local fn = e.mod[hook]
  if type(fn) ~= "function" then return true, nil end
  local st = req_state(e.id)
  local ew = st.ew
  if not ew or st.site ~= site then
    ew = setmetatable({ site_id = site and site.id, ctx = st.ctx or {} }, { __index = e.api })
    if (e.lua_api or 1) >= 2 then
      local d = site and type(site.domains) == "table" and site.domains[1]
      ew.site_name = type(d) == "table" and d.name or nil
    end
    st.ctx, st.ew, st.site = ew.ctx, ew, site
  end
  ew.global_config = set.config
  e.global_config = set.config
  ew.site_config = st.site_config
  local previous, excluded = st.hook, st.excluded
  st.hook, st.excluded = hook, 0
  ngx.update_time()
  local started = ngx.now()
  local ok, res = pcall(fn, ew, ...)
  -- Time spent waiting for a verified crawler's DNS does not count.
  started = started + (st.excluded or 0)
  st.hook, st.excluded = previous, excluded
  ngx.update_time()
  if not ok then
    _M.fault(e, site and site.id, hook .. ": " .. tostring(res))
    return false
  end
  local io = e.caps.http_client and (hook == "access" or hook == "access_late" or hook == "endpoint")
  if ngx.now() - started > (io and _M.IO_BUDGET or _M.BUDGET) then
    _M.fault(e, site and site.id, hook .. " over its budget")
    return false
  end
  return true, res
end

-- ensure_init runs an extension's init hook once per worker, on first use.
local function ensure_init(e, set)
  if e.inited then return true end
  e.inited = true
  e.api = e.api or api(e)
  if type(e.mod.init) ~= "function" then return true end
  local ok = call(e, set, nil, "init")
  if not ok then
    e.err = "init failed"
    local d = meta()
    if d then d:set(shared_key(e, "err"), e.err) end
  end
  return ok
end

local function unavailable()
  ngx.status = 503
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = "extension"
  ngx.print("extension unavailable\n")
  return ngx.exit(ngx.HTTP_OK)
end

local function respond(v)
  ngx.status = v.status
  local has_cc = false
  if v.headers then
    for k, val in pairs(v.headers) do
      ngx.header[k] = val
      if lower(k) == "cache-control" then has_cc = true end
    end
  end
  if not has_cc then ngx.header["Cache-Control"] = "no-store" end
  if v.body and ngx.req.get_method() ~= "HEAD" then ngx.print(v.body) end
  return ngx.exit(ngx.HTTP_OK)
end
_M.respond = respond

-- each calls fn(e, set, site_ext) for the site's extensions that run, in
-- hook order, until fn returns something. request: the request hooks,
-- where an extension that fails closed and cannot run ends it ("closed");
-- the response hooks skip it.
local function each(site, fn, request)
  local list = site._ext
  if not list then return end
  for i = 1, #list do
    local x = list[i]
    local e, set, closed = usable(x.id)
    if e then
      if ensure_init(e, set) then
        req_state(x.id).site_config = x.config
        local r = fn(e, set, x)
        if r ~= nil then return r end
      elseif request and set.closed then
        return "closed"
      end
    elseif request and closed then
      return "closed"
    end
  end
end

local function log_verdict(id, kind)
  local ctx = ngx.ctx
  local log = ctx.edgeweir_ext_log
  if not log then log = {}; ctx.edgeweir_ext_log = log end
  log["ext." .. id .. ".verdict"] = kind
end

-- request_hook runs access or access_late; returns the first verdict as
-- {kind, id, ...}, "closed" for a failing extension that fails closed, or
-- nil.
local function request_hook(site, hook)
  return each(site, function(e, set)
    if not e.hooks[hook] then return nil end
    local ok, res = call(e, set, site, hook)
    if not ok then return set.closed and "closed" or nil end
    local kind = type(res) == "table" and res[VERDICT]
    if not kind then return nil end
    if kind == "allow" and hook ~= "access" then
      _M.fault(e, site.id, "access_late: allow is an access verdict")
      return set.closed and "closed" or nil
    end
    log_verdict(e.id, kind)
    res.id = e.id
    return res
  end, true)
end

-- access(site) runs the access hooks: nil to continue, true when the
-- extensions answered (deny, challenge without a pass, respond, closed),
-- "allow" for an allow verdict.
function _M.access(site, run_challenge, deny)
  return _M.verdict(site, request_hook(site, "access"), run_challenge, deny)
end

function _M.access_late(site, run_challenge, deny)
  return _M.verdict(site, request_hook(site, "access_late"), run_challenge, deny)
end

-- verdict acts on a hook's verdict (router helpers run_challenge and deny).
function _M.verdict(site, v, run_challenge, deny)
  if v == nil then return nil end
  if v == "closed" then
    reasons.set("extension")
    return true, deny(503, "extension", "extension unavailable")
  end
  local kind = v[VERDICT]
  if kind == "allow" then return "allow" end
  local rule = "ext:" .. v.id
  if kind == "deny" then
    reasons.set("extension", rule)
    return true, deny(v.status, "extension-denied", "request denied")
  end
  if kind == "challenge" then
    if require("edgeweir.challenge").pass_level(site) >= v.level then return nil end
    return true, run_challenge(site, v.kind, v.level, rule)
  end
  if kind == "respond" then return true, respond(v) end
end

-- ASSET_PATH accepts assets/<segments> without dot segments.
local function asset_path(rest)
  if #rest > 200 or find(rest, "//", 1, true) then return nil end
  for seg in rest:gmatch("[^/]+") do
    if not seg:match("^[%w_-][%w._-]*$") then return nil end
  end
  return rest
end

local assets_cache
local function asset(e, rel)
  if not assets_cache then assets_cache = require("resty.lrucache").new(128) end
  local key = e.sha256 .. "/" .. rel
  local hit = assets_cache:get(key)
  if hit then return hit end
  local data = read_file(e.dir .. "/assets/" .. rel, 4 * 1024 * 1024)
  if not data then return nil end
  local h = require("resty.sha256"):new()
  h:update(data)
  local ext = lower(rel:match("%.([%w]+)$") or "")
  hit = { data = data, etag = '"' .. require("resty.string").to_hex(h:final()):sub(1, 32) .. '"',
    type = CONTENT_TYPES[ext] or "application/octet-stream" }
  assets_cache:set(key, hit)
  return hit
end

local function plain(status, msg)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.print(msg, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- endpoint(site, path) answers /.edgeweir/ext/<id>/<rest>: the package's
-- assets and its declared endpoints, on sites that enable it.
function _M.endpoint(site, path)
  local id, rest = path:match("^/%.edgeweir/ext/([a-z][a-z0-9-]*)/(.*)$")
  local x
  if id and site._ext then
    for _, s in ipairs(site._ext) do
      if s.id == id then x = s; break end
    end
  end
  if not x then return plain(404, "not found") end
  local e, set, closed = usable(id)
  if not e then
    if closed then reasons.set("extension"); return unavailable() end
    return plain(404, "not found")
  end
  local method = ngx.req.get_method()
  if sub(rest, 1, 7) == "assets/" then
    local rel = asset_path(sub(rest, 8))
    local a = rel and asset(e, rel)
    if not a then return plain(404, "not found") end
    if method ~= "GET" and method ~= "HEAD" then return plain(405, "method not allowed") end
    ngx.header["Content-Type"] = a.type
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Cache-Control"] = "public, max-age=3600"
    ngx.header["ETag"] = a.etag
    if ngx.var.http_if_none_match == a.etag then
      ngx.status = 304
      return ngx.exit(ngx.HTTP_OK)
    end
    ngx.header["Content-Length"] = #a.data
    if method == "GET" then ngx.print(a.data) end
    return ngx.exit(ngx.HTTP_OK)
  end
  local ep = e.endpoints[rest]
  if not ep or not e.hooks.endpoint then return plain(404, "not found") end
  if not ep.methods[method] then
    ngx.header["Allow"] = (function()
      local m = {}
      for k in pairs(ep.methods) do m[#m + 1] = k end
      table.sort(m)
      return concat(m, ", ")
    end)()
    return plain(405, "method not allowed")
  end
  local len = tonumber(ngx.var.http_content_length)
  if (len and len > ep.max_body) or (not len and ngx.var.http_transfer_encoding) then
    return plain(413, "request body too large")
  end
  if not ensure_init(e, set) then
    if set.closed then reasons.set("extension"); return unavailable() end
    return plain(404, "not found")
  end
  local st = req_state(id)
  st.site_config, st.max_body = x.config, ep.max_body
  local ok, res = call(e, set, site, "endpoint", rest)
  if not ok then
    if set.closed then reasons.set("extension"); return unavailable() end
    return plain(500, "extension failed")
  end
  if type(res) == "table" and res[VERDICT] == "respond" then return respond(res) end
  return plain(500, "extension returned no response")
end

-- header_filter runs the header filter hooks and prepares the body filter
-- (HTML injection, body rewrites) of responses of enabled sites; not for
-- subrequests or the reserved prefix.
function _M.header_filter(site)
  if ngx.is_subrequest then return end
  local ctx = ngx.ctx
  local path = ctx.edgeweir_original_path or ngx.var.uri
  if sub(path or "", 1, 11) == "/.edgeweir/" then return end
  local rewrite = false
  each(site, function(e, set)
    if e.hooks.body_filter then rewrite = true end
    if e.hooks.header_filter then call(e, set, site, "header_filter") end
    return nil
  end)
  local q = ctx.edgeweir_ext_inject
  ctx.edgeweir_ext_inject = nil
  local inject = q and (#q.head_end > 0 or #q.body_end > 0) and _M.injectable(ngx.req.get_method(), ngx.status, ngx.header)
  if inject or rewrite then
    local h = ngx.header
    h["Content-Length"] = nil
    local etag = h["ETag"]
    if type(etag) == "string" and sub(etag, 1, 2) ~= "W/" then h["ETag"] = "W/" .. etag end
    local head = inject and concat(q.head_end) or ""
    ctx.edgeweir_ext_body = { rewrite = rewrite, head = head, tail = inject and concat(q.body_end) or "",
      scanned = head == "", buf = {}, size = 0, held = "" }
  end
end

-- injectable reports whether HTML may be injected into the response.
function _M.injectable(method, status, h)
  if method ~= "GET" or status ~= 200 then return false end
  local ct = header_value(h["Content-Type"])
  if type(ct) ~= "string" or not lower(ct):match("^%s*text/html") then return false end
  if h["Content-Encoding"] or h["Content-Range"] then return false end
  local cc = header_value(h["Cache-Control"])
  if cc and find(lower(cc), "no-transform", 1, true) then return false end
  return true
end

-- find_ci finds the first (last: true, the last) case-insensitive tag in s.
local function find_tag(s, tag, last)
  local l = lower(s)
  if not last then return (find(l, tag, 1, true)) end
  local pos, at = 1, nil
  while true do
    local i = find(l, tag, pos, true)
    if not i then return at end
    at, pos = i, i + 1
  end
end
_M.find_tag = find_tag

-- inject(state, chunk, eof) is the injection over the body: the head part
-- before the first </head> within HEAD_SCAN bytes (else merged into the
-- tail part), the tail part before the last </body> in the final TAIL
-- bytes (else appended). Returns the bytes to send now.
function _M.inject(st, chunk, eof)
  local out = {}
  if not st.scanned then
    st.buf[#st.buf + 1] = chunk
    st.size = st.size + #chunk
    local data = concat(st.buf)
    local at = find_tag(data, "</head>")
    if at then
      out[1] = sub(data, 1, at - 1) .. st.head
      chunk = sub(data, at)
      st.scanned = true
    elseif st.size >= _M.HEAD_SCAN or eof then
      st.tail = st.head .. st.tail
      chunk = data
      st.scanned = true
    else
      st.buf = { data }
      return ""
    end
    st.buf = nil
  end
  if st.tail == "" then
    out[#out + 1] = chunk
    return concat(out)
  end
  local data = st.held .. chunk
  if not eof then
    if #data > _M.TAIL then
      out[#out + 1] = sub(data, 1, #data - _M.TAIL)
      st.held = sub(data, #data - _M.TAIL + 1)
    else
      st.held = data
    end
    return concat(out)
  end
  local at = find_tag(data, "</body", true)
  if at then
    out[#out + 1] = sub(data, 1, at - 1) .. st.tail .. sub(data, at)
  else
    out[#out + 1] = data .. st.tail
  end
  st.held = ""
  return concat(out)
end

-- body_filter runs the body filter hooks (body_rewrite) and the injection.
function _M.body_filter()
  local ctx = ngx.ctx
  local st = ctx.edgeweir_ext_body
  if not st then return end
  local chunk, eof = ngx.arg[1] or "", ngx.arg[2]
  local site = ctx.edgeweir_site
  if st.rewrite and site then
    each(site, function(e, set)
      if not e.hooks.body_filter or not e.caps.body_rewrite then return nil end
      local ok, res = call(e, set, site, "body_filter", chunk, eof)
      if ok and type(res) == "string" then chunk = res end
      return nil
    end)
  end
  if st.head ~= "" or st.tail ~= "" then
    chunk = _M.inject(st, chunk, eof)
  end
  ngx.arg[1] = chunk
end

-- log runs the log hooks (edgeweir.stats, before the access log).
function _M.log(site)
  -- ngx.is_subrequest raises outside a request (the Lua tests' timers).
  if ngx.get_phase() ~= "timer" and ngx.is_subrequest then return end
  each(site, function(e, set)
    if e.hooks.log then call(e, set, site, "log") end
    return nil
  end)
end

-- status is GET /v1/extensions: by id, the package this worker loaded, a
-- load error and the fault and trip counters of all workers.
function _M.status()
  local out = {}
  local d = meta()
  for _, spec in ipairs(LIST) do
    local key = function(what) return "ext|" .. spec.id .. "|" .. spec.sha256 .. "|" .. what end
    out[spec.id] = {
      sha256 = spec.sha256,
      error = (EXT[spec.id] and EXT[spec.id].err) or (d and d:get(key("err"))) or "",
      faults = d and d:get(key("faults")) or 0,
      trips = d and d:get(key("trips")) or 0,
    }
  end
  return out
end

return _M
