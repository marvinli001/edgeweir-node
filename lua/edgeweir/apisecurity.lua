local json = require("cjson.safe")
local auth = require("edgeweir.auth")
local uripath = require("edgeweir.uripath")
local body = require("edgeweir.body")

local M = { socket = "", TIMEOUT = 250, MAX_BODY = 131072 }
local sub, lower, find = string.sub, string.lower, string.find

local words = {}
for word in string.gmatch("api v1 v2 v3 v4 graphql query users user accounts account profile profiles auth login logout token tokens oauth sessions session orders order products product items item posts post comments comment search health status metrics events event files file upload uploads download downloads admin public private internal webhooks webhook me settings billing payments payment organizations organization teams team projects project resources resource reports report notifications notification assets static content data rest rpc", "%S+") do words[word] = true end

local function array(t)
  if #t == 0 and json.empty_array then return json.empty_array end
  return setmetatable(t, json.array_mt)
end

function M.discover(path)
  local segments = {}
  for segment in string.gmatch(path or "", "[^/]+") do
    local n = #segments + 1
    if n > 20 then return "/{segment1}" end
    segments[n] = words[segment] and segment or "{segment" .. n .. "}"
  end
  local out = "/" .. table.concat(segments, "/")
  if out ~= "/" and sub(path or "", -1) == "/" then out = out .. "/" end
  return out
end

local function prefix_pattern(prefix)
  local p = prefix:gsub("{[A-Za-z][A-Za-z0-9_]*}", "\1")
  p = p:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
  return "^" .. p:gsub("\1", "[^/]+")
end

function M.prepare(site)
  local settings = site.api_security
  site._api, site._api_jwt, site._api_graphql = nil, nil, nil
  if type(settings) ~= "table" then return end
  site._api = settings.discovery.enabled or settings.schema.mode ~= "off" or settings.jwt.mode ~= "off" or settings.graphql.mode ~= "off"
  if settings.jwt.mode ~= "off" then
    local scope = settings.jwt.scope
    local holder = { auth_rules = { { id = "api-jwt", kind = "jwt", domains = scope.domains,
      path_prefixes = scope.pathPrefixes, extensions = scope.extensions, exclude_path_prefixes = scope.excludePathPrefixes } } }
    auth.prepare(holder)
    site._api_jwt = holder._auth[1]
  end
  if settings.graphql.mode ~= "off" then
    local patterns = {}
    for i, p in ipairs(settings.graphql.pathPrefixes) do patterns[i] = prefix_pattern(p) end
    site._api_graphql = patterns
  end
end

function M.endpoint(site, method, path)
  for _, e in ipairs(site.api_security.schema.endpoints) do
    if e.method == method and string.match(path, prefix_pattern(e.path) .. "$") then return true end
  end
  return false
end

-- Take the visitor's headers before access authentication can remove
-- Authorization or replace identity headers.
function M.capture(site, headers)
  if not site._api then return end
  local saved, bytes, count, truncated = {}, 0, 0, false
  for name, values in pairs(headers) do
    count = count + 1
    bytes = bytes + #name
    local lines = type(values) == "table" and values or { values }
    local copy = {}
    for _, value in ipairs(lines) do
      bytes = bytes + #value
      if bytes <= 32768 and count <= 200 then copy[#copy + 1] = value else truncated = true end
    end
    if #copy > 0 then saved[lower(name)] = array(copy) else truncated = true end
  end
  ngx.ctx.edgeweir_api_request = { headers = saved, authorization = saved.authorization, headers_truncated = truncated }
end

function M.selected(site)
  local var = ngx.var
  local raw = uripath.raw_path(var.request_uri or var.uri or "/")
  local ambiguous = uripath.no_exemption(raw)
  local jwt = site._api_jwt and auth.in_scope(site._api_jwt, var.host, var.uri, ambiguous, ambiguous) or false
  local graphql = false
  if site._api_graphql then
    graphql = ambiguous
    for _, p in ipairs(site._api_graphql) do if string.match(var.uri, p) then graphql = true; break end end
  end
  return jwt, graphql, ambiguous, raw
end

local function read_body()
  local var = ngx.var
  local decision = body.decide(M.MAX_BODY, var.http_content_length, var.http_transfer_encoding, ngx.req.http_version(), false)
  if decision == "empty" then return "", false end
  if decision ~= "read" then return "", true end
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if not data then
    local name = ngx.req.get_body_file()
    if name then
      local f = io.open(name, "rb")
      if not f then return "", true end
      data = f:read(M.MAX_BODY + 1)
      f:close()
    else data = "" end
  end
  if type(data) ~= "string" or #data > M.MAX_BODY then return "", true end
  if tonumber(var.http_content_length) ~= #data then return "", true end
  return data, false
end

function M.ask(request)
  if M.socket == "" then return nil end
  local encoded = json.encode(request)
  if not encoded or #encoded > 262144 then return nil, "request-budget" end
  local sock = ngx.socket.tcp()
  local deadline = ngx.now() + M.TIMEOUT / 1000
  local function receive(pattern)
    local ms = math.floor((deadline - ngx.now()) * 1000)
    if ms <= 0 then return nil end
    sock:settimeout(ms)
    return sock:receive(pattern)
  end
  sock:settimeout(M.TIMEOUT)
  local ok = sock:connect("unix:" .. M.socket)
  if not ok then sock:close(); return nil end
  local ms = math.floor((deadline - ngx.now()) * 1000)
  if ms <= 0 then sock:close(); return nil, "check-deadline" end
  sock:settimeout(ms)
  ok = sock:send("POST /v1/api-security/check HTTP/1.0\r\nHost: agent\r\nContent-Type: application/json\r\nContent-Length: "
    .. #encoded .. "\r\nConnection: close\r\n\r\n" .. encoded)
  if not ok then sock:close(); return nil end
  local line = receive("*l")
  local status = line and tonumber(line:match("^HTTP/1%.[01] (%d%d%d)"))
  if not status then sock:close(); return nil end
  local length, done
  for _ = 1, 16 do
    line = receive("*l")
    if not line or #line > 1024 then sock:close(); return nil end
    if line == "" then done = true; break end
    local n = lower(line):match("^content%-length:%s*(%d+)%s*$")
    if n then length = tonumber(n) end
  end
  if not done or (length and length > 4096) then sock:close(); return nil end
  local data, _, partial = receive(length or 4097)
  sock:close()
  data = data or partial
  if not data or #data > 4096 then return nil end
  local decoded = json.decode(data)
  if type(decoded) ~= "table" then return nil end
  if status ~= 200 then
    local code = decoded.error
    if code ~= "policy-unavailable" and code ~= "check-overloaded" and code ~= "request-budget" then code = "check-unavailable" end
    return nil, code
  end
  if decoded.status ~= 0 and decoded.status ~= 403 then return nil end
  return decoded
end

local function schema_selected(site, ambiguous)
  local schema = site.api_security.schema
  return schema.mode ~= "off" and (ambiguous or schema.unknownEndpoints == "block"
    or M.endpoint(site, ngx.req.get_method(), ngx.var.uri))
end

local function unavailable(site, jwt, graphql, code)
  local settings = site.api_security
  local issues, enforced = {}, false
  local ambiguous = uripath.no_exemption(uripath.raw_path(ngx.var.request_uri or ngx.var.uri or "/"))
  for _, c in ipairs({ { "schema", settings.schema.mode, schema_selected(site, ambiguous) }, { "jwt", settings.jwt.mode, jwt }, { "graphql", settings.graphql.mode, graphql } }) do
    if c[3] and c[2] ~= "off" then
      issues[#issues + 1] = { check = c[1], code = code or "check-unavailable", mode = c[2] }
      enforced = enforced or c[2] == "enforce"
    end
  end
  ngx.ctx.edgeweir_api_log = { template = M.discover(ngx.var.uri), source = "traffic", issues = array(issues), exceptionIds = array({}) }
  ngx.ctx.edgeweir_api_force_log = #issues > 0
  if enforced then return { status = 503, code = "api-security-unavailable", reason = "api_security" } end
end

local function run(site, jwt, graphql, ambiguous, raw)
  local saved = ngx.ctx.edgeweir_api_request
  if not saved then M.capture(site, ngx.req.get_headers(0)); saved = ngx.ctx.edgeweir_api_request end
  local data, truncated = "", false
  if (site.api_security.schema.mode ~= "off" and M.endpoint(site, ngx.req.get_method(), ngx.var.uri)) or graphql then data, truncated = read_body() end
  local var = ngx.var
  local request = { site_id = site.id, version = site.api_security_version, method = ngx.req.get_method(),
    path = var.uri, raw_path = raw, query = var.args or "", headers = saved.headers, authorization = saved.authorization,
    jwt_scoped = jwt, graphql_scoped = graphql, path_ambiguous = ambiguous,
    body = ngx.encode_base64(data), body_truncated = truncated, headers_truncated = saved.headers_truncated }
  local reply, code = M.ask(request)
  if not reply then return unavailable(site, jwt, graphql, code) end
  local log = reply.log
  if type(log) == "table" then
    if type(log.issues) ~= "table" or type(log.exceptionIds) ~= "table" then return unavailable(site, jwt, graphql) end
    local forced = #log.issues > 0 or #log.exceptionIds > 0
    local discovery = site.api_security.discovery
    local sampled = discovery.enabled and ngx.crc32_short(var.request_id or var.edgeweir_request_id or "") % 10000 < discovery.sampleRate
    if forced or sampled then
      log.issues, log.exceptionIds = array(log.issues), array(log.exceptionIds)
      ngx.ctx.edgeweir_api_log, ngx.ctx.edgeweir_api_force_log = log, true
    end
  end
  if reply.status == 403 then
    return { status = 403, code = reply.error or "api-security-denied", reason = "api_security" }
  end
end

function M.check(site, acme)
  if not site._api then return end
  local jwt, graphql, ambiguous, raw = M.selected(site)
  if jwt then ngx.ctx.edgeweir_api_cache_bypass = true end
  if not schema_selected(site, ambiguous) and not jwt and not graphql then
    local discovery = site.api_security.discovery
    if not discovery.enabled or ngx.crc32_short(ngx.var.request_id or ngx.var.edgeweir_request_id or "") % 10000 >= discovery.sampleRate then return end
  end
  if acme or ngx.var.edgeweir_local == "1" then return end
  local ok, result = pcall(run, site, jwt, graphql, ambiguous, raw)
  if not ok then return unavailable(site, jwt, graphql) end
  return result
end

return M
