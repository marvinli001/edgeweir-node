-- edgeweir.auth: access authentication of a site (Site.auth_rules, proto
-- v0.27.0, feature access-auth-v1, ADR-0038).
--
-- prepare(site) compiles a site's rules when the site table is installed.
--
-- select(site, acme) runs in the edge layer's access phase after bans and
-- the PURGE method, before maintenance, CC and the rules: it picks the
-- first enabled rule whose scope the request matches (domains, path
-- prefixes, extensions, excluded prefixes) and, for signed URLs, parses the
-- signature and removes it at once (kinds A and D: their query parameters;
-- B and C: the two leading path segments, cut from the normalized $uri), so
-- that maintenance, CC, the rules (http.request.uri and full_uri included),
-- the cache key, purge markers and the origin see the URI without it. HTTP-01
-- requests and the reserved prefix /.edgeweir/ are never selected.
--
-- check(site, https_redirect) runs inside edgeweir.policy after the
-- platform allow and block lists, before the rule phases (the local
-- listeners, the agent's prefetches, are not checked). A plain HTTP
-- request the site's own Force HTTPS redirects is redirected first, so
-- credentials never travel unencrypted. It returns nil to let the request
-- through, or what edgeweir.policy returns: a redirect, a denial
-- { status, code } or { respond = function } for answers of their own
-- (Basic's 401 with WWW-Authenticate, the forward authentication service's
-- 401, 403 and 3xx). Every refusal is counted (edgeweir.stats.auth_failed).
--
-- Basic: PBKDF2-HMAC-SHA256 hashes from the rule's secret; results are kept
-- per worker (success 60 s, failure 10 s, keyed by the SHA-256 of the
-- Authorization value and the secret's version); a client network gets at
-- most BASIC_FAILURES failed verifications per site in BASIC_WINDOW seconds,
-- then 429 without hashing. Forward authentication: a subrequest to
-- /./edgeweir-auth, which the origin layer sends to the service (origin
-- address policy, TLS verification, the rule's timeout); 2xx and 401/403
-- answers may be cached in edgeweir_auth, keyed by the forwarded headers.
-- Signed URLs: md5 over the raw path, the timestamp (rand for A) and each
-- key, compared in constant time.
--
-- Nothing here logs a password, hash, key or signature.
local cjson = require("cjson.safe")
local lrucache = require("resty.lrucache")
local resty_sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex
local bit = require("bit")
local ipaddr = require("edgeweir.ipaddr")
local expressions = require("edgeweir.expressions")
local errorpages = require("edgeweir.errorpages")
local stats = require("edgeweir.stats")

local _M = {}

local byte, char, find, format, lower, sub = string.byte, string.char, string.find, string.format, string.lower, string.sub
local bor, bxor = bit.bor, bit.bxor
local floor, tonumber, tostring, type = math.floor, tonumber, tostring, type
local concat = table.concat

-- The internal location of forward authentication subrequests (nginx.conf):
-- no client request reaches it (nginx resolves "." segments) and it is
-- internal.
_M.LOCATION = "/./edgeweir-auth"
-- Bodies of the service's 401 and 403 answers passed on (larger ones get
-- the site's error page).
_M.MAX_BODY = 65536
-- Failed Basic verifications per site and client network per window.
_M.BASIC_FAILURES = 10
_M.BASIC_WINDOW = 10
_M.SUCCESS_TTL = 60
_M.FAILURE_TTL = 10
-- Iterations of the dummy hash computed for unknown users.
local DUMMY_ITERATIONS = 10000
local DUMMY_SALT = "edgeweir-dummy-s"

local results = lrucache.new(2048)

local function sha256_hex(...)
  local h = resty_sha256:new()
  for i = 1, select("#", ...) do
    h:update((select(i, ...)))
  end
  return to_hex(h:final())
end

local function unhex(s)
  return (s:gsub("..", function(c) return char(tonumber(c, 16)) end))
end

-- same compares two strings in time that depends on their length only.
function _M.same(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
    return false
  end
  local d = 0
  for i = 1, #a do
    d = bor(d, bxor(byte(a, i), byte(b, i)))
  end
  return d == 0
end

-- domain_matcher returns a function telling whether a host matches a site
-- domain in its written form: a.com, *.a.com (one label), .a.com (any
-- depth) or ~pattern (the whole host).
local function domain_matcher(d)
  if sub(d, 1, 1) == "~" then
    local re = "^(?:" .. sub(d, 2) .. ")$"
    return function(host) return ngx.re.find(host, re, "jo") ~= nil end
  end
  if sub(d, 1, 2) == "*." then
    local parent = sub(d, 3)
    return function(host)
      local dot = find(host, ".", 1, true)
      return dot ~= nil and dot > 1 and sub(host, dot + 1) == parent
    end
  end
  if sub(d, 1, 1) == "." then
    return function(host) return #host > #d and sub(host, -#d) == d end
  end
  return function(host) return host == d end
end

local function set_of(list)
  local out = {}
  for _, v in ipairs(list or {}) do out[v] = true end
  return out
end

-- prepare compiles a site's rules (site._auth; nil without rules).
function _M.prepare(site)
  local rules = site.auth_rules
  if type(rules) ~= "table" or #rules == 0 then
    site._auth = nil
    site._auth_signed_path = nil
    return
  end
  local out = {}
  for i, r in ipairs(rules) do
    local c = {
      id = r.id, kind = r.kind, version = tostring(r.secret_version or 0),
      prefixes = r.path_prefixes or {}, excludes = r.exclude_path_prefixes or {},
      extensions = r.extensions and #r.extensions > 0 and set_of(r.extensions) or nil,
      basic = r.basic, forward = r.forward, url = r.url, keys = r.keys or {},
    }
    if r.domains and #r.domains > 0 then
      c.domains = {}
      for j, d in ipairs(r.domains) do c.domains[j] = domain_matcher(d) end
    end
    if r.kind == "basic" then
      c.users = {}
      for _, u in ipairs(r.users or {}) do
        c.users[u.name] = { iterations = u.iterations, salt = unhex(u.salt), hash = unhex(u.hash) }
      end
    end
    if r.forward then
      local headers = {}
      for j, h in ipairs(r.forward.request_headers or {}) do headers[j] = h end
      c.request_headers = headers
    end
    out[i] = c
  end
  site._auth = out
  -- Rules whose signature is in the path (url_b, url_c): requests refused
  -- before it is removed have no path to log (edgeweir.accesslogs).
  local signed_path = false
  for i = 1, #out do
    if out[i].kind == "url_b" or out[i].kind == "url_c" then signed_path = true end
  end
  site._auth_signed_path = signed_path or nil
end

local function starts_with_any(path, prefixes)
  for i = 1, #prefixes do
    local p = prefixes[i]
    if sub(path, 1, #p) == p then return true end
  end
  return false
end

-- in_scope reports whether a request for host and path (normalized,
-- without B/C signature segments) is in a rule's scope.
function _M.in_scope(rule, host, path)
  if rule.domains then
    local hit = false
    for i = 1, #rule.domains do
      if rule.domains[i](host) then hit = true; break end
    end
    if not hit then return false end
  end
  if #rule.prefixes > 0 and not starts_with_any(path, rule.prefixes) then return false end
  if rule.extensions and not rule.extensions[expressions.path_extension(path)] then return false end
  return not starts_with_any(path, rule.excludes)
end

-- Query elements: name (text before the first "=") and value.
local function element_name(e)
  local eq = find(e, "=", 1, true)
  return eq and sub(e, 1, eq - 1) or e
end
local function element_value(e)
  local eq = find(e, "=", 1, true)
  return eq and sub(e, eq + 1) or ""
end

-- parse_query finds the signature of a kind A or D rule in a query string:
-- { ts, rand, hash, args } (args: the query without the signature
-- parameters) or nil. The first element of a parameter counts; all of them
-- are removed.
function _M.parse_query(kind, names, query)
  local sign_v, time_v
  local kept = {}
  for e in string.gmatch(query or "", "[^&]+") do
    local name = element_name(e)
    if name == names.sign_param then
      if sign_v == nil then sign_v = element_value(e) end
    elseif kind == "url_d" and name == names.time_param then
      if time_v == nil then time_v = element_value(e) end
    else
      kept[#kept + 1] = e
    end
  end
  if sign_v == nil then return nil end
  local args = concat(kept, "&")
  if kind == "url_a" then
    local ts, rand, hash = sign_v:match("^(%d+)%-(%w+)%-(%x+)$")
    if not ts or #ts > 12 or #rand > 64 or #hash ~= 32 or hash:find("[A-F]") then return nil end
    return { ts = ts, rand = rand, hash = hash, args = args }
  end
  if not time_v or not time_v:match("^%d+$") or #time_v > 12 or #sign_v ~= 32 or not sign_v:match("^[0-9a-f]+$") then
    return nil
  end
  return { ts = time_v, hash = sign_v, args = args }
end

-- parse_segments finds the signature of a kind B or C rule in a raw path:
-- { ts, hash, rest, prefix } (rest: the raw path after the two segments,
-- starting with "/"; prefix: the two segments) or nil.
function _M.parse_segments(kind, raw_path)
  local first, second, rest = raw_path:match("^/([^/]+)/([^/]+)(/.*)$")
  if not first then return nil end
  local ts, hash = first, second
  if kind == "url_c" then ts, hash = second, first end
  if not ts:match("^%d+$") or #ts > 12 or #hash ~= 32 or not hash:match("^[0-9a-f]+$") then return nil end
  return { ts = ts, hash = hash, rest = rest, prefix = "/" .. first .. "/" .. second }
end

-- select picks the request's rule and removes a signed URL's signature
-- (see the module comment). acme: an HTTP-01 request.
function _M.select(site, acme)
  local rules = site._auth
  if not rules or acme then return end
  local var = ngx.var
  local uri = var.uri
  if sub(uri, 1, 11) == "/.edgeweir/" then return end
  local host = var.host or ""
  local request_uri = var.request_uri
  local q = find(request_uri, "?", 1, true)
  local raw_path = q and sub(request_uri, 1, q - 1) or request_uri
  for i = 1, #rules do
    local rule = rules[i]
    local path, sig = uri, nil
    local kind = rule.kind
    if kind == "url_b" or kind == "url_c" then
      sig = _M.parse_segments(kind, raw_path)
      -- The normalized path must carry the same two segments: nothing is
      -- decoded out of the raw path (no ".." or "%2F" past normalization).
      if sig and sub(uri, 1, #sig.prefix + 1) == sig.prefix .. "/" then
        path = sub(uri, #sig.prefix + 1)
      else
        sig = nil
      end
    end
    if _M.in_scope(rule, host, path) then
      local state = { rule = rule, request_uri = request_uri }
      if kind == "url_a" or kind == "url_d" then
        sig = _M.parse_query(kind, rule.url, var.args)
        if sig then
          ngx.req.set_uri_args(sig.args)
          state.stripped = sig.args ~= "" and (raw_path .. "?" .. sig.args) or raw_path
          sig.path = raw_path
        end
      elseif sig then
        ngx.req.set_uri(path, false)
        state.stripped = q and (sig.rest .. sub(request_uri, q)) or sig.rest
        sig.path = sig.rest
      end
      state.sig = sig
      ngx.ctx.edgeweir_auth = state
      return
    end
  end
end

-- request_uri is the request URI the rules see: without the signature of a
-- signed URL.
function _M.request_uri()
  local state = ngx.ctx.edgeweir_auth
  return state and state.stripped or ngx.var.request_uri
end

-- refused counts a refusal and names its block reason and rule
-- (edgeweir.reasons, recorded by edgeweir.router); a service that does not
-- answer (503 auth-unavailable) is no block.
local function refused(site, result)
  stats.auth_failed(site.id)
  if result.code ~= "auth-unavailable" then
    local state = ngx.ctx.edgeweir_auth
    result.reason, result.rule_id = "auth", state and state.rule and state.rule.id or nil
  end
  return result
end

-- check_signature checks a signed URL's signature against the rule's keys
-- (every key is tried, in constant time) and window: nil, or a denial.
function _M.check_signature(rule, sig, now)
  if not sig then return "auth-denied" end
  local match = false
  local rand = rule.kind == "url_a" and ("@" .. sig.rand) or ""
  for i = 1, #rule.keys do
    if _M.same(ngx.md5(sig.path .. "@" .. sig.ts .. rand .. "@" .. rule.keys[i]), sig.hash) then
      match = true
    end
  end
  if not match then return "auth-denied" end
  local ts, u = tonumber(sig.ts), rule.url
  if now < ts - u.skew_seconds or now > ts + u.validity_seconds + u.skew_seconds then
    return "auth-expired"
  end
  return nil
end

local function url(site, rule, state)
  local code = _M.check_signature(rule, state.sig, ngx.time())
  if code then return refused(site, { status = 403, code = code }) end
  return nil
end

-- verify_password derives a password's hash with a user's salt and
-- iterations and compares it in constant time; unknown users cost a dummy
-- derivation of the same kind.
function _M.verify_password(user, password)
  local kdf = require("resty.openssl.kdf")
  local derived = kdf.derive({
    type = kdf.PBKDF2, md = "sha256", outlen = 32, pass = password,
    salt = user and user.salt or DUMMY_SALT, pbkdf2_iter = user and user.iterations or DUMMY_ITERATIONS,
  })
  return user ~= nil and derived ~= nil and _M.same(derived, user.hash)
end

-- parse_basic returns the user name and password of an Authorization
-- header of the Basic scheme, or nil.
function _M.parse_basic(header)
  if type(header) ~= "string" then return nil end
  local b64 = header:match("^%s*[Bb][Aa][Ss][Ii][Cc]%s+([A-Za-z0-9+/]+=?=?)%s*$")
  local decoded = b64 and ngx.decode_base64(b64)
  if not decoded then return nil end
  local colon = find(decoded, ":", 1, true)
  if not colon then return nil end
  return sub(decoded, 1, colon - 1), sub(decoded, colon + 1)
end

local function basic(site, rule)
  local var = ngx.var
  local b = rule.basic
  local deny = function()
    return refused(site, { respond = function() return errorpages.respond_auth(site, b.realm) end })
  end
  local header = var.http_authorization
  local name, password = _M.parse_basic(header)
  if not name then return deny() end
  local key = rule.id .. ":" .. rule.version .. ":" .. sha256_hex(header)
  local known = results:get(key)
  if known == nil then
    local dict = ngx.shared.edgeweir_auth
    local now = ngx.time()
    local window = floor(now / _M.BASIC_WINDOW)
    local limit = "bf|" .. site.id .. "|" .. (ipaddr.client_network(var.remote_addr) or tostring(var.remote_addr)) .. "|" .. window
    if (dict:get(limit) or 0) >= _M.BASIC_FAILURES then
      return refused(site, { status = 429, code = "auth-rate-limited", retry_after = _M.BASIC_WINDOW - now % _M.BASIC_WINDOW })
    end
    if _M.verify_password(rule.users[name], password) then
      known = name
      results:set(key, name, _M.SUCCESS_TTL)
    else
      known = false
      results:set(key, false, _M.FAILURE_TTL)
      dict:incr(limit, 1, 0, _M.BASIC_WINDOW)
    end
  end
  if not known then return deny() end
  if not b.keep_authorization then ngx.req.clear_header("Authorization") end
  if b.user_header then ngx.req.set_header("X-Auth-User", known) end
  return nil
end

-- lowered returns a response's headers by lowercase name (lines joined).
local function lowered(headers)
  local out = {}
  for k, v in pairs(headers or {}) do
    out[lower(k)] = type(v) == "table" and concat(v, ", ") or v
  end
  return out
end

-- pass_on answers with the service's 401 or 403 (status, WWW-Authenticate,
-- Content-Type and body), or with the site's error page when the body is
-- larger than MAX_BODY.
local function pass_on(site, answer)
  return function()
    if answer.large then return errorpages.respond(answer.s == 401 and 401 or 403, "auth-denied", site) end
    local h = ngx.header
    ngx.status = answer.s
    h["Cache-Control"] = "no-store"
    h["X-Edgeweir-Error"] = "auth-denied"
    if answer.w then h["WWW-Authenticate"] = answer.w end
    if answer.t then h["Content-Type"] = answer.t end
    h["Content-Length"] = #(answer.b or "")
    if ngx.req.get_method() ~= "HEAD" and answer.b then ngx.print(answer.b) end
    return ngx.exit(ngx.HTTP_OK)
  end
end

local function redirect_on(status, location)
  return function()
    ngx.status = status
    local h = ngx.header
    h["Location"] = location
    h["Cache-Control"] = "no-store"
    h["X-Edgeweir-Error"] = "auth-denied"
    h["Content-Length"] = 0
    return ngx.exit(ngx.HTTP_OK)
  end
end

-- copy sets the service's headers on the request towards the origin and
-- removes the visitor's own of those names.
local function copy(f, values)
  for _, name in ipairs(f.response_headers or {}) do
    local v = values and values[name]
    if v ~= nil and v ~= "" then
      ngx.req.set_header(name, v)
    else
      ngx.req.clear_header(name)
    end
  end
end

-- unavailable logs a failing service (IDs and status only, once per rule
-- and node every 60 seconds) and lets the request through or refuses it.
local function unavailable(site, rule, status)
  if ngx.shared.edgeweir_policy_logs:safe_add("auth:" .. rule.id, true, 60) then
    ngx.log(ngx.NOTICE, "edgeweir: access authentication service failed site=", site.id, " rule=", rule.id, " status=", status)
  end
  if rule.forward.allow_unavailable then return nil end
  return refused(site, { status = 503, code = "auth-unavailable" })
end

-- outcome turns a (possibly cached) answer of the service into the result.
local function outcome(site, rule, answer)
  local f = rule.forward
  local s = answer.s
  if s >= 200 and s < 300 then
    copy(f, answer.h)
    return nil
  end
  if s == 401 or s == 403 then return refused(site, { respond = pass_on(site, answer) }) end
  if s >= 300 and s < 400 and f.pass_redirects and answer.l then
    return refused(site, { respond = redirect_on(s, answer.l) })
  end
  if s >= 500 or s == 0 then return unavailable(site, rule, s) end
  return refused(site, { status = 403, code = "auth-denied" })
end

local function forward(site, rule, state)
  local f = rule.forward
  local dict = ngx.shared.edgeweir_auth
  local cache_key
  if (f.cache_seconds or 0) > 0 then
    local headers = ngx.req.get_headers(0)
    local parts = { rule.id, f.url }
    for _, name in ipairs(rule.request_headers) do
      local v = headers[name]
      parts[#parts + 1] = name .. "\0" .. (type(v) == "table" and concat(v, ", ") or v or "")
    end
    cache_key = "fw|" .. sha256_hex(concat(parts, "\0"))
    local cached = dict:get(cache_key)
    local answer = cached and cjson.decode(cached)
    if type(answer) == "table" then return outcome(site, rule, answer) end
  end
  local var = ngx.var
  local res = ngx.location.capture(_M.LOCATION, {
    method = f.head and ngx.HTTP_HEAD or ngx.HTTP_GET,
    vars = {
      edgeweir_auth_site = site.id,
      edgeweir_auth_rule = rule.id,
      edgeweir_auth_uri = state.request_uri,
      edgeweir_auth_method = ngx.req.get_method(),
      edgeweir_auth_host = var.host or "",
    },
  })
  local s = res and res.status or 0
  local answer = { s = s }
  local values = res and lowered(res.header) or {}
  if s >= 200 and s < 300 then
    local h = {}
    for _, name in ipairs(f.response_headers or {}) do h[name] = values[name] end
    answer.h = h
  elseif s == 401 or s == 403 then
    answer.w, answer.t = values["www-authenticate"], values["content-type"]
    local body = res.body or ""
    if #body > _M.MAX_BODY or res.truncated then answer.large = true else answer.b = body end
  elseif s >= 300 and s < 400 then
    answer.l = values["location"]
  end
  if cache_key and ((s >= 200 and s < 300) or s == 401 or s == 403) then
    dict:set(cache_key, cjson.encode(answer), f.cache_seconds)
  end
  return outcome(site, rule, answer)
end

-- check decides the request's access (see the module comment);
-- https_redirect is edgeweir.policy.site_https_redirect.
function _M.check(site, https_redirect)
  local ctx = ngx.ctx
  local state = ctx.edgeweir_auth
  if not state then return nil end
  local var = ngx.var
  if var.edgeweir_local == "1" then return nil end
  if var.scheme ~= "https" then
    local r = https_redirect(site, var.host, state.request_uri, ctx.edgeweir_found, ctx.edgeweir_default_certificate)
    if r then return r end
  end
  local rule = state.rule
  if rule.kind == "basic" then return basic(site, rule) end
  if rule.kind == "forward" then return forward(site, rule, state) end
  return url(site, rule, state)
end

return _M
