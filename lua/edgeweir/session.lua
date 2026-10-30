-- edgeweir.session: session detection (Site.session_detection, feature
-- session-detection-v1, ADR-0068).
--
-- A small first-party script reports what the browser shows about
-- automation, the node keeps it in a signed session cookie and scores
-- every request of the site with edgeweir.botscore.
--
--   GET  /.edgeweir/session/s.js   the script (static, cached an hour)
--   POST /.edgeweir/session/c      a report: t (token), n (proof of work),
--                                  f (flags, edgeweir.botscore F_*)
--
-- Token (one per HTML response, in the script tag's data-t; 5 minutes):
--   <kid>.<b64url(site|kind|prefix|ua|iat|exp|nonce)>.<b64url(sig)>
--   sig = HMAC(key, "t1.<kid>.<payload>"), kind "b" (background) or "i"
--   (the interstitial). A report needs n with sha256(token ":" n) of POW
--   leading zero bits (a few ms in a browser), and at most RATE reports
--   per client network and minute count.
-- Session cookie (30 minutes, renewed by every report):
--   __ew_sess=v1.<kid>.<b64url(site|prefix|ua|iat|exp|sid|flags)>.<b64url(sig)>
--   sig = HMAC(key, "s1.<kid>.<payload>"); prefix and ua as challenge
--   passes (edgeweir.challenge). Flags only add up within a session.
-- Staleness: HTML navigations of a session count in edgeweir_challenge
-- ("s|<sid>", 30 minutes) and a report resets them; past STALE_AFTER the
-- script is taken as not running (a scripted client replaying the cookie).
--
-- The script goes into the site's HTML responses (header_filter and
-- body_filter, edge layer): 200 answers to GET with text/html, no
-- Content-Encoding, Content-Range or Cache-Control no-transform, when the
-- response's Content-Security-Policy lets a same-origin script run and
-- connect (csp_allows; its nonce is reused). It goes before the first
-- "</head>" within 64 KiB, else at the end. The cache keeps the origin's
-- bytes: the tag is added on the way out, to hits and misses alike.
--
-- Enforcement (mode "enforce", edgeweir.router): a session whose flags
-- carry a hard signal or whose score is below 30 is automated; its passes
-- below the captcha level do not count (challenge.pass_level's floor) and
-- its requests get a captcha challenge. Where the interstitial applies
-- (interstitial_for), requests without a session or a js pass see the
-- interstitial page; a report from it with a score of 30 or more also
-- gets a js pass.
local bit = require("bit")
local b64 = require("ngx.base64")
local rand = require("resty.openssl.rand")
local lrucache = require("resty.lrucache")
local botscore = require("edgeweir.botscore")
local challenge = require("edgeweir.challenge")
local errorpages = require("edgeweir.errorpages")
local ipaddr = require("edgeweir.ipaddr")
local reasons = require("edgeweir.reasons")
local topstats = require("edgeweir.topstats")

local _M = {}

local find, lower, sub, concat = string.find, string.lower, string.sub, table.concat
local tonumber, tostring, type = tonumber, tostring, type

_M.COOKIE = "__ew_sess"
_M.PREFIX = "/.edgeweir/session/"
_M.SCRIPT = "/.edgeweir/session/s.js"
_M.COLLECT = "/.edgeweir/session/c"
_M.TTL = 1800
_M.TOKEN_TTL = 300
_M.POW = 10
_M.STALE_AFTER = 10
_M.RATE = 60
_M.SCAN_LIMIT = 65536

local function dict()
  return ngx.shared.edgeweir_challenge
end

local function split(s, n)
  local out, i = {}, 1
  for _ = 1, n - 1 do
    local j = find(s, "|", i, true)
    if not j then return nil end
    out[#out + 1] = sub(s, i, j - 1)
    i = j + 1
  end
  if find(s, "|", i, true) then return nil end
  out[#out + 1] = sub(s, i)
  return out
end

local sessions = assert(lrucache.new(10000))

-- forget drops the worker cache (tests).
function _M.forget()
  sessions = assert(lrucache.new(10000))
end

-- ---------------------------------------------------------------------
-- Tokens and sessions

-- sign_token signs f = {site, kind, prefix, ua, iat, exp, nonce}.
function _M.sign_token(key, f)
  local payload = b64.encode_base64url(concat({ f.site, f.kind, f.prefix, f.ua, f.iat, f.exp, f.nonce }, "|"))
  local head = key.id .. "." .. payload
  return head .. "." .. b64.encode_base64url(challenge.mac(key, "t1." .. head))
end

-- parse_token checks a token's signature and returns its fields.
function _M.parse_token(keys, token)
  if type(token) ~= "string" or #token > 512 then return nil end
  local kid, payload, sig = token:match("^([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  local key = kid and keys and keys.by_id[kid]
  if not key or not challenge.equal(b64.encode_base64url(challenge.mac(key, "t1." .. kid .. "." .. payload)), sig) then
    return nil
  end
  local f = split(b64.decode_base64url(payload) or "", 7)
  if not f then return nil end
  local iat, exp = tonumber(f[5]), tonumber(f[6])
  if not iat or not exp or (f[2] ~= "b" and f[2] ~= "i") then return nil end
  return { site = f[1], kind = f[2], prefix = f[3], ua = f[4], iat = iat, exp = exp, nonce = f[7] }
end

-- sign_session signs f = {site, prefix, ua, iat, exp, sid, flags}.
function _M.sign_session(key, f)
  local payload = b64.encode_base64url(concat({ f.site, f.prefix, f.ua, f.iat, f.exp, f.sid, f.flags }, "|"))
  local head = "v1." .. key.id .. "." .. payload
  return head .. "." .. b64.encode_base64url(challenge.mac(key, "s1." .. key.id .. "." .. payload))
end

-- parse_session checks a session cookie's signature and returns its fields.
function _M.parse_session(keys, value)
  if type(value) ~= "string" or #value > 1024 then return nil end
  local kid, payload, sig = value:match("^v1%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  local key = kid and keys and keys.by_id[kid]
  if not key or not challenge.equal(b64.encode_base64url(challenge.mac(key, "s1." .. kid .. "." .. payload)), sig) then
    return nil
  end
  local f = split(b64.decode_base64url(payload) or "", 7)
  if not f then return nil end
  local iat, exp, flags = tonumber(f[4]), tonumber(f[5]), tonumber(f[7])
  if not iat or not exp or not flags or flags < 0 or flags > botscore.F_ALL or not f[6]:match("^[A-Za-z0-9_-]+$") then
    return nil
  end
  return { site = f[1], prefix = f[2], ua = f[3], iat = iat, exp = exp, sid = f[6], flags = flags }
end

-- bound reports whether a parsed token or session holds for site, client
-- and time.
function _M.bound(f, site_id, prefix, uah, now)
  return f.site == site_id and f.exp > now and f.prefix == prefix and f.ua == uah
end

-- session_cookie returns the Set-Cookie value of a session.
function _M.session_cookie(value, https)
  return _M.COOKIE .. "=" .. value .. "; Path=/; Max-Age=" .. _M.TTL .. "; HttpOnly; SameSite=Lax" .. (https and "; Secure" or "")
end

-- navigation reports whether the request loads a page (Sec-Fetch-Dest
-- document, else an Accept that names text/html) with GET.
function _M.navigation(method, dest, accept)
  if method ~= "GET" then return false end
  if dest then return dest == "document" end
  return type(accept) == "string" and find(lower(accept), "text/html", 1, true) ~= nil
end

-- current returns the request's valid session ({sid, flags, stale}) for
-- site, or nil. Cached in ngx.ctx.
function _M.current(site)
  local ctx = ngx.ctx
  local s = rawget(ctx, "edgeweir_session")
  if s ~= nil then return s or nil end
  s = false
  local var = ngx.var
  local cookie = var["cookie_" .. _M.COOKIE]
  if cookie and #cookie <= 1024 then
    local now = challenge.clock()
    local f = sessions:get(cookie)
    if not f then
      f = _M.parse_session(challenge.keys(), cookie)
      if f and f.exp > now then sessions:set(cookie, f, math.min(f.exp - now, 60)) end
    end
    if f and _M.bound(f, site.id, challenge.prefix_of(var.remote_addr), challenge.ua_of(var.http_user_agent), now) then
      s = { sid = f.sid, flags = f.flags, stale = false }
    end
  end
  ctx.edgeweir_session = s
  return s or nil
end

-- ---------------------------------------------------------------------
-- Interstitial rules

-- host_matches compares a request host with a rule's ("" any,
-- "*.example.com" exactly one label below).
function _M.host_matches(pattern, host)
  if pattern == "" or pattern == nil then return true end
  host = lower(host or "")
  if sub(pattern, 1, 2) == "*." then
    local suffix = sub(pattern, 2)
    local label = sub(host, 1, #host - #suffix)
    return #host > #suffix and sub(host, -#suffix) == suffix and label ~= "" and not find(label, ".", 1, true)
  end
  return host == pattern
end

-- interstitial_for returns whether the interstitial applies to a request
-- for host and path: the first rule that matches, else the default.
function _M.interstitial_for(sd, host, path)
  for _, r in ipairs(sd.rules or {}) do
    local prefix = r.path_prefix or ""
    if _M.host_matches(r.host, host) and (prefix == "" or sub(path or "", 1, #prefix) == prefix) then
      return r.interstitial == true
    end
  end
  return sd.interstitial == true
end

-- ---------------------------------------------------------------------
-- Request phase

-- prepare runs for every request of a site with session detection before
-- the rules: it finds the session, counts page loads towards staleness,
-- scores the request (ngx.ctx.edgeweir_bot_score) and, in enforce mode,
-- marks an automated session (passes below the captcha level stop
-- counting).
function _M.prepare(site)
  local var = ngx.var
  local s = _M.current(site)
  if s and _M.navigation(ngx.req.get_method(), var.http_sec_fetch_dest, var.http_accept) then
    local n = dict():incr("s|" .. s.sid, 1, 0, _M.TTL)
    s.stale = n ~= nil and n > _M.STALE_AFTER
  end
  local score = _M.score(site)
  local ctx = ngx.ctx
  if site.session_detection.mode == "enforce" and s and (botscore.hard_flags(s.flags) or score < botscore.AUTOMATED_BELOW) then
    ctx.edgeweir_session_automated = true
    ctx.edgeweir_pass_floor = 4
  end
  return score
end

-- score returns the request's bot score (cached in ngx.ctx; the session
-- counts only on sites with session detection).
function _M.score(site)
  local ctx = ngx.ctx
  local score = rawget(ctx, "edgeweir_bot_score")
  if score then return score end
  local s = site.session_detection and _M.current(site) or nil
  local ja4 = site._ja4 and require("edgeweir.ja4").value() or ""
  score = botscore.compute(botscore.signals(ngx.var, ja4, challenge.pass_level(site), s))
  ctx.edgeweir_bot_score = score
  return score
end

-- decide returns what enforce mode asks of a request ("challenge": the
-- session is automated; "interstitial": it has neither a session nor a js
-- pass where the interstitial applies) or nil. The caller leaves out
-- exempt clients and verified crawlers.
function _M.decide(site)
  local sd = site.session_detection
  if sd.mode ~= "enforce" then return nil end
  local ctx = ngx.ctx
  if ctx.edgeweir_session_automated then
    return challenge.pass_level(site) < 4 and "challenge" or nil
  end
  if _M.current(site) or challenge.pass_level(site) >= 2 then return nil end
  local var = ngx.var
  if _M.interstitial_for(sd, var.host, ctx.edgeweir_original_path or var.uri) then return "interstitial" end
  return nil
end

-- ---------------------------------------------------------------------
-- The script and the interstitial

-- COLLECTOR reports the browser's flags with the token of its script tag
-- (data-t) after load and on the first trusted input; data-r (the
-- interstitial) goes back to that path once the report is in.
_M.COLLECTOR = [[(function(){var s=document.currentScript,t=s&&s.getAttribute('data-t'),r=s&&s.getAttribute('data-r');if(!t)return;
var n=navigator,w=window,f=0,i,g=['__playwright__binding__','__pwInitScripts','_phantom','callPhantom','__nightmare','domAutomation','domAutomationController','_selenium','__selenium_unwrapped','__webdriver_evaluate','__driver_evaluate','__webdriver_script_fn','__fxdriver_unwrapped','__lastWatirAlert','Cypress','__puppeteer_evaluation_script__'];
if(n.webdriver)f|=1;for(i=0;i<g.length;i++)if(g[i] in w)f|=2;
try{for(i in document)if(/^\$?cdc_/.test(i)){f|=2;break}}catch(e){}
if(/HeadlessChrome/.test(n.userAgent)||(w.outerWidth===0&&w.outerHeight===0))f|=4;
if(!n.languages||!n.languages.length)f|=8;
function go(){var p=solve(t,]] .. _M.POW .. [[,0,4194304),b,x;if(p<0)return;b='t='+encodeURIComponent(t)+'&n='+p+'&f='+f;
function done(ok){if(ok&&r)location.replace(r)}
try{if(w.fetch){fetch(']] .. _M.COLLECT .. [[',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(function(q){done(q.ok)},function(){})}
else{x=new XMLHttpRequest();x.open('POST',']] .. _M.COLLECT .. [[');x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');x.onload=function(){done(x.status<300)};x.send(b)}}catch(e){}}
function ev(e){if(e.isTrusted===false){f|=16;return}if(!(f&32)){f|=32;go()}}
['pointerdown','pointermove','keydown','touchstart','wheel','scroll'].forEach(function(k){addEventListener(k,ev,{capture:true,passive:true})});
if(r||document.readyState==='complete')setTimeout(go,0);else addEventListener('load',function(){setTimeout(go,0)})})();
]]

_M.SCRIPT_JS = challenge.SHA_JS .. _M.COLLECTOR

-- token returns a signed token of kind ("b", "i") for the request.
local function token(site, keys, kind)
  local var, now = ngx.var, challenge.clock()
  return _M.sign_token(keys.current, {
    site = site.id, kind = kind, prefix = challenge.prefix_of(var.remote_addr), ua = challenge.ua_of(var.http_user_agent),
    iat = now, exp = now + _M.TOKEN_TTL, nonce = b64.encode_base64url(assert(rand.bytes(9))),
  })
end

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }
local function esc(s)
  return (tostring(s or ""):gsub("[&<>\"']", ESCAPES))
end

-- tag returns the script tag added to HTML (nonce: the page's CSP nonce).
function _M.tag(tok, nonce)
  return '<script src="' .. _M.SCRIPT .. '" data-t="' .. esc(tok) .. '" async'
    .. (nonce and (' nonce="' .. esc(nonce) .. '"') or "") .. "></script>"
end

-- interstitial answers with the interstitial page (GET, HEAD) or a plain
-- 403 (other methods), records the block reason challenge and counts a
-- challenge issued.
function _M.interstitial(site)
  local keys = challenge.keys()
  if not keys or not keys.current then
    return errorpages.respond(503, "challenge-unavailable", site)
  end
  reasons.set("challenge")
  local h = ngx.header
  local method = ngx.req.get_method()
  if method ~= "GET" and method ~= "HEAD" then
    ngx.status = 403
    h["Content-Type"] = "text/plain; charset=utf-8"
    h["Cache-Control"] = "no-store, private"
    h["X-Edgeweir-Challenge"] = "required"
    ngx.print("challenge required\n")
    return ngx.exit(ngx.HTTP_OK)
  end
  topstats.challenge(site.id, "issued")
  local var = ngx.var
  local nonce = ngx.encode_base64(assert(rand.bytes(16)))
  ngx.status = 403
  h["Content-Type"] = "text/html; charset=utf-8"
  h["Cache-Control"] = "no-store, private"
  h["Content-Security-Policy"] = challenge.csp(nonce)
  h["X-Content-Type-Options"] = "nosniff"
  h["Referrer-Policy"] = "same-origin"
  h["X-Edgeweir-Challenge"] = "session"
  if method == "HEAD" then return ngx.exit(ngx.HTTP_OK) end
  local lang = challenge.language(var.http_accept_language)
  local t = challenge.TEXT[lang] or challenge.TEXT.en
  local title, hint = challenge.custom_text(site, lang)
  local ret = challenge.return_url(var.request_uri) or "/"
  ngx.print(concat({
    '<!doctype html><html lang="', t.lang, '"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">',
    "<title>", title ~= "" and esc(title) or t.title, '</title><style nonce="', nonce, '">', challenge.PAGE_STYLE,
    '</style></head><body class="w"><main>', errorpages.BRAND, '<div class="cd"><div class="st"><span class="pl">', t.title,
    "</span></div><h1>", title ~= "" and esc(title) or t.verify, "</h1>",
    hint ~= "" and ('<p class="hint">' .. esc(hint) .. "</p>") or "",
    errorpages.hops(lang, { { "x", t.checking, "held" }, { "", t.ok, "ok" }, { "n", errorpages.pending(t.waiting) } }),
    '<div class="bar" role="progressbar" aria-label="', t.verify, '"><i></i></div><p class="note">', t.seconds, "</p>",
    '<noscript><p class="err">', t.noscript, "</p></noscript></div></main>",
    '<script nonce="', nonce, '" data-t="', esc(token(site, keys, "i")), '" data-r="', esc(ret), '">', _M.SCRIPT_JS, "</script>",
    "</body></html>",
  }))
  return ngx.exit(ngx.HTTP_OK)
end

local function text(status, headers, body)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store, private"
  for k, v in pairs(headers) do ngx.header[k] = v end
  if ngx.req.get_method() ~= "HEAD" then ngx.print(body, "\n") end
  return ngx.exit(ngx.HTTP_OK)
end

local function field(args, name)
  local v = args[name]
  if type(v) == "table" then v = v[1] end
  return type(v) == "string" and v or nil
end

-- collect takes a report (POST /.edgeweir/session/c): 204 with the
-- session cookie (and a js pass after the interstitial), 400 for a
-- malformed or invalid report, 429 past RATE per client network.
local function collect(site)
  if ngx.req.get_method() ~= "POST" then
    return text(405, { Allow = "POST", ["X-Edgeweir-Error"] = "method-not-allowed" }, "method not allowed")
  end
  local var = ngx.var
  local length = tonumber(var.content_length)
  if not length or length > 1024 then
    return text(413, { ["X-Edgeweir-Error"] = "too-large" }, "request too large")
  end
  local network = ipaddr.client_network(var.remote_addr) or var.remote_addr
  local n = dict():incr("r|" .. site.id .. "|" .. network, 1, 0, 60)
  if n and n > _M.RATE then
    return text(429, { ["Retry-After"] = "60", ["X-Edgeweir-Error"] = "rate-limited" }, "too many reports")
  end
  local keys = challenge.keys()
  if not keys or not keys.current then return errorpages.respond(503, "challenge-unavailable", site) end
  ngx.req.read_body()
  local args = ngx.req.get_post_args(8) or {}
  local tok, pow, flags = field(args, "t"), field(args, "n"), tonumber(field(args, "f") or "")
  local now = challenge.clock()
  local prefix, uah = challenge.prefix_of(var.remote_addr), challenge.ua_of(var.http_user_agent)
  local t = _M.parse_token(keys, tok)
  if not t or not _M.bound(t, site.id, prefix, uah, now) or not challenge.pow_ok(tok, pow, _M.POW)
    or not flags or flags ~= math.floor(flags) or flags < 0 or flags > botscore.F_ALL then
    return text(400, { ["X-Edgeweir-Error"] = "invalid-report" }, "invalid report")
  end
  local old = _M.current(site)
  local sid = old and old.sid or b64.encode_base64url(assert(rand.bytes(12)))
  flags = bit.bor(flags, old and old.flags or 0)
  dict():set("s|" .. sid, 0, _M.TTL)
  local https = var.scheme == "https"
  local cookies = {
    _M.session_cookie(_M.sign_session(keys.current, {
      site = site.id, prefix = prefix, ua = uah, iat = now, exp = now + _M.TTL, sid = sid, flags = flags,
    }), https),
  }
  if t.kind == "i" then
    local ctx = ngx.ctx
    ctx.edgeweir_session, ctx.edgeweir_bot_score = { sid = sid, flags = flags, stale = false }, nil
    if not botscore.hard_flags(flags) and _M.score(site) >= botscore.AUTOMATED_BELOW and challenge.pass_level(site) < 2 then
      local ttl = challenge.pass_ttl(site)
      cookies[2] = challenge.pass_cookie(challenge.sign_pass(keys.current, site.id, 2, prefix, uah, now, now + ttl), ttl, https)
      topstats.challenge(site.id, "passed")
    end
  end
  ngx.header["Set-Cookie"] = cookies
  ngx.header["Cache-Control"] = "no-store, private"
  return ngx.exit(204)
end

-- reserved answers a request under /.edgeweir/session/ (never proxied).
function _M.reserved(site)
  local uri = ngx.var.uri
  if uri == _M.COLLECT then return collect(site) end
  if uri == _M.SCRIPT then
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
      return text(405, { Allow = "GET, HEAD", ["X-Edgeweir-Error"] = "method-not-allowed" }, "method not allowed")
    end
    local h = ngx.header
    h["Content-Type"] = "application/javascript; charset=utf-8"
    h["Cache-Control"] = "public, max-age=3600"
    h["X-Content-Type-Options"] = "nosniff"
    if method ~= "HEAD" then ngx.print(_M.SCRIPT_JS) end
    return ngx.exit(ngx.HTTP_OK)
  end
  return text(404, { ["X-Edgeweir-Error"] = "not-found" }, "not found")
end

-- ---------------------------------------------------------------------
-- Injection

-- directives parses one Content-Security-Policy into lowercase directive
-- names and their source lists (the first of a repeated directive wins).
local function directives(policy)
  local out = {}
  for part in (policy .. ";"):gmatch("([^;]*);") do
    local name, rest = part:match("^%s*([%w%-]+)%s*(.*)$")
    if name then
      name = lower(name)
      if not out[name] then
        local list = {}
        for token in rest:gmatch("%S+") do list[#list + 1] = token end
        out[name] = list
      end
    end
  end
  return out
end

local function has_source(list, source)
  for _, t in ipairs(list) do
    if lower(t) == source then return true end
  end
  return false
end

-- csp_allows reports whether the response's Content-Security-Policy (a
-- string, a list of them, or nil) lets the same-origin script run and
-- report, and the nonce the tag must carry (nil when none is needed).
-- script-src-elem, else script-src, else default-src: a nonce source
-- (reused), or 'self' or * without 'strict-dynamic'. connect-src, else
-- default-src: 'self' or *.
function _M.csp_allows(value)
  if value == nil then return true, nil end
  local policies = type(value) == "table" and value or { value }
  local nonce
  for _, policy in ipairs(policies) do
    if type(policy) ~= "string" then return false end
    local d = directives(policy)
    local script = d["script-src-elem"] or d["script-src"] or d["default-src"]
    local connect = d["connect-src"] or d["default-src"]
    if connect and not (has_source(connect, "'self'") or has_source(connect, "*")) then return false end
    if script then
      local found
      for _, t in ipairs(script) do
        local n = t:match("^'nonce%-([A-Za-z0-9+/=_-]+)'$")
        if n then found = n; break end
      end
      if found then
        if nonce and nonce ~= found then return false end
        nonce = found
      elseif has_source(script, "'strict-dynamic'")
        or not (has_source(script, "'self'") or has_source(script, "*")) then
        return false
      end
    end
  end
  return true, nonce
end

-- eligible reports whether a response of the site gets the script: status
-- 200 to a GET, text/html, no Content-Encoding or Content-Range, no
-- no-transform.
function _M.eligible(method, status, h)
  if method ~= "GET" or status ~= 200 then return false end
  local ct = h["Content-Type"]
  if type(ct) == "table" then ct = ct[1] end
  if type(ct) ~= "string" or not find(lower(ct), "^%s*text/html") then return false end
  local ce = h["Content-Encoding"]
  if ce ~= nil and ce ~= "" and lower(type(ce) == "table" and ce[1] or ce) ~= "identity" then return false end
  if h["Content-Range"] ~= nil then return false end
  local cc = h["Cache-Control"]
  if type(cc) == "table" then cc = concat(cc, ",") end
  if type(cc) == "string" and find(lower(cc), "no-transform", 1, true) then return false end
  return true
end

-- header_filter prepares the injection for an eligible response of a site
-- with session detection (edge layer, not subrequests).
function _M.header_filter(site)
  if ngx.is_subrequest then return end
  local ctx = ngx.ctx
  local path = ctx.edgeweir_original_path or ngx.var.uri
  if sub(path or "", 1, 11) == "/.edgeweir/" then return end
  local h = ngx.header
  if not _M.eligible(ngx.req.get_method(), ngx.status, h) then return end
  local ok, nonce = _M.csp_allows(h["Content-Security-Policy"])
  if not ok then return end
  local keys = challenge.keys()
  if not keys or not keys.current then return end
  ctx.edgeweir_inject = { tag = _M.tag(token(site, keys, "b"), nonce), tail = "", seen = 0 }
  h["Content-Length"] = nil
  local etag = h["ETag"]
  if type(etag) == "string" and sub(etag, 1, 2) ~= "W/" then h["ETag"] = "W/" .. etag end
end

-- inject is the body filter's step: state {tag, tail, seen, append, done},
-- a chunk and eof; returns what to send.
function _M.inject(st, chunk, eof)
  chunk = chunk or ""
  if st.done then return chunk end
  if st.append then
    if eof then st.done = true; return chunk .. st.tag end
    return chunk
  end
  local data = st.tail .. chunk
  local at = find(lower(data), "</head", 1, true)
  if at then
    st.done, st.tail = true, ""
    return sub(data, 1, at - 1) .. st.tag .. sub(data, at)
  end
  if eof then
    st.done, st.tail = true, ""
    return data .. st.tag
  end
  st.seen = st.seen + #chunk
  if st.seen > _M.SCAN_LIMIT then
    st.append, st.tail = true, ""
    return data
  end
  -- Keep the last bytes that may start "</head" for the next chunk.
  local keep = math.min(#data, 5)
  st.tail = sub(data, #data - keep + 1)
  return sub(data, 1, #data - keep)
end

-- body_filter adds the tag to the response header_filter prepared.
function _M.body_filter()
  local st = ngx.ctx.edgeweir_inject
  if not st or st.done then return end
  ngx.arg[1] = _M.inject(st, ngx.arg[1], ngx.arg[2])
end

return _M
