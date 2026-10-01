-- edgeweir.challenge: challenges and passes.
--
-- Levels, in rising strength: cookie302 (1), js (2), pow (3), captcha (4);
-- a pass of level L satisfies every requirement up to L. The captcha
-- level can also be passed with the high-difficulty proof of work
-- ("pow_high" here), the accessible path next to the image.
--
-- Everything is stateless across nodes: challenge tokens and passes are
-- HMAC-SHA256 signed with the cluster's keys (the agent pushes them with
-- PUT /v1/challenge/keys: the current key signs, next, current and
-- previous verify).
--
--   pass cookie  __ew_pass=v1.<kid>.<b64url(site|level|prefix|ua|iat|exp)>.<b64url(sig)>
--                sig = HMAC(key, "v1.<kid>.<payload>")
--   token        <kid>.<b64url(site|type|level|prefix|ua|iat|exp|nonce|difficulty|answer)>.<b64url(sig)>
--                sig = HMAC(key, "c1.<kid>.<payload>"), valid 5 minutes
--
-- prefix is the client's /24 (IPv4) or /64 (IPv6) network ("4:a.b.c",
-- "6:<16 hex digits>"), ua the first 16 hex digits of sha256(User-Agent).
-- The answer of a captcha token is HMAC(key, "a|<nonce>|<ANSWER>") in hex:
-- any node holding the key can check it. Used nonces are kept in
-- lua_shared_dict edgeweir_challenge until the token expires, so a token
-- is redeemed once.
--
-- Reserved prefix /.edgeweir/ (never proxied):
--   POST /.edgeweir/challenge/verify     t (token), a (answer), r (return
--        path), alt=pow (captcha token: switch to the proof of work)
--   GET  /.edgeweir/challenge/worker.js  proof-of-work Web Worker
--   anything else                        404 not-found
local bit = require("bit")
local cjson = require("cjson.safe")
local b64 = require("ngx.base64")
local hmac = require("resty.openssl.hmac")
local rand = require("resty.openssl.rand")
local resty_sha256 = require("resty.sha256")
local str = require("resty.string")
local lrucache = require("resty.lrucache")
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

local byte, sub, find, format, concat = string.byte, string.sub, string.find, string.format, table.concat
local floor, max = math.floor, math.max
local tonumber, tostring, type = tonumber, tostring, type

_M.TYPES = { "cookie302", "js", "pow", "captcha" }
_M.LEVELS = { cookie302 = 1, js = 2, pow = 3, captcha = 4 }
_M.COOKIE = "__ew_pass"
_M.PREFIX = "/.edgeweir/"
_M.VERIFY = "/.edgeweir/challenge/verify"
_M.WORKER = "/.edgeweir/challenge/worker.js"
_M.TOKEN_TTL = 300
_M.DEFAULT_PASS_TTL = 1800
_M.DEFAULT_POW = 16
_M.DEFAULT_POW_HIGH = 20
_M.CAPTCHA_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

-- clock returns the current time in seconds (replaced in tests).
_M.clock = function()
  return ngx.time()
end

local function dict()
  return ngx.shared.edgeweir_challenge
end

local function valid_id(s)
  return type(s) == "string" and #s > 0 and #s <= 128 and not find(s, "[^A-Za-z0-9_-]")
end

-- ---------------------------------------------------------------------
-- Keys

-- validate_keys checks a PUT /v1/challenge/keys body:
-- {id, current, keys: [{id, secret (base64, at least 16 bytes)}]}.
function _M.validate_keys(doc)
  if type(doc) ~= "table" or type(doc.keys) ~= "table" then
    return nil, "keys must be an array"
  end
  local seen, list = {}, {}
  for _, k in ipairs(doc.keys) do
    if type(k) ~= "table" or not valid_id(k.id) or seen[k.id] or type(k.secret) ~= "string" then
      return nil, "invalid key"
    end
    local secret = ngx.decode_base64(k.secret)
    if not secret or #secret < 16 or #secret > 256 then
      return nil, "invalid key secret"
    end
    seen[k.id] = true
    list[#list + 1] = { id = k.id, secret = k.secret }
  end
  local current = doc.current
  if current == nil or current == cjson.null then current = "" end
  if type(current) ~= "string" or (current ~= "" and not seen[current]) then
    return nil, "current key missing"
  end
  local id = doc.id
  if id == nil or id == cjson.null then id = "" end
  if type(id) ~= "string" or #id > 128 then
    return nil, "invalid key set id"
  end
  return { id = id, current = current, keys = list }
end

-- replace_keys installs the keys (control API).
function _M.replace_keys(doc)
  local set, err = _M.validate_keys(doc)
  if not set then return nil, err, 400 end
  local d = dict()
  local ok, serr = d:safe_set("#keys", cjson.encode(set))
  if not ok then
    return nil, "shared dict edgeweir_challenge: " .. tostring(serr), serr == "no memory" and 507 or 500
  end
  d:incr("#kver", 1, 0)
  return _M.status()
end

local kcache = { ver = false }

-- keys returns {current = key or nil, by_id = {id = key}} with key =
-- {id, secret}, or nil when the node has none. Cached per worker.
function _M.keys()
  local d = dict()
  local ver = d:get("#kver")
  if not ver then return nil end
  if kcache.ver ~= ver then
    local set = cjson.decode(d:get("#keys") or "")
    local keys = { by_id = {} }
    if type(set) == "table" then
      for _, k in ipairs(set.keys or {}) do
        local key = { id = k.id, secret = ngx.decode_base64(k.secret) }
        keys.by_id[k.id] = key
        if k.id == set.current then keys.current = key end
      end
    end
    kcache = { ver = ver, keys = next(keys.by_id) and keys or nil }
  end
  return kcache.keys
end

-- ---------------------------------------------------------------------
-- Captcha pool

local ANSWER_LEN = 5

-- replace_captchas installs the agent's captcha pool:
-- {id, images: [{answer, png (base64)}]}.
function _M.replace_captchas(doc)
  if type(doc) ~= "table" or type(doc.images) ~= "table" or #doc.images > 1024 then
    return nil, "images must be an array of at most 1024", 400
  end
  if type(doc.id) ~= "string" or #doc.id > 128 then
    return nil, "invalid pool id", 400
  end
  for _, img in ipairs(doc.images) do
    if type(img) ~= "table" or type(img.answer) ~= "string" or #img.answer ~= ANSWER_LEN
      or find(img.answer, "[^" .. _M.CAPTCHA_ALPHABET .. "]") or type(img.png) ~= "string"
      or #img.png > 65536 or find(img.png, "[^A-Za-z0-9+/=]") then
      return nil, "invalid captcha image", 400
    end
  end
  local d = dict()
  local old = d:get("#cn") or 0
  d:set("#cid", "")
  for i, img in ipairs(doc.images) do
    local ok, err = d:safe_set("c|" .. i, img.answer .. img.png)
    if not ok then
      d:set("#cn", math.min(old, i - 1))
      return nil, "shared dict edgeweir_challenge: " .. tostring(err), err == "no memory" and 507 or 500
    end
  end
  d:set("#cn", #doc.images)
  for i = #doc.images + 1, old do d:delete("c|" .. i) end
  d:set("#cid", doc.id)
  return _M.status()
end

-- pick_captcha returns a random image of the pool: answer, base64 PNG.
function _M.pick_captcha()
  local d = dict()
  local n = d:get("#cn") or 0
  if n < 1 then return nil end
  local v = d:get("c|" .. math.random(n))
  if not v then return nil end
  return sub(v, 1, ANSWER_LEN), sub(v, ANSWER_LEN + 1)
end

-- status is GET /v1/challenge.
function _M.status()
  local d = dict()
  local set = cjson.decode(d:get("#keys") or "") or {}
  local ids = {}
  for _, k in ipairs(set.keys or {}) do ids[#ids + 1] = k.id end
  if cjson.empty_array_mt and #ids == 0 then setmetatable(ids, cjson.empty_array_mt) end
  return {
    keys_id = set.id or "", current = set.current or "", keys = ids,
    captchas = d:get("#cn") or 0, captchas_id = d:get("#cid") or "",
    nonce_overflow = d:get("#nonce_overflow") or 0,
  }
end

-- ---------------------------------------------------------------------
-- Primitives

local function mac(key, msg)
  local h = key.mac
  if h then
    assert(h:reset())
  else
    h = assert(hmac.new(key.secret, "sha256"))
    key.mac = h
  end
  return assert(h:final(msg))
end
-- mac is HMAC-SHA256 with a key of keys() (edgeweir.affinity signs with it).
_M.mac = mac

local function sha256(s)
  local h = resty_sha256:new()
  h:update(s)
  return h:final()
end
_M.sha256 = sha256

function _M.sha256_hex(s)
  return str.to_hex(sha256(s))
end

-- equal compares two strings without an early exit.
local function equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(byte(a, i), byte(b, i)))
  end
  return diff == 0
end
_M.equal = equal

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

-- client_prefix returns the network of addr that passes are bound to:
-- "4:a.b.c" (/24; IPv4-mapped IPv6 counts as IPv4) or "6:<hex of /64>".
function _M.client_prefix(addr)
  local b = ipaddr.parse(addr)
  if not b then return nil end
  if #b == 16 then
    local mapped = b[11] == 255 and b[12] == 255
    for i = 1, 10 do
      if b[i] ~= 0 then mapped = false; break end
    end
    if mapped then b = { b[13], b[14], b[15], b[16] } end
  end
  if #b == 4 then
    return "4:" .. b[1] .. "." .. b[2] .. "." .. b[3]
  end
  return format("6:%02x%02x%02x%02x%02x%02x%02x%02x", b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8])
end

-- ua_hash returns the first 16 hex digits of sha256(User-Agent).
function _M.ua_hash(ua)
  if type(ua) == "table" then ua = ua[1] end
  return sub(_M.sha256_hex(type(ua) == "string" and ua or ""), 1, 16)
end

local caches = {}
local function cache(name, size)
  local c = caches[name]
  if not c then
    c = assert(lrucache.new(size))
    caches[name] = c
  end
  return c
end

-- forget drops the worker caches (tests).
function _M.forget()
  caches, kcache = {}, { ver = false }
end

local function prefix_of(addr)
  local c = cache("prefixes", 10000)
  local p = c:get(addr)
  if not p then
    p = _M.client_prefix(addr) or "-"
    c:set(addr, p)
  end
  return p
end

local function ua_of(ua)
  if type(ua) == "table" then ua = ua[1] end
  ua = ua or ""
  local c = cache("uas", 4000)
  local h = c:get(ua)
  if not h then
    h = _M.ua_hash(ua)
    c:set(ua, h)
  end
  return h
end

-- ---------------------------------------------------------------------
-- Passes

function _M.sign_pass(key, site_id, level, prefix, uah, iat, exp)
  local payload = b64.encode_base64url(concat({ site_id, level, prefix, uah, iat, exp }, "|"))
  local head = "v1." .. key.id .. "." .. payload
  return head .. "." .. b64.encode_base64url(mac(key, head))
end

-- parse_pass checks the signature of a pass and returns its fields, or
-- nil and a reason.
function _M.parse_pass(keys, value)
  if type(value) ~= "string" or #value > 1024 then return nil, "malformed" end
  local kid, payload, sig = value:match("^v1%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  if not kid then return nil, "malformed" end
  local key = keys and keys.by_id[kid]
  if not key then return nil, "unknown key" end
  if not equal(b64.encode_base64url(mac(key, "v1." .. kid .. "." .. payload)), sig) then
    return nil, "bad signature"
  end
  local f = split(b64.decode_base64url(payload) or "", 6)
  if not f then return nil, "malformed" end
  local level, iat, exp = tonumber(f[2]), tonumber(f[5]), tonumber(f[6])
  if not level or not iat or not exp then return nil, "malformed" end
  return { kid = kid, site = f[1], level = level, prefix = f[3], ua = f[4], iat = iat, exp = exp }
end

-- check_pass reports whether a parsed pass holds for site, client and time.
function _M.check_pass(p, site_id, prefix, uah, now)
  if p.site ~= site_id then return false, "site" end
  if p.exp <= now then return false, "expired" end
  if p.prefix ~= prefix then return false, "prefix" end
  if p.ua ~= uah then return false, "user agent" end
  return true
end

-- pass_level returns the level of the request's valid pass for site (0
-- without one). Verified passes are cached per worker for up to a minute;
-- the result is kept in ngx.ctx for the rest of the request.
function _M.pass_level(site)
  local ctx = ngx.ctx
  local level = rawget(ctx, "edgeweir_pass")
  if level then return level end
  level = 0
  local var = ngx.var
  local cookie = var["cookie_" .. _M.COOKIE]
  if cookie and #cookie <= 1024 then
    local passes = cache("passes", 10000)
    local now = _M.clock()
    local p = passes:get(cookie)
    if not p then
      p = _M.parse_pass(_M.keys(), cookie)
      if p and p.exp > now then
        passes:set(cookie, p, math.min(p.exp - now, 60))
      end
    end
    if p and _M.check_pass(p, site.id, prefix_of(var.remote_addr), ua_of(var.http_user_agent), now) then
      level = p.level
    end
  end
  ctx.edgeweir_pass = level
  return level
end

-- pass_ttl returns the lifetime of the site's passes.
local function pass_ttl(site)
  local p = site.protection
  return p and tonumber(p.pass_ttl) or _M.DEFAULT_PASS_TTL
end

-- pass_cookie returns the Set-Cookie value of a new pass.
function _M.pass_cookie(value, ttl, https)
  return _M.COOKIE .. "=" .. value .. "; Path=/; Max-Age=" .. ttl .. "; HttpOnly; SameSite=Lax" .. (https and "; Secure" or "")
end

-- ---------------------------------------------------------------------
-- Challenge tokens

-- sign_token signs f = {site, type, level, prefix, ua, iat, exp, nonce,
-- difficulty, answer}.
function _M.sign_token(key, f)
  local payload = b64.encode_base64url(concat({
    f.site, f.type, f.level, f.prefix, f.ua, f.iat, f.exp, f.nonce, f.difficulty or 0, f.answer or "",
  }, "|"))
  local head = key.id .. "." .. payload
  return head .. "." .. b64.encode_base64url(mac(key, "c1." .. head))
end

-- parse_token checks a token's signature and returns its fields.
function _M.parse_token(keys, token)
  if type(token) ~= "string" or #token > 2048 then return nil, "malformed" end
  local kid, payload, sig = token:match("^([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)%.([A-Za-z0-9_-]+)$")
  if not kid then return nil, "malformed" end
  local key = keys and keys.by_id[kid]
  if not key then return nil, "unknown key" end
  if not equal(b64.encode_base64url(mac(key, "c1." .. kid .. "." .. payload)), sig) then
    return nil, "bad signature"
  end
  local f = split(b64.decode_base64url(payload) or "", 10)
  if not f then return nil, "malformed" end
  local out = {
    kid = kid, site = f[1], type = f[2], level = tonumber(f[3]), prefix = f[4], ua = f[5],
    iat = tonumber(f[6]), exp = tonumber(f[7]), nonce = f[8], difficulty = tonumber(f[9]), answer = f[10],
  }
  if not out.level or not out.iat or not out.exp or not out.difficulty or not _M.LEVELS[out.type] then
    return nil, "malformed"
  end
  return out
end

function _M.check_token(f, site_id, prefix, uah, now)
  if f.site ~= site_id then return false, "site" end
  if f.exp <= now then return false, "expired" end
  if f.prefix ~= prefix then return false, "prefix" end
  if f.ua ~= uah then return false, "user agent" end
  return true
end

-- consume records a token's nonce until the token expires; false when it
-- was used before. When the store is full even after dropping expired
-- nonces, the token is accepted (it is bound to the client's network and
-- User-Agent, like the pass it buys) and the overflow is counted.
function _M.consume(nonce, exp, now)
  local d = dict()
  local ttl = max(exp - now, 1)
  local ok, err = d:safe_add("n|" .. nonce, true, ttl)
  if ok then return true end
  if err == "exists" then return false end
  d:flush_expired(1000)
  ok, err = d:safe_add("n|" .. nonce, true, ttl)
  if ok then return true end
  if err == "exists" then return false end
  d:incr("#nonce_overflow", 1, 0)
  return true
end

-- leading_zero_bits counts the leading zero bits of a byte string.
function _M.leading_zero_bits(s)
  local bits = 0
  for i = 1, #s do
    local b = byte(s, i)
    if b ~= 0 then
      while b < 128 do
        bits = bits + 1
        b = b * 2
      end
      return bits
    end
    bits = bits + 8
  end
  return bits
end

-- pow_ok checks a proof of work: sha256(token ":" n) has at least
-- difficulty leading zero bits (n: decimal, at most 16 digits).
function _M.pow_ok(token, n, difficulty)
  if type(n) ~= "string" or not n:match("^%d+$") or #n > 16 then return false end
  return _M.leading_zero_bits(sha256(token .. ":" .. n)) >= difficulty
end

-- captcha_answer is the signed form of a captcha answer.
function _M.captcha_answer(key, nonce, answer)
  return sub(str.to_hex(mac(key, "a|" .. nonce .. "|" .. answer)), 1, 32)
end

-- captcha_ok checks a submitted answer (case and surrounding blanks do
-- not matter).
function _M.captcha_ok(key, f, answer)
  if not key or type(answer) ~= "string" or #answer > 64 then return false end
  answer = answer:gsub("%s", ""):upper()
  if #answer ~= ANSWER_LEN then return false end
  return equal(_M.captcha_answer(key, f.nonce, answer), f.answer)
end

-- return_url accepts a path on this site: one leading "/" (not "//"), no
-- backslash, blanks or control characters, not under the reserved prefix.
function _M.return_url(r)
  if type(r) ~= "string" or #r == 0 or #r > 2048 then return nil end
  if byte(r, 1) ~= 47 or byte(r, 2) == 47 or byte(r, 2) == 92 then return nil end
  if find(r, "[%z\1-\32\127\\]") then return nil end
  if sub(r, 1, #_M.PREFIX) == _M.PREFIX then return nil end
  return r
end

-- language picks "zh" or "en" from Accept-Language (highest q wins, the
-- first on ties; English without a match).
function _M.language(header)
  if type(header) == "table" then header = concat(header, ",") end
  if type(header) ~= "string" then return "en" end
  local best, bestq = "en", 0
  for item in sub(header, 1, 512):gmatch("[^,]+") do
    local tag, params = item:match("^%s*([%a%-%*]+)%s*(.*)$")
    if tag then
      local q = 1
      local qs = params:match("[qQ]%s*=%s*([%d%.]+)")
      if qs then q = tonumber(qs) or 0 end
      local primary = tag:lower():match("^(%a+)")
      if (primary == "zh" or primary == "en") and q > bestq then
        best, bestq = primary, q
      end
    end
  end
  return best
end

-- ---------------------------------------------------------------------
-- Pages

local SHA = [[var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2],IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],W=new Int32Array(64);
function blk(h,m,o){var i,x,y,a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],k=h[7],t,u;for(i=0;i<16;i++)W[i]=m[o+4*i]<<24|m[o+4*i+1]<<16|m[o+4*i+2]<<8|m[o+4*i+3];for(i=16;i<64;i++){x=W[i-15];y=W[i-2];W[i]=((x>>>7|x<<25)^(x>>>18|x<<14)^x>>>3)+((y>>>17|y<<15)^(y>>>19|y<<13)^y>>>10)+W[i-7]+W[i-16]|0}for(i=0;i<64;i++){t=k+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+(e&f^~e&g)+K[i]+W[i]|0;u=((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+(a&b^a&c^b&c)|0;k=g;g=f;f=e;e=d+t|0;d=c;c=b;b=a;a=t+u|0}h[0]=h[0]+a|0;h[1]=h[1]+b|0;h[2]=h[2]+c|0;h[3]=h[3]+d|0;h[4]=h[4]+e|0;h[5]=h[5]+f|0;h[6]=h[6]+g|0;h[7]=h[7]+k|0}
function fin(h,t,l,n){var e=l+9>64?128:64,i,b=n*8;t[l]=128;for(i=l+1;i<e;i++)t[i]=0;t[e-4]=b>>>24&255;t[e-3]=b>>>16&255;t[e-2]=b>>>8&255;t[e-1]=b&255;t[e-5]=b/4294967296&255;blk(h,t,0);if(e>64)blk(h,t,64)}
function bytes(s){var b=new Uint8Array(s.length),i;for(i=0;i<s.length;i++)b[i]=s.charCodeAt(i)&255;return b}
function sha256hex(s){var m=bytes(s),h=new Int32Array(IV),i=0,t=new Uint8Array(128),o='';for(;i+64<=m.length;i+=64)blk(h,m,i);t.set(m.subarray(i));fin(h,t,m.length-i,m.length);for(i=0;i<8;i++)o+=('0000000'+(h[i]>>>0).toString(16)).slice(-8);return o}
function solve(s,d,n,z){var m=bytes(s+':'),p=new Int32Array(IV),i=0,b,r,t=new Uint8Array(128),h=new Int32Array(8),q=32-d,x,j;for(;i+64<=m.length;i+=64)blk(p,m,i);b=m.subarray(i);r=b.length;for(;n<z;n++){x=''+n;t.set(b);for(j=0;j<x.length;j++)t[r+j]=x.charCodeAt(j);h.set(p);fin(h,t,r+x.length,m.length+x.length);if(h[0]>>>q===0)return n}return -1}
]]

-- The proof-of-work Web Worker: finds n for {t, d} and posts {n}.
_M.WORKER_JS = SHA .. [[onmessage=function(e){var t=e.data.t,d=e.data.d,n=0,r;for(;;){r=solve(t,d,n,n+262144);if(r>=0){postMessage({n:r});return}n+=262144}};
]]

-- JS: sha256 of the token, with WebCrypto where the page is a secure
-- context and the script's own SHA-256 otherwise (plain HTTP).
local JS_MAIN = [[(function(){var f=document.getElementById('f'),t=f.t.value;function go(h){f.a.value=h;f.submit()}
try{if(window.crypto&&crypto.subtle&&window.TextEncoder){crypto.subtle.digest('SHA-256',new TextEncoder().encode(t)).then(function(b){var a=new Uint8Array(b),s='',i;for(i=0;i<a.length;i++)s+=(a[i]<16?'0':'')+a[i].toString(16);go(s)},function(){go(sha256hex(t))});return}}catch(e){}
go(sha256hex(t))})();
]]

-- PoW: a Web Worker from the reserved prefix; in slices on the page when
-- workers are unavailable.
local POW_MAIN = [[(function(){var f=document.getElementById('f'),t=f.t.value,d=+f.getAttribute('data-d'),w,done=false;function go(n){if(done)return;done=true;f.a.value=n;f.submit()}
function slow(n){var r=solve(t,d,n,n+32768);if(r>=0)go(r);else setTimeout(function(){slow(n+32768)},0)}
try{w=new Worker(']] .. _M.WORKER .. [[')}catch(e){w=null}
if(w){w.onmessage=function(e){if(e.data&&typeof e.data.n==='number'){w.terminate();go(e.data.n)}};w.onerror=function(){w.terminate();slow(0)};w.postMessage({t:t,d:d})}else slow(0)})();
]]

local STYLE = [[:root{color-scheme:light dark;--bg:#f5f6f8;--fg:#16181c;--mute:#5d636d;--card:#fff;--line:#e2e5e9;--accent:#2f6fed;--err:#c23a2b}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--fg:#e7e9ec;--mute:#9aa1ab;--card:#161a20;--line:#2a2f37;--accent:#6d9bff;--err:#ff7a6a}}
*{box-sizing:border-box}html,body{margin:0;min-height:100%}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{width:100%;max-width:380px;padding:28px;background:var(--card);border:1px solid var(--line);border-radius:14px}
h1{margin:0 0 18px;font-size:18px;font-weight:600}
.bar{height:4px;overflow:hidden;border-radius:2px;background:var(--line)}
.bar i{display:block;width:35%;height:100%;border-radius:2px;background:var(--accent);animation:run 1.2s ease-in-out infinite}
@keyframes run{from{transform:translateX(-100%)}to{transform:translateX(290%)}}
@media (prefers-reduced-motion:reduce){.bar i{width:100%;opacity:.45;animation:none}}
img{display:block;width:100%;max-width:320px;height:auto;border:1px solid var(--line);border-radius:8px;background:#fff}
label{display:block;margin:14px 0 6px;color:var(--mute);font-size:13px}
input[type=text]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;font-size:18px;letter-spacing:.2em;text-transform:uppercase}
input[type=text]:focus{outline:2px solid var(--accent);outline-offset:1px}
button{font:inherit;cursor:pointer}
.go{width:100%;margin-top:14px;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-weight:600}
.alt{margin-top:12px;padding:0;border:0;background:none;color:var(--accent);font-size:13px;text-decoration:underline}
.err{margin:0 0 14px;color:var(--err);font-size:13px}
p{margin:14px 0 0;color:var(--mute);font-size:13px}
footer{margin-top:22px;color:var(--mute);font-size:12px;font-variant-numeric:tabular-nums}
]]

local TEXT = {
  zh = {
    lang = "zh-CN", title = "安全检查", verify = "正在验证浏览器", captcha = "输入图中字符", code = "验证码",
    submit = "继续", alt = "改用计算验证", image = "验证码图片；无法识别时可改用计算验证",
    noscript = "请启用 JavaScript 后刷新页面。", wrong = "验证码不正确，请重试。", failed = "验证未通过，请重试。",
  },
  en = {
    lang = "en", title = "Security check", verify = "Verifying your browser", captcha = "Enter the characters shown",
    code = "Code", submit = "Continue", alt = "Use a computation instead",
    image = "Captcha image; use the computation option if you cannot read it",
    noscript = "Enable JavaScript and reload the page.", wrong = "That code was not right. Try again.",
    failed = "Verification failed. Try again.",
  },
}

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }
local function esc(s)
  return (tostring(s or ""):gsub("[&<>\"']", ESCAPES))
end
_M.escape = esc

-- csp is the Content-Security-Policy of a challenge page.
function _M.csp(nonce)
  return "default-src 'none'; script-src 'nonce-" .. nonce .. "'; style-src 'nonce-" .. nonce
    .. "'; img-src data:; connect-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
end

local function hidden(name, value)
  return '<input type="hidden" name="' .. name .. '" value="' .. esc(value) .. '">'
end

-- page renders a challenge page. o = {lang, kind (js, pow, captcha),
-- token, ret, difficulty, image (base64 PNG), nonce, error, id}.
function _M.page(o)
  local t = TEXT[o.lang] or TEXT.en
  local out = {
    '<!doctype html><html lang="', t.lang, '"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">',
    "<title>", t.title, '</title><style nonce="', o.nonce, '">', STYLE, "</style></head><body><main>",
  }
  local function add(...)
    for _, s in ipairs({ ... }) do out[#out + 1] = s end
  end
  local script
  if o.kind == "captcha" then
    add("<h1>", t.captcha, "</h1>")
    if o.error then add('<p class="err" role="alert">', t.wrong, "</p>") end
    add('<form method="post" action="', _M.VERIFY, '">',
      '<img src="data:image/png;base64,', o.image, '" alt="', esc(t.image), '" width="160" height="60">',
      '<label for="a">', t.code, "</label>",
      '<input type="text" id="a" name="a" required maxlength="8" autocomplete="off" autocapitalize="characters" spellcheck="false" autofocus>',
      hidden("t", o.token), hidden("r", o.ret),
      '<button class="go" type="submit">', t.submit, "</button></form>",
      '<form method="post" action="', _M.VERIFY, '">', hidden("t", o.token), hidden("r", o.ret), hidden("alt", "pow"),
      '<button class="alt" type="submit">', t.alt, "</button></form>")
  else
    add("<h1>", t.verify, "</h1>")
    if o.error then add('<p class="err" role="alert">', t.failed, "</p>") end
    add('<div class="bar" role="progressbar" aria-label="', t.verify, '"><i></i></div>',
      '<form id="f" method="post" action="', _M.VERIFY, '"')
    if o.kind == "pow" then add(' data-d="', tostring(o.difficulty), '"') end
    add(">", hidden("t", o.token), hidden("r", o.ret), hidden("a", ""), "</form>",
      "<noscript><p>", t.noscript, "</p></noscript>")
    script = SHA .. (o.kind == "pow" and POW_MAIN or JS_MAIN)
  end
  add("<footer>Edgeweir", o.id and o.id ~= "" and (" · " .. esc(o.id)) or "", "</footer></main>")
  if script then add('<script nonce="', o.nonce, '">', script, "</script>") end
  add("</body></html>")
  return concat(out)
end

-- ---------------------------------------------------------------------
-- Responses

local function text(status, headers, body)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store, private"
  for k, v in pairs(headers) do ngx.header[k] = v end
  if ngx.req.get_method() ~= "HEAD" then ngx.print(body, "\n") end
  return ngx.exit(ngx.HTTP_OK)
end

local function unavailable()
  return text(503, { ["X-Edgeweir-Error"] = "challenge-unavailable" }, "challenge unavailable")
end

-- location returns an absolute Location on the host the client asked
-- for (nginx would otherwise build one from the listening port).
local function location(path)
  local var = ngx.var
  local host = var.http_host
  if type(host) == "string" and #host <= 300 and not find(host, "[^%w%.%-:%[%]]") then
    return var.scheme .. "://" .. host .. path
  end
  return path
end

local function redirect(status, path, cookie)
  ngx.header["Cache-Control"] = "no-store, private"
  if cookie then ngx.header["Set-Cookie"] = cookie end
  return ngx.redirect(location(path), status)
end

-- difficulty returns the proof-of-work bits of site for kind.
local function difficulty(site, high)
  local p = site.protection
  if high then return p and tonumber(p.pow_high) or _M.DEFAULT_POW_HIGH end
  return p and tonumber(p.pow) or _M.DEFAULT_POW
end

-- render answers with a challenge page of kind (js, pow, pow_high,
-- captcha) at level for the return path ret.
local function render(site, keys, kind, level, ret, failed)
  local var = ngx.var
  local now = _M.clock()
  local f = {
    site = site.id, type = kind, level = level, prefix = prefix_of(var.remote_addr),
    ua = ua_of(var.http_user_agent), iat = now, exp = now + _M.TOKEN_TTL,
    nonce = b64.encode_base64url(assert(rand.bytes(12))), difficulty = 0, answer = "",
  }
  local image
  if kind == "captcha" then
    local answer
    answer, image = _M.pick_captcha()
    if answer then
      f.answer = _M.captcha_answer(keys.current, f.nonce, answer)
    else
      kind = "pow_high" -- no pool yet: the accessible alternative
    end
  end
  if kind == "pow_high" then
    f.type, f.difficulty = "pow", difficulty(site, true)
  elseif kind == "pow" then
    f.difficulty = difficulty(site, false)
  end
  local nonce = ngx.encode_base64(assert(rand.bytes(16)))
  local h = ngx.header
  ngx.status = 403
  h["Content-Type"] = "text/html; charset=utf-8"
  h["Cache-Control"] = "no-store, private"
  h["Content-Security-Policy"] = _M.csp(nonce)
  h["X-Content-Type-Options"] = "nosniff"
  h["Referrer-Policy"] = "same-origin"
  h["X-Edgeweir-Challenge"] = f.type
  if ngx.req.get_method() ~= "HEAD" then
    ngx.print(_M.page({
      lang = _M.language(var.http_accept_language), kind = f.type, token = _M.sign_token(keys.current, f),
      ret = ret, difficulty = f.difficulty, image = image, nonce = nonce, error = failed, id = var.request_id,
    }))
  end
  return ngx.exit(ngx.HTTP_OK)
end

-- kind_for returns the challenge of a level: its type, or pow_high for
-- the captcha level when high_pow is set.
function _M.kind_for(level, high_pow)
  if level >= 4 and high_pow then return "pow_high" end
  return _M.TYPES[level]
end

-- respond challenges the request at level with kind (cookie302, js, pow,
-- pow_high or captcha). Requests other than GET and HEAD get 403 with
-- X-Edgeweir-Challenge: required; without keys 503.
function _M.respond(site, kind, level)
  local keys = _M.keys()
  if not keys or not keys.current then return unavailable() end
  local method = ngx.req.get_method()
  if method ~= "GET" and method ~= "HEAD" then
    return text(403, { ["X-Edgeweir-Challenge"] = "required" }, "challenge required")
  end
  local var = ngx.var
  local ret = _M.return_url(var.request_uri) or "/"
  if kind == "cookie302" then
    local now = _M.clock()
    local ttl = pass_ttl(site)
    local value = _M.sign_pass(keys.current, site.id, max(level, 1), prefix_of(var.remote_addr),
      ua_of(var.http_user_agent), now, now + ttl)
    ngx.header["X-Edgeweir-Challenge"] = "cookie302"
    return redirect(302, ret, _M.pass_cookie(value, ttl, var.scheme == "https"))
  end
  return render(site, keys, kind, level, ret, false)
end

local function field(args, name)
  local v = args[name]
  if type(v) == "table" then v = v[1] end
  if type(v) ~= "string" then return nil end
  return v
end

-- verify redeems a challenge token (POST /.edgeweir/challenge/verify).
local function verify(site)
  local var = ngx.var
  if ngx.req.get_method() ~= "POST" then
    return text(405, { Allow = "POST", ["X-Edgeweir-Error"] = "method-not-allowed" }, "method not allowed")
  end
  local length = tonumber(var.content_length)
  if length and length > 4096 then
    return text(413, { ["X-Edgeweir-Error"] = "too-large" }, "request too large")
  end
  ngx.req.read_body()
  local args = ngx.req.get_post_args(8) or {}
  local token, answer = field(args, "t"), field(args, "a")
  local ret = _M.return_url(field(args, "r")) or "/"
  local keys = _M.keys()
  if not keys or not keys.current then return unavailable() end
  local now = _M.clock()
  local prefix, uah = prefix_of(var.remote_addr), ua_of(var.http_user_agent)
  local f = _M.parse_token(keys, token)
  if not f or not _M.check_token(f, site.id, prefix, uah, now) then
    return redirect(303, ret) -- a new challenge on the page itself
  end
  local kind = (f.type == "pow" and f.level >= 4) and "pow_high" or f.type
  if field(args, "alt") == "pow" and f.type == "captcha" then
    return render(site, keys, "pow_high", f.level, ret, false)
  end
  if not _M.consume(f.nonce, f.exp, now) then
    return redirect(303, ret)
  end
  local ok
  if f.type == "js" then
    ok = equal(answer, _M.sha256_hex(token))
  elseif f.type == "pow" then
    ok = _M.pow_ok(token, answer, f.difficulty)
  elseif f.type == "captcha" then
    ok = _M.captcha_ok(keys.by_id[f.kid], f, answer)
  end
  if not ok then
    return render(site, keys, kind, f.level, ret, true)
  end
  local level = max(f.level, _M.pass_level(site))
  local ttl = pass_ttl(site)
  local value = _M.sign_pass(keys.current, site.id, level, prefix, uah, now, now + ttl)
  return redirect(303, ret, _M.pass_cookie(value, ttl, var.scheme == "https"))
end

-- reserved handles a request under /.edgeweir/ (never proxied).
function _M.reserved(site)
  local uri = ngx.var.uri
  if uri == _M.VERIFY then
    return verify(site)
  end
  if uri == _M.WORKER then
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
      return text(405, { Allow = "GET, HEAD", ["X-Edgeweir-Error"] = "method-not-allowed" }, "method not allowed")
    end
    local h = ngx.header
    h["Content-Type"] = "application/javascript; charset=utf-8"
    h["Cache-Control"] = "public, max-age=3600"
    h["Content-Security-Policy"] = "default-src 'none'"
    h["X-Content-Type-Options"] = "nosniff"
    if method ~= "HEAD" then ngx.print(_M.WORKER_JS) end
    return ngx.exit(ngx.HTTP_OK)
  end
  return text(404, { ["X-Edgeweir-Error"] = "not-found" }, "not found")
end

-- required returns the level and challenge the site asks of requests
-- without a sufficient pass (platform and site Under Attack, CC levels
-- from cc_level(site)); 0 when none.
function _M.required(site, cc_level)
  local level, kind = 0, nil
  local cfg = site._config
  local pp = cfg and cfg.platform_protection
  if type(pp) == "table" and pp.under_attack == true then
    level, kind = _M.LEVELS[pp.challenge] or 2, _M.LEVELS[pp.challenge] and pp.challenge or "js"
  end
  local p = site.protection
  if type(p) == "table" then
    if p.under_attack == true then
      local l = _M.LEVELS[p.under_attack_challenge] or 2
      if l > level then level, kind = l, _M.TYPES[l] end
    end
    if p.cc and cc_level and cc_level > level then
      level, kind = cc_level, _M.kind_for(cc_level, p.cc.high_pow == true)
    end
  end
  return level, kind
end

return _M
