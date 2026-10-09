-- edgeweir.bots: verified search engine crawlers (proto v0.29.0, feature
-- challenge-v2, ADR-0040).
--
-- A request claims a crawler when its User-Agent contains one of the
-- crawler's tokens (ASCII case-insensitive; the first crawler of CRAWLERS
-- that matches). It is verified when a PTR lookup of ip.src gives a name
-- (one of the first three, lowercased, the trailing dot removed) equal to
-- one of the crawler's domains or ending in "." and the domain, and a
-- forward lookup of that name (A for IPv4 clients, AAAA for IPv6 clients)
-- holds ip.src: the method each search engine documents; no third-party IP
-- lists are downloaded. Lookups use the nameservers edgeweir.dns was
-- configured with (nginx.conf's resolver), 1000 ms per try, two tries.
--
-- Results are cached per address and crawler in lua_shared_dict
-- edgeweir_bots: verified 24 hours, not verified 1 hour, a failed lookup
-- (timeout, server error) 60 seconds. While one request looks an address
-- up, the others count as not verified and do not wait.
--
-- request() gives the request's http.request.bot.verified and
-- http.request.bot.name (computed once per request, only when asked):
-- edgeweir.policy reads them for rules, edgeweir.router for the sites that
-- let verified crawlers skip Under Attack and CC challenges.
local resolver = require("resty.dns.resolver")
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

local find, lower, gsub, sub = string.find, string.lower, string.gsub, string.sub

-- CRAWLERS: name, User-Agent tokens, the domains of their reverse names.
_M.CRAWLERS = {
  { name = "googlebot", tokens = { "googlebot", "storebot-google", "google-inspectiontool", "googleother", "google-cloudvertexbot" },
    domains = { "googlebot.com", "google.com", "googleusercontent.com" } },
  { name = "bingbot", tokens = { "bingbot" }, domains = { "search.msn.com" } },
  { name = "baiduspider", tokens = { "baiduspider" }, domains = { "baidu.com", "baidu.jp" } },
  { name = "yandexbot", tokens = { "yandex" }, domains = { "yandex.ru", "yandex.net", "yandex.com" } },
  { name = "applebot", tokens = { "applebot" }, domains = { "applebot.apple.com" } },
}

_M.VERIFIED_TTL = 86400
_M.REJECTED_TTL = 3600
_M.FAILED_TTL = 60
-- The longest a lookup may take (PTR and up to three forward lookups, two
-- tries of 1000 ms each) and then some: the in-flight mark's lifetime.
_M.FLIGHT_TTL = 10
_M.MAX_NAMES = 3

local by_name = {}
for _, c in ipairs(_M.CRAWLERS) do by_name[c.name] = c end

-- new_resolver returns the DNS resolver of a lookup (replaced in tests).
function _M.new_resolver()
  return resolver:new({ nameservers = require("edgeweir.dns").nameservers(), retrans = 2, timeout = 1000 })
end

local function dict()
  return ngx.shared.edgeweir_bots
end

-- claimed returns the crawler a User-Agent claims, or nil.
function _M.claimed(ua)
  if type(ua) == "table" then ua = ua[1] end
  if type(ua) ~= "string" or ua == "" then return nil end
  local l = lower(ua)
  for _, c in ipairs(_M.CRAWLERS) do
    for _, token in ipairs(c.tokens) do
      if find(l, token, 1, true) then return c end
    end
  end
  return nil
end

-- in_domains reports whether host is one of domains or ends in "." and
-- one of them.
function _M.in_domains(host, domains)
  for _, d in ipairs(domains) do
    if host == d or (#host > #d + 1 and sub(host, -(#d + 1)) == "." .. d) then return true end
  end
  return false
end

-- client returns the address bytes of addr (an IPv4-mapped IPv6 address
-- as IPv4) and its text for lookups.
local function client(addr)
  local b = ipaddr.parse(addr)
  if not b then return nil end
  local v4
  if #b == 16 and b[11] == 0xff and b[12] == 0xff then
    local mapped = true
    for i = 1, 10 do
      if b[i] ~= 0 then mapped = false break end
    end
    if mapped then v4 = { b[13], b[14], b[15], b[16] } end
  end
  if v4 then return v4, ipaddr.format(v4) end
  return b, addr
end

local function same(bytes, text)
  local b = ipaddr.parse(text)
  if not b or #b ~= #bytes then return false end
  for i = 1, #b do
    if b[i] ~= bytes[i] then return false end
  end
  return true
end

-- lookup verifies crawler c for the address: true, false, or nil and an
-- error when a lookup failed before anything verified it.
function _M.lookup(c, bytes, text)
  local r, err = _M.new_resolver()
  if not r then return nil, err end
  local answers, qerr = r:reverse_query(text)
  if not answers then return nil, qerr end
  if answers.errcode then
    if answers.errcode == 3 then return false end -- NXDOMAIN: no name
    return nil, answers.errstr or ("dns error " .. answers.errcode)
  end
  local names = {}
  for _, a in ipairs(answers) do
    if a.type == resolver.TYPE_PTR and type(a.ptrdname) == "string" then
      names[#names + 1] = lower((gsub(a.ptrdname, "%.$", "")))
      if #names >= _M.MAX_NAMES then break end
    end
  end
  local qtype = #bytes == 4 and resolver.TYPE_A or resolver.TYPE_AAAA
  local failed
  for _, host in ipairs(names) do
    if _M.in_domains(host, c.domains) then
      local fwd, ferr = r:query(host, { qtype = qtype })
      if not fwd then
        failed = ferr or "lookup failed"
      elseif fwd.errcode then
        if fwd.errcode ~= 3 then failed = fwd.errstr or ("dns error " .. fwd.errcode) end
      else
        for _, a in ipairs(fwd) do
          if (a.type == resolver.TYPE_A or a.type == resolver.TYPE_AAAA) and type(a.address) == "string" and same(bytes, a.address) then
            return true
          end
        end
      end
    end
  end
  if failed then return nil, failed end
  return false
end

-- verify reports whether addr is crawler name's (cached, see above).
function _M.verify(name, addr)
  local c = by_name[name]
  local bytes, text = client(addr)
  if not c or not bytes then return false end
  local d = dict()
  local key = "v|" .. text .. "|" .. name
  local cached = d:get(key)
  if cached ~= nil then return cached == 1 end
  local flight = "f|" .. text
  if not d:add(flight, true, _M.FLIGHT_TTL) then return false end
  local ok, result, err = pcall(_M.lookup, c, bytes, text)
  d:delete(flight)
  local value, ttl
  if ok and result == true then
    value, ttl = 1, _M.VERIFIED_TTL
  elseif ok and result == false then
    value, ttl = 0, _M.REJECTED_TTL
  else
    value, ttl = 2, _M.FAILED_TTL
    if d:safe_add("log|" .. name, true, 60) then
      ngx.log(ngx.NOTICE, "edgeweir: crawler verification failed crawler=", name, ": ", ok and tostring(err) or tostring(result))
    end
  end
  d:set(key, value, ttl)
  return value == 1
end

-- request returns whether the request comes from a verified crawler and
-- its name ("" when not), once per request.
function _M.request()
  local ctx = ngx.ctx
  local r = ctx.edgeweir_bot
  if r == nil then
    local var = ngx.var
    local c = _M.claimed(var.http_user_agent)
    local verified = c ~= nil and _M.verify(c.name, var.remote_addr)
    r = { verified = verified, name = verified and c.name or "" }
    ctx.edgeweir_bot = r
  end
  return r.verified, r.name
end

return _M
