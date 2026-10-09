-- edgeweir.dns: resolves origin host names for the balancer.
--
-- balancer_by_lua cannot resolve names (no cosockets), so the origin layer
-- resolves every candidate in the access phase with lua-resty-dns and
-- caches answers per worker for min(TTL, 30 s) (failures for 5 s), the same
-- validity nginx's own resolver used before. A failing origin's entry is
-- dropped so that the next attempt resolves it again (containers and cloud
-- instances change addresses on restart).
--
-- Every answer and every IP literal goes through the origin address policy
-- (edgeweir.ipaddr): special-purpose addresses outside the allow list are
-- dropped; when nothing is left the attempt fails (address_forbidden), so a
-- DNS name can never point an origin at the node itself or its network.
local resolver = require("resty.dns.resolver")
local lrucache = require("resty.lrucache")
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

local MAX_TTL, NEGATIVE_TTL = 30, 5

local nameservers = { "127.0.0.1" }
local ipv6 = false
local cache

local function lru()
  if not cache then
    cache = assert(lrucache.new(4096))
  end
  return cache
end

-- configure sets the nameservers (addresses as in nginx's `resolver`,
-- IPv6 in brackets) and whether AAAA records are used.
function _M.configure(servers, use_ipv6)
  local list = {}
  for _, s in ipairs(servers or {}) do
    list[#list + 1] = (s:gsub("^%[(.*)%]$", "%1"))
  end
  if #list > 0 then
    nameservers = list
  end
  ipv6 = use_ipv6 == true
end

-- nameservers returns the configured nameservers (edgeweir.bots looks
-- crawlers up with them).
function _M.nameservers()
  return nameservers
end

local function is_ip(host)
  if host:find("^%d+%.%d+%.%d+%.%d+$") then
    return true
  end
  return host:find(":", 1, true) ~= nil
end

-- query returns the A or AAAA addresses of host (replaceable in tests).
function _M.query(host, qtype)
  local r, err = resolver:new({ nameservers = nameservers, retrans = 2, timeout = 2000 })
  if not r then
    return nil, err
  end
  local answers, qerr = r:query(host, { qtype = qtype })
  if not answers then
    return nil, qerr
  end
  if answers.errcode then
    return nil, answers.errstr or ("dns error " .. answers.errcode)
  end
  local addrs, ttl = {}, MAX_TTL
  for _, a in ipairs(answers) do
    if a.address and (a.type == resolver.TYPE_A or a.type == resolver.TYPE_AAAA) then
      addrs[#addrs + 1] = a.address
      if a.ttl and a.ttl < ttl then
        ttl = math.max(a.ttl, 1)
      end
    end
  end
  if #addrs == 0 then
    return nil, "no address"
  end
  return addrs, nil, ttl
end

local function forbidden_error(host, address)
  local what = (address == host) and ("address " .. address) or ("dns " .. host .. ": every address (e.g. " .. address .. ")")
  return nil, what .. " is a special-purpose address outside the origin allow list", "address_forbidden",
    { address = address }
end

-- pick returns a random address of addrs that the policy allows.
local function pick(host, addrs, allowed)
  local ok, first_bad = {}, nil
  for i = 1, #addrs do
    if ipaddr.forbidden(addrs[i], allowed) then
      first_bad = first_bad or addrs[i]
    else
      ok[#ok + 1] = addrs[i]
    end
  end
  if #ok == 0 then
    return forbidden_error(host, first_bad)
  end
  return ok[math.random(#ok)]
end

-- resolve returns an address for host that origins may use, or nil, an
-- error message, an error code ("dns_failed" or "address_forbidden") and
-- its parameters. allowed is the parsed origin allow list
-- (ipaddr.prefixes).
function _M.resolve(host, allowed)
  if is_ip(host) then
    if ipaddr.forbidden(host, allowed) then
      return forbidden_error(host, host)
    end
    return host
  end
  local c = lru()
  local hit = c:get(host)
  if hit then
    if hit.err then
      return nil, hit.err, "dns_failed", { host = host }
    end
    return pick(host, hit, allowed)
  end
  local addrs, err, ttl = _M.query(host, resolver.TYPE_A)
  if not addrs and ipv6 then
    addrs, err, ttl = _M.query(host, resolver.TYPE_AAAA)
  end
  if not addrs then
    err = "dns " .. host .. ": " .. tostring(err)
    c:set(host, { err = err }, NEGATIVE_TTL)
    return nil, err, "dns_failed", { host = host }
  end
  c:set(host, addrs, ttl)
  return pick(host, addrs, allowed)
end

function _M.invalidate(host)
  if cache then
    cache:delete(host)
  end
end

return _M
