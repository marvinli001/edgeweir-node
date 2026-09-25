-- edgeweir.dns: resolves origin host names for the balancer.
--
-- balancer_by_lua cannot resolve names (no cosockets), so the origin layer
-- resolves every candidate in the access phase with lua-resty-dns and
-- caches answers per worker for min(TTL, 30 s) (failures for 5 s), the same
-- validity nginx's own resolver used before. A failing origin's entry is
-- dropped so that the next attempt resolves it again (containers and cloud
-- instances change addresses on restart).
local resolver = require("resty.dns.resolver")
local lrucache = require("resty.lrucache")

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

local function is_ip(host)
  if host:find("^%d+%.%d+%.%d+%.%d+$") then
    return true
  end
  return host:find(":", 1, true) ~= nil
end

local function query(host, qtype)
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

-- resolve returns an address for host (IP literals pass through), or nil
-- and an error.
function _M.resolve(host)
  if is_ip(host) then
    return host
  end
  local c = lru()
  local hit = c:get(host)
  if hit then
    if hit.err then
      return nil, hit.err
    end
    return hit[math.random(#hit)]
  end
  local addrs, err, ttl = query(host, resolver.TYPE_A)
  if not addrs and ipv6 then
    addrs, err, ttl = query(host, resolver.TYPE_AAAA)
  end
  if not addrs then
    err = "dns " .. host .. ": " .. tostring(err)
    c:set(host, { err = err }, NEGATIVE_TTL)
    return nil, err
  end
  c:set(host, addrs, ttl)
  return addrs[math.random(#addrs)]
end

function _M.invalidate(host)
  if cache then
    cache:delete(host)
  end
end

return _M
