-- edgeweir.unknownhost: requests no site serves (unknown-host-v1).
--
-- The cluster's handling (NodeConfig.unknown_hosts, edgeweir.store.config
-- `unknown`) applies to a Host no site or offline host serves, and to a
-- site's host on a port the site is not bound to (unknown_host), and to a
-- Host that is an IP literal or empty (ip_access): "page" answers with the
-- platform's unknown host page (404), "close" closes the connection
-- without a response (444), "site" serves the request as the default site
-- when it is in the table and bound to the port (else the page).
--
-- Scan protection counts every such request by client network (the IPv4
-- address or the IPv6 /64, as edgeweir.cc counts) in lua_shared_dict
-- "edgeweir_cc" ("u|<network>", a 60-second window from the first
-- request): a request after scan_threshold within it bans the network at
-- platform scope for scan_ban_seconds (edgeweir.bans.add_auto with "*",
-- reason unknown_host_scan) unless the address is banned at platform scope
-- already; "ub|<network>" keeps concurrent workers from banning it twice.
-- Once the ban is lifted (the node's own entry by edgeweir.bans.release,
-- or a shared one the console removed), the next request over the
-- threshold bans again; the count keeps its window.
-- Loopback, trusted proxies and addresses the platform rules allow are
-- never counted.
local bans = require("edgeweir.bans")
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

_M.WINDOW = 60
-- How long "ub|<network>" holds back another ban of the same network.
_M.BAN_GUARD = 1

local find, match = string.find, string.match

-- ip_access tells whether a Host ($host) names no host: empty, "_" (no
-- Host: nginx's server_name of the default server), an IPv4 address or an
-- IPv6 address in brackets.
function _M.ip_access(host)
  if host == nil or host == "" or host == "_" then
    return true
  end
  if find(host, "^%[") then
    return true
  end
  return match(host, "^%d+%.%d+%.%d+%.%d+$") ~= nil
end

local function allowed(cfg, addr)
  if cfg.trusted and cfg.trusted(addr) then
    return true
  end
  local allows = cfg.allows
  if allows then
    for i = 1, #allows do
      if allows[i](addr) then
        return true
      end
    end
  end
  return false
end

-- count records one request for scan protection and bans the client's
-- network after the threshold. Returns the count (nil when not counted).
function _M.count(cfg, addr)
  local u = cfg.unknown
  if not u or u.scan_threshold <= 0 or not addr or allowed(cfg, addr) then
    return nil
  end
  local network = ipaddr.client_network(addr)
  if not network then
    return nil
  end
  local dict = ngx.shared.edgeweir_cc
  local n = dict:incr("u|" .. network, 1, 0, _M.WINDOW)
  if
    n
    and n > u.scan_threshold
    and not bans.match(nil, addr)
    and dict:safe_add("ub|" .. network, true, _M.BAN_GUARD)
  then
    local ok, err = bans.add_auto("*", addr, u.scan_ban_seconds, {
      reason = "unknown_host_scan",
      metric = "unknown_host_requests",
      observed = n,
      threshold = u.scan_threshold,
      window_seconds = _M.WINDOW,
    })
    if not ok then
      ngx.log(ngx.WARN, "edgeweir: scan protection could not ban ", network, ": ", err)
    end
  end
  return n
end

-- action returns the handling of a request with this Host: "page",
-- "close" or "site".
function _M.action(cfg, host)
  local u = cfg.unknown
  if not u then
    return "page"
  end
  return _M.ip_access(host) and u.ip_access or u.unknown_host
end

return _M
