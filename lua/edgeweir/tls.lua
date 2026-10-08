-- edgeweir.tls: certificates of the TLS listeners. A site's certificate
-- for its domains; the node's health certificate for SNI
-- health.edgeweir.invalid and handshakes without SNI
-- (edgeweir.probehealth); any other name, a domain its site's certificate
-- does not cover yet (tls_pending) and a site's domain on a listener port
-- the site is not bound to (edge-ports-v1) abort the handshake. A host
-- found through a suffix or pattern domain (domains-v2) completes only
-- where the site's certificate names it (its dns_names: the host, or "*."
-- and its parent). With the cluster's unknown host handling
-- (unknown-host-v1) handing unknown hosts to the default site and
-- default_certificate on, names no site serves get the default site's
-- certificate instead of an aborted handshake.
local ssl = require("ngx.ssl")
local hello = require("ngx.ssl.clienthello")
local store = require("edgeweir.store")
local policy = require("edgeweir.policy")
local ja4 = require("edgeweir.ja4")
local probehealth = require("edgeweir.probehealth")
local cache = require("resty.lrucache").new(1000)
local _M = {}

-- on_port tells whether site is served on the listener of the handshake
-- (edge-ports-v1); the local TLS socket (prefetches) has no port.
local function on_port(site)
  local port = ssl.server_port()
  return not port or store.serves_port(site, port)
end

-- choose returns the site whose certificate a handshake for host gets
-- (nil: abort): the site serving the host, else (for names no site serves
-- here) the default site when the cluster hands unknown hosts to it with
-- its certificate.
local function choose(host)
  local site, ver, how = store.lookup_host(host)
  if site then
    if not site.certificate or policy.tls_pending(site, host) then return nil end
    if how == "match" and not policy.names_cover(site.certificate.dns_names, host) then return nil end
    if on_port(site) then return site end
  end
  local u = store.config(not site and ver or nil).unknown
  if not (u and u.default_certificate and u.unknown_host == "site" and u.default_site_id) then return nil end
  local default = store.site_current(u.default_site_id)
  if default and default.certificate and on_port(default) then return default end
  return nil
end

function _M.client_hello()
  local name = hello.get_client_hello_server_name()
  if probehealth.is_health_sni(name) then
    if not probehealth.material(store.config()) then return ngx.exit(ngx.ERROR) end
    return
  end
  local site = choose(string.lower(name))
  if not site then return ngx.exit(ngx.ERROR) end
  -- JA4 only for sites that read it; never fails the handshake.
  if site._ja4 then
    local ok, err = pcall(ja4.client_hello)
    if not ok then ngx.log(ngx.WARN, "edgeweir: JA4 unavailable: ", err) end
  end
  if site.tls and site.tls.minimum_version == "1.3" then
    local ok = hello.set_protocols({ "TLSv1.3" })
    if not ok then return ngx.exit(ngx.ERROR) end
  end
end

function _M.certificate()
  local name = ssl.server_name()
  local site, material
  if probehealth.is_health_sni(name) then
    material = probehealth.material(store.config())
  else
    site = choose(string.lower(name))
    material = site and site.certificate
  end
  if not material then return ngx.exit(ngx.ERROR) end
  local parsed = cache:get(material.fingerprint)
  if not parsed then
    local cert = ssl.parse_pem_cert(material.chain_pem)
    local key = ssl.parse_pem_priv_key(material.private_key_pem)
    if not cert or not key then return ngx.exit(ngx.ERROR) end
    parsed = { cert, key }
    cache:set(material.fingerprint, parsed)
  end
  if not ssl.clear_certs() or not ssl.set_cert(parsed[1]) or not ssl.set_priv_key(parsed[2]) then
    return ngx.exit(ngx.ERROR)
  end
  if site and site.tls and site.tls.ocsp_stapling and material.ocsp and material.ocsp ~= "" and (material.ocsp_until or 0) > ngx.time() then
    require("ngx.ocsp").set_ocsp_status_resp(ngx.decode_base64(material.ocsp))
  end
end

return _M
