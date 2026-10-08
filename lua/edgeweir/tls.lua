-- edgeweir.tls: certificates of the TLS listeners. A site's certificate
-- for its domains; the node's health certificate for SNI
-- health.edgeweir.invalid and handshakes without SNI
-- (edgeweir.probehealth); any other name, a domain its site's certificate
-- does not cover yet (tls_pending) and a site's domain on a listener port
-- the site is not bound to (edge-ports-v1: a name no site serves there)
-- abort the handshake. A host
-- found through a suffix or pattern domain (domains-v2) completes only
-- where the site's certificates name it (their dns_names: the host, or
-- "*." and its parent). With the cluster's unknown host handling
-- (unknown-host-v1) handing unknown hosts to the default site and
-- default_certificate on, names no site serves get the default site's
-- certificate instead of an aborted handshake.
--
-- Sites with several certificates (multi-certificate-v1) get one per
-- handshake (select): among those naming the SNI, the key types the
-- client can use (an ECDSA certificate needs its curve's signature scheme
-- and TLS 1.3 or an ECDHE-ECDSA suite of the site's cipher profile;
-- computed in the ClientHello only for sites with both ECDSA and RSA
-- certificates), exact names over wildcards, ECDSA over RSA when the
-- client can use it, then the site's order; the first certificate when
-- none names the SNI. Its OCSP response is stapled.
--
-- Session resumption: the ClientHello sets the site's session id context
-- (tls_session_context, from the agent; SSL_set_session_id_context): a
-- session resumes only for the site, minimum version, client certificate
-- setting and certificates it was made with; any other is a full
-- handshake. Health certificate handshakes use SHA-256("edgeweir-tls-v1\0
-- health"). Sites with client certificates (client-cert-v1) ask for one in
-- the certificate phase (ngx.ssl.verify_client, never aborting; see
-- edgeweir.clientcert).
local ffi = require("ffi")
local ssl = require("ngx.ssl")
local hello = require("ngx.ssl.clienthello")
local resty_sha256 = require("resty.sha256")
local store = require("edgeweir.store")
local policy = require("edgeweir.policy")
local ja4 = require("edgeweir.ja4")
local probehealth = require("edgeweir.probehealth")
local lrucache = require("resty.lrucache")
local cache = lrucache.new(1000)
local ca_cache = lrucache.new(100)
local _M = {}

local find, sub = string.find, string.sub

-- The session id context of a connection (OpenSSL, exported by the node's
-- nginx). Declared once; a second declaration elsewhere is harmless.
pcall(ffi.cdef, [[
int SSL_set_session_id_context(void *ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
]])

-- set_session_context sets the handshake's session id context (raw
-- bytes, at most 32). Tests replace it.
function _M.set_session_context(raw)
  local ptr, err = ssl.get_req_ssl_pointer()
  if not ptr then return nil, err end
  if ffi.C.SSL_set_session_id_context(ptr, raw, #raw) ~= 1 then
    return nil, "SSL_set_session_id_context failed"
  end
  return true
end

-- HEALTH_CONTEXT is the session id context of health certificate
-- handshakes.
do
  local h = resty_sha256:new()
  h:update("edgeweir-tls-v1\0health")
  _M.HEALTH_CONTEXT = h:final()
end

-- SCHEMES are the TLS signature schemes of ECDSA certificates by curve;
-- ECDSA_SUITES the ECDHE-ECDSA suites of the cipher profiles (TLS 1.2).
_M.SCHEMES = { ["P-256"] = 0x0403, ["P-384"] = 0x0503, ["P-521"] = 0x0603 }
_M.ECDSA_SUITES = {
  modern = { [0xC02B] = true, [0xCCA9] = true },
  compatible = { [0xC02B] = true, [0xCCA9] = true, [0xC02C] = true },
}

-- client_caps returns the curves of ECDSA certificates the client can use
-- (a set, empty for none) from its ClientHello: the raw
-- signature_algorithms (13) and supported_versions (43) extensions and
-- the cipher suites. A curve is usable when signature_algorithms lists its
-- scheme and the client offers TLS 1.3 (every site allows it) or an
-- ECDHE-ECDSA suite of profile. Without signature_algorithms none is.
function _M.client_caps(sigalgs_raw, versions_raw, ciphers, profile)
  local caps = {}
  local sigalgs = ja4.parse_u16_list(sigalgs_raw)
  if not sigalgs then return caps end
  local ok = false
  for _, v in ipairs(ja4.parse_versions(versions_raw) or {}) do
    if v == 0x0304 then ok = true; break end
  end
  if not ok then
    local suites = _M.ECDSA_SUITES[profile] or _M.ECDSA_SUITES.modern
    for _, c in ipairs(ciphers or {}) do
      if suites[c] then ok = true; break end
    end
  end
  if not ok then return caps end
  for curve, scheme in pairs(_M.SCHEMES) do
    for i = 1, #sigalgs do
      if sigalgs[i] == scheme then caps[curve] = true; break end
    end
  end
  return caps
end

-- coverage tells how a certificate's names cover host: "exact", "wild"
-- (a "*." over its parent) or nil.
local function coverage(names, host)
  if type(names) ~= "table" or type(host) ~= "string" then return nil end
  local dot = find(host, ".", 1, true)
  local wild = dot and dot > 1 and "*." .. sub(host, dot + 1)
  local level
  for i = 1, #names do
    if names[i] == host then return "exact" end
    if names[i] == wild then level = "wild" end
  end
  return level
end

-- usable tells whether the client can use cert: anything but ECDSA
-- always, ECDSA when caps (nil: not computed, a site without both key
-- types) holds its curve.
local function usable(cert, caps)
  return cert.key_type ~= "ec" or caps == nil or caps[cert.curve] == true
end

-- select picks the certificate of a handshake for host (lowercase SNI)
-- among certs (the site's, in its order) for a client with caps (see
-- client_caps; nil: not computed): those naming host, of a key type the
-- client can use (all of them when it can use none), exact names over
-- wildcards, ECDSA when the client can use it, else RSA, then the site's
-- order. The first certificate when none names host.
function _M.select(certs, host, caps)
  if #certs <= 1 then return certs[1] end
  local candidates = {}
  for i = 1, #certs do
    local level = coverage(certs[i].dns_names, host)
    if level then candidates[#candidates + 1] = { cert = certs[i], exact = level == "exact" } end
  end
  if #candidates == 0 then return certs[1] end
  local keep = {}
  for _, c in ipairs(candidates) do
    if usable(c.cert, caps) then keep[#keep + 1] = c end
  end
  if #keep > 0 then candidates = keep end
  keep = {}
  for _, c in ipairs(candidates) do
    if c.exact then keep[#keep + 1] = c end
  end
  if #keep > 0 then candidates = keep end
  local prefer = (caps ~= nil and next(caps) ~= nil) and "ec" or "rsa"
  if caps ~= nil then
    for _, c in ipairs(candidates) do
      if c.cert.key_type == prefer then return c.cert end
    end
  end
  return candidates[1].cert
end

-- on_port tells whether site is served on the listener of the handshake
-- (edge-ports-v1); the local TLS socket (prefetches) has no port.
local function on_port(site)
  local port = ssl.server_port()
  return not port or store.serves_port(site, port)
end

-- choose returns the site whose certificate a handshake for host gets
-- (nil: abort): the site serving the host, else (for names no site serves
-- here, a site bound to other ports included, as edgeweir.router sees
-- them) the default site when the cluster hands unknown hosts to it with
-- its certificate.
local function choose(host)
  local site, ver, how = store.lookup_host(host)
  if site and on_port(site) then
    if not site.certificate or policy.tls_pending(site, host) then return nil end
    if how == "match" and not policy.names_cover(site._cert_names, host) then return nil end
    return site
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
    local ok, err = _M.set_session_context(_M.HEALTH_CONTEXT)
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: cannot set the TLS session context: ", err)
      return ngx.exit(ngx.ERROR)
    end
    return
  end
  local site = choose(string.lower(name))
  if not site then return ngx.exit(ngx.ERROR) end
  -- Sessions resume for this site only (fail closed: without its context
  -- a session could resume for another site).
  local ok, err = false, "no session context"
  if site._sid_ctx then ok, err = _M.set_session_context(site._sid_ctx) end
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: cannot set the TLS session context of site ", site.id, ": ", err)
    return ngx.exit(ngx.ERROR)
  end
  -- JA4 only for sites that read it; never fails the handshake.
  if site._ja4 then
    local jok, jerr = pcall(ja4.client_hello)
    if not jok then ngx.log(ngx.WARN, "edgeweir: JA4 unavailable: ", jerr) end
  end
  -- Which ECDSA certificates the client can use, only for sites with
  -- ECDSA and RSA ones; on error none (RSA always works).
  if site._mixed_keys then
    local cok, caps = pcall(function()
      return _M.client_caps(hello.get_client_hello_ext(13), hello.get_client_hello_ext(43),
        hello.get_client_hello_ciphers(), site.tls and site.tls.cipher_profile)
    end)
    ngx.ctx.edgeweir_tls_caps = cok and caps or {}
  end
  if site.tls and site.tls.minimum_version == "1.3" then
    local pok = hello.set_protocols({ "TLSv1.3" })
    if not pok then return ngx.exit(ngx.ERROR) end
  end
end

-- parsed returns the parsed chain and key of material (cached by
-- fingerprint).
local function parsed(material)
  local p = cache:get(material.fingerprint)
  if not p then
    local cert = ssl.parse_pem_cert(material.chain_pem)
    local key = ssl.parse_pem_priv_key(material.private_key_pem)
    if not cert or not key then return nil end
    p = { cert, key }
    cache:set(material.fingerprint, p)
  end
  return p
end

-- verify_client asks for the client certificate of site's setting
-- (client-cert-v1): its CA chain (parsed once per CA bundle) and depth.
local function verify_client(cc)
  local chain = ca_cache:get(cc.key)
  if not chain then
    chain = ssl.parse_pem_cert(cc.ca_pem)
    if not chain then return nil, "invalid CA bundle" end
    ca_cache:set(cc.key, chain)
  end
  return ssl.verify_client(chain, cc.depth)
end

function _M.certificate()
  local name = ssl.server_name()
  local site, material
  if probehealth.is_health_sni(name) then
    material = probehealth.material(store.config())
  else
    local host = string.lower(name)
    site = choose(host)
    if site then
      local caps = site._mixed_keys and (ngx.ctx.edgeweir_tls_caps or {}) or nil
      material = _M.select(site._certs, host, caps)
    end
  end
  if not material then return ngx.exit(ngx.ERROR) end
  local p = parsed(material)
  if not p then return ngx.exit(ngx.ERROR) end
  if not ssl.clear_certs() or not ssl.set_cert(p[1]) or not ssl.set_priv_key(p[2]) then
    return ngx.exit(ngx.ERROR)
  end
  if site and site._client then
    local ok, err = verify_client(site._client)
    if not ok then
      ngx.log(ngx.ERR, "edgeweir: cannot ask for client certificates of site ", site.id, ": ", err)
      return ngx.exit(ngx.ERROR)
    end
  end
  if site and site.tls and site.tls.ocsp_stapling and material.ocsp and material.ocsp ~= "" and (material.ocsp_until or 0) > ngx.time() then
    require("ngx.ocsp").set_ocsp_status_resp(ngx.decode_base64(material.ocsp))
  end
end

return _M
