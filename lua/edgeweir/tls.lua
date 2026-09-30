local ssl = require("ngx.ssl")
local hello = require("ngx.ssl.clienthello")
local store = require("edgeweir.store")
local ja4 = require("edgeweir.ja4")
local cache = require("resty.lrucache").new(1000)
local _M = {}

function _M.client_hello()
  local name = hello.get_client_hello_server_name()
  local site = name and store.lookup_host(string.lower(name))
  if not site or not site.certificate then return ngx.exit(ngx.ERROR) end
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
  local site = name and store.lookup_host(string.lower(name))
  local material = site and site.certificate
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
  if site.tls and site.tls.ocsp_stapling and material.ocsp and material.ocsp ~= "" and (material.ocsp_until or 0) > ngx.time() then
    require("ngx.ocsp").set_ocsp_status_resp(ngx.decode_base64(material.ocsp))
  end
end

return _M
