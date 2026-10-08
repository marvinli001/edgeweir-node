-- edgeweir.clientcert: visitors' client certificates (mutual TLS, feature
-- client-cert-v1) on the request side.
--
-- The handshake asks for a certificate on sites with a client certificate
-- setting (edgeweir.tls, ngx.ssl.verify_client) and never aborts: the
-- outcome is $ssl_client_verify (SUCCESS, FAILED:<reason> or NONE), kept
-- with resumed sessions. Here:
--
--   * the visitor's own X-Client-Verify, X-Client-Cert-SHA256,
--     X-Client-Cert-Subject and X-Client-Cert-Serial request headers are
--     removed on every site (edgeweir.router, with X-Edgeweir-*);
--   * a site in mode "required" answers requests without a verified
--     certificate (plain HTTP counts as none) with the 403 error page,
--     X-Edgeweir-Error: client-cert-required, before the site logic; plain
--     HTTP requests get the site's HTTPS redirect first, and HTTP-01
--     requests for the origin go on;
--   * sites with forward_headers send the four headers to the origin:
--     X-Client-Verify (SUCCESS, FAILED or NONE) always, the others for a
--     verified certificate only: the lowercase hex SHA-256 of its DER, its
--     subject ($ssl_client_s_dn, RFC 2253) and serial ($ssl_client_serial,
--     uppercase hex);
--   * the expression fields tls.client.verified, tls.client.cert_sha256
--     and tls.client.subject (edgeweir.policy, for sites whose rules read
--     them): true and the values for a verified certificate, false and ""
--     otherwise.
local resty_sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex

local _M = {}

local sub, find, gsub = string.sub, string.find, string.gsub

-- HEADERS are the request headers the node sends towards the origin;
-- visitors' own are always removed (STRIP holds them lowercase, as
-- ngx.req.get_headers names them).
_M.HEADERS = { "X-Client-Verify", "X-Client-Cert-SHA256", "X-Client-Cert-Subject", "X-Client-Cert-Serial" }
_M.STRIP = {}
for _, name in ipairs(_M.HEADERS) do _M.STRIP[name:lower()] = true end

-- verify_state reduces $ssl_client_verify to SUCCESS, FAILED (any
-- "FAILED:..." value) or NONE; plain HTTP has no certificate.
function _M.verify_state(scheme, verify)
  if scheme ~= "https" then return "NONE" end
  if verify == "SUCCESS" then return "SUCCESS" end
  if type(verify) == "string" and sub(verify, 1, 6) == "FAILED" then return "FAILED" end
  return "NONE"
end

-- cert_sha256 returns the lowercase hex SHA-256 of the DER of the first
-- certificate in a PEM ($ssl_client_raw_cert), "" when there is none.
function _M.cert_sha256(pem)
  if type(pem) ~= "string" then return "" end
  local _, b = find(pem, "-----BEGIN CERTIFICATE-----", 1, true)
  local e = b and find(pem, "-----END CERTIFICATE-----", b + 1, true)
  if not e then return "" end
  local der = ngx.decode_base64((gsub(sub(pem, b + 1, e - 1), "%s", "")))
  if not der or der == "" then return "" end
  local h = resty_sha256:new()
  h:update(der)
  return to_hex(h:final())
end

-- compute returns a request's client certificate values: verify (SUCCESS,
-- FAILED, NONE), verified, and for a verified certificate sha256, subject
-- and serial ("" otherwise).
function _M.compute(scheme, verify, raw_cert, subject, serial)
  local state = _M.verify_state(scheme, verify)
  if state ~= "SUCCESS" then
    return { verify = state, verified = false, sha256 = "", subject = "", serial = "" }
  end
  return { verify = state, verified = true, sha256 = _M.cert_sha256(raw_cert),
    subject = type(subject) == "string" and subject or "", serial = type(serial) == "string" and serial or "" }
end

-- values returns the request's values (cached in ngx.ctx).
function _M.values()
  local ctx = ngx.ctx
  local v = ctx.edgeweir_client
  if v then return v end
  local var = ngx.var
  local scheme = var.scheme
  if scheme == "https" then
    local verify = var.ssl_client_verify
    if verify == "SUCCESS" then
      v = _M.compute(scheme, verify, var.ssl_client_raw_cert, var.ssl_client_s_dn, var.ssl_client_serial)
    else
      v = _M.compute(scheme, verify)
    end
  else
    v = _M.compute(scheme)
  end
  ctx.edgeweir_client = v
  return v
end

-- decision tells what a request of site must get before the site logic:
-- nil (go on), "deny" (403 client-cert-required) or "http" (plain HTTP:
-- the site's HTTPS redirect when it has one, else deny). Only sites in
-- mode "required" ask; HTTP-01 requests (acme) for the origin go on, as
-- validation servers have no certificate.
function _M.decision(site, scheme, verify, acme)
  if not site or not site._client_required then return nil end
  if scheme == "https" then
    return _M.verify_state(scheme, verify) ~= "SUCCESS" and "deny" or nil
  end
  if acme then return nil end
  return "http"
end

-- header_value is a value as a request header: nil when empty or when it
-- holds a control character (nginx escapes them in the subject; never
-- trusted here).
local function header_value(s)
  if s == "" or find(s, "[%c]") then return nil end
  return s
end

-- forward sets the request headers towards the origin from values (v):
-- X-Client-Verify always, the others when set.
function _M.forward(v)
  local set = ngx.req.set_header
  set(_M.HEADERS[1], v.verify)
  set(_M.HEADERS[2], header_value(v.sha256))
  set(_M.HEADERS[3], header_value(v.subject))
  set(_M.HEADERS[4], header_value(v.serial))
end

return _M
