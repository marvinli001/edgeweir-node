-- edgeweir.sigv4: AWS Signature Version 4 for S3-compatible origins.
--
-- Cache misses may be proxied to object storage (AWS S3, MinIO, Aliyun OSS
-- S3 API, ...). Only GET and HEAD are forwarded, the client query string is
-- dropped and the payload is not signed, so sign_s3() always signs exactly
-- host;x-amz-content-sha256;x-amz-date with an empty canonical query string.
--
-- The canonical URI follows the S3 rule: the path is percent-decoded once
-- and every byte except unreserved characters (A-Z a-z 0-9 - _ . ~) and "/"
-- is re-encoded as %XX (uppercase hex). There is no double encoding and no
-- path normalization ("//", "." and ".." are kept). sign_s3() returns that
-- encoded path as h.uri; it must be sent upstream verbatim, otherwise the
-- signature does not match.
--
-- Derived signing keys are cached per (secret, date, region, service) in a
-- small per-worker table, so a hot request costs one SHA-256 of the
-- canonical request and one HMAC-SHA256.
local resty_sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex
local hmac = require("resty.openssl.hmac")

local _M = {}

local byte, char, find, format, gsub, lower, sub =
  string.byte, string.char, string.find, string.format, string.gsub, string.lower, string.sub
local concat, sort = table.concat, table.sort
local floor, tonumber, tostring, type, pairs = math.floor, tonumber, tostring, type, pairs

local ALGORITHM = "AWS4-HMAC-SHA256"
local UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
local S3_SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date"

-- Largest unix time whose x-amz-date still has a four-digit year.
local MAX_TIME = 253402300799

-- Upper bound of cached signing keys per worker. Keys roll over daily, so
-- the whole table is dropped when it fills up instead of tracking recency.
local KEY_CACHE_MAX = 256
local key_cache, key_cache_n = {}, 0

local function sha256_hex(s)
  local h = resty_sha256:new()
  h:update(s)
  return to_hex(h:final())
end

local function hmac_sha256(key, msg)
  local h, err = hmac.new(key, "sha256")
  if not h then
    return nil, err
  end
  local digest, ferr = h:final(msg)
  if not digest then
    return nil, ferr
  end
  return digest
end

-- signing_key derives (or returns the cached) SigV4 signing key.
local function signing_key(secret, date, region, service)
  -- date has a fixed length and region/service contain no control
  -- characters, so the NUL-separated cache key is unambiguous.
  local ck = secret .. "\0" .. date .. "\0" .. region .. "\0" .. service
  local k = key_cache[ck]
  if k then
    return k
  end
  local err
  k, err = hmac_sha256("AWS4" .. secret, date)
  if k then
    k, err = hmac_sha256(k, region)
  end
  if k then
    k, err = hmac_sha256(k, service)
  end
  if k then
    k, err = hmac_sha256(k, "aws4_request")
  end
  if not k then
    return nil, "hmac-sha256 failed: " .. tostring(err)
  end
  if key_cache_n >= KEY_CACHE_MAX then
    key_cache, key_cache_n = {}, 0
  end
  key_cache[ck] = k
  key_cache_n = key_cache_n + 1
  return k
end

-- finish turns a canonical request into the signature and the
-- Authorization header value.
local function finish(creq, signed_headers, amz_date, region, service, access_key, secret_key)
  local date = sub(amz_date, 1, 8)
  local scope = date .. "/" .. region .. "/" .. service .. "/aws4_request"
  local sts = ALGORITHM .. "\n" .. amz_date .. "\n" .. scope .. "\n" .. sha256_hex(creq)
  local key, err = signing_key(secret_key, date, region, service)
  if not key then
    return nil, err
  end
  local mac
  mac, err = hmac_sha256(key, sts)
  if not mac then
    return nil, "hmac-sha256 failed: " .. tostring(err)
  end
  local sig = to_hex(mac)
  return {
    authorization = ALGORITHM .. " Credential=" .. access_key .. "/" .. scope
      .. ", SignedHeaders=" .. signed_headers .. ", Signature=" .. sig,
    signature = sig,
    canonical_request = creq,
    string_to_sign = sts,
  }
end

local function unhex(h)
  return char(tonumber(h, 16))
end

local function pct(c)
  return format("%%%02X", byte(c))
end

-- canonical_uri returns the S3 canonical URI of a request path: decode
-- %XX once, then encode every byte except A-Z a-z 0-9 - _ . ~ and "/".
-- Malformed escapes ("%zz", a trailing "%") are kept literally and their
-- "%" is encoded. An empty path becomes "/".
function _M.canonical_uri(path)
  if path == nil or path == "" then
    return "/"
  end
  local p = gsub(path, "%%(%x%x)", unhex)
  p = gsub(p, "[^A-Za-z0-9%-%._~/]", pct)
  return p
end

-- trimall trims a header value and collapses inner whitespace runs, as
-- SigV4 canonical headers require.
local function trimall(v)
  v = gsub(v, "^%s+", "")
  v = gsub(v, "%s+$", "")
  v = gsub(v, "%s+", " ")
  return v
end

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

-- is_scope_part accepts values that cannot corrupt the credential scope
-- ("<ak>/<date>/<region>/<service>/aws4_request") or the header line.
local function is_scope_part(v)
  return is_nonempty_string(v) and not find(v, "[%c%s/,]")
end

local function valid_payload_hash(v)
  return v == UNSIGNED_PAYLOAD or (type(v) == "string" and #v == 64 and not find(v, "[^0-9a-f]"))
end

local function check_credentials(r)
  if not is_scope_part(r.region) then
    return "region must be a non-empty string without whitespace or '/'"
  end
  if not is_scope_part(r.service) then
    return "service must be a non-empty string without whitespace or '/'"
  end
  if not is_scope_part(r.access_key) then
    return "access_key must be a non-empty string without whitespace or '/'"
  end
  if not is_nonempty_string(r.secret_key) then
    return "secret_key must be a non-empty string"
  end
  return nil
end

-- sign is the general signer behind sign_s3, exposed for tests against
-- the official AWS vectors (which sign other header sets). Every entry of
-- r.headers (name -> value) is signed; names are lowercased and values
-- trimmed. r.uri is used verbatim as the canonical URI and r.query
-- (default "") as the canonical query string. r.amz_date is the
-- "YYYYMMDDTHHMMSSZ" timestamp and r.payload_hash the hashed payload.
-- Returns { authorization, signature, canonical_request, string_to_sign }
-- or nil, err.
function _M.sign(r)
  if type(r) ~= "table" then
    return nil, "request must be a table"
  end
  if not is_nonempty_string(r.method) or find(r.method, "[%c%s]") then
    return nil, "method must be a non-empty string without whitespace"
  end
  if not is_nonempty_string(r.uri) or find(r.uri, "[%c%s]") then
    return nil, "uri must be a non-empty string without whitespace"
  end
  local query = r.query or ""
  if type(query) ~= "string" or find(query, "[%c%s]") then
    return nil, "query must be a string without whitespace"
  end
  if type(r.amz_date) ~= "string" or not find(r.amz_date, "^%d%d%d%d%d%d%d%dT%d%d%d%d%d%dZ$") then
    return nil, "amz_date must look like 20150830T123600Z"
  end
  if not valid_payload_hash(r.payload_hash) then
    return nil, "payload_hash must be UNSIGNED-PAYLOAD or a lowercase hex SHA-256"
  end
  local cerr = check_credentials(r)
  if cerr then
    return nil, cerr
  end
  if type(r.headers) ~= "table" then
    return nil, "headers must be a table"
  end

  local names, values = {}, {}
  for name, value in pairs(r.headers) do
    if not is_nonempty_string(name) or find(name, "[%c%s:]") then
      return nil, "invalid header name"
    end
    if type(value) ~= "string" or find(value, "[\r\n]") then
      return nil, "header " .. name .. ": value must be a single-line string"
    end
    local n = lower(name)
    if values[n] then
      return nil, "duplicate header " .. n
    end
    names[#names + 1] = n
    values[n] = trimall(value)
  end
  if #names == 0 then
    return nil, "headers must not be empty"
  end
  sort(names)

  local lines = {}
  for i = 1, #names do
    lines[i] = names[i] .. ":" .. values[names[i]] .. "\n"
  end
  local signed_headers = concat(names, ";")
  local creq = r.method .. "\n" .. r.uri .. "\n" .. query .. "\n" .. concat(lines)
    .. "\n" .. signed_headers .. "\n" .. r.payload_hash
  return finish(creq, signed_headers, r.amz_date, r.region, r.service, r.access_key, r.secret_key)
end

-- x-amz-date of the last signed second (ngx.time() ticks once a second).
local last_time, last_amz_date

local function amz_date_of(t)
  if t ~= last_time then
    last_amz_date = os.date("!%Y%m%dT%H%M%SZ", t)
    last_time = t
  end
  return last_amz_date
end

-- sign_s3 signs an S3 GET/HEAD request (see the file comment). Returns
-- { authorization, amz_date, content_sha256, uri } or nil, err. The caller
-- sends Authorization, X-Amz-Date = amz_date, X-Amz-Content-SHA256 =
-- content_sha256, Host = opts.host and uses uri as the request path with
-- no query string.
function _M.sign_s3(opts)
  if type(opts) ~= "table" then
    return nil, "options must be a table"
  end
  local method = opts.method
  if method ~= "GET" and method ~= "HEAD" then
    return nil, "method must be GET or HEAD"
  end
  local host = opts.host
  if type(host) == "string" then
    host = trimall(host)
  end
  if not is_nonempty_string(host) or find(host, "[%c%s]") then
    return nil, "host must be a non-empty string without whitespace"
  end
  local path = opts.path
  if path ~= nil and type(path) ~= "string" then
    return nil, "path must be a string"
  end
  if path ~= nil and path ~= "" and byte(path, 1) ~= 47 then -- "/"
    return nil, "path must start with /"
  end
  local r = {
    region = opts.region,
    service = opts.service or "s3",
    access_key = opts.access_key,
    secret_key = opts.secret_key,
  }
  local cerr = check_credentials(r)
  if cerr then
    return nil, cerr
  end
  local t = opts.time
  if t == nil then
    t = ngx.time()
  elseif type(t) ~= "number" or t ~= t or t < 0 or t > MAX_TIME then
    return nil, "time must be a unix timestamp in seconds"
  end
  t = floor(t)
  local payload_hash = opts.payload_hash or UNSIGNED_PAYLOAD
  if not valid_payload_hash(payload_hash) then
    return nil, "payload_hash must be UNSIGNED-PAYLOAD or a lowercase hex SHA-256"
  end

  local amz_date = amz_date_of(t)
  local uri = _M.canonical_uri(path)
  -- The three signed headers are already in sorted order.
  local creq = method .. "\n" .. uri .. "\n\n"
    .. "host:" .. host .. "\n"
    .. "x-amz-content-sha256:" .. payload_hash .. "\n"
    .. "x-amz-date:" .. amz_date .. "\n\n"
    .. S3_SIGNED_HEADERS .. "\n" .. payload_hash
  local res, err = finish(creq, S3_SIGNED_HEADERS, amz_date, r.region, r.service, r.access_key, r.secret_key)
  if not res then
    return nil, err
  end
  return {
    authorization = res.authorization,
    amz_date = amz_date,
    content_sha256 = payload_hash,
    uri = uri,
  }
end

-- Test hooks for the signing-key cache.
function _M._cache_size()
  return key_cache_n
end

function _M._cache_clear()
  key_cache, key_cache_n = {}, 0
end

return _M
