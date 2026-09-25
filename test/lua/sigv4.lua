-- Lua unit tests for edgeweir.sigv4. Run inside the OpenResty image with
-- the resty CLI:
--
--   docker run --rm -v "$PWD/lua:/lua:ro" -v "$PWD/test/lua:/t:ro" \
--     openresty/openresty:1.31.1.1-bookworm-fat resty -I /lua /t/sigv4.lua
local sigv4 = require("edgeweir.sigv4")
local resty_sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex

local passed, failed = 0, 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    print("ok   " .. name)
  else
    failed = failed + 1
    print("FAIL " .. name .. ": " .. tostring(err))
  end
end

local function eq(got, want, msg)
  if got ~= want then
    error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2)
  end
end

local function sha256_hex(s)
  local h = resty_sha256:new()
  h:update(s)
  return to_hex(h:final())
end

local function signature_of(authorization)
  return authorization:match("Signature=(%x+)$")
end

-- SHA-256 of the empty string.
local EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

-- Example credentials of the S3 API reference ("Examples: Signature
-- Calculations"); also used for the Node.js cross-check vectors below.
local S3_AK = "AKIAIOSFODNN7EXAMPLE"
local S3_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

-- Known answer 1: Amazon S3 API Reference, "Signature Calculations for the
-- Authorization Header: Transferring Payload in a Single Chunk (AWS
-- Signature Version 4)", section "Example: GET Object":
--   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
-- The page has since been removed from docs.aws.amazon.com (it redirects to
-- the API reference index); the values were copied from the archived copy:
--   https://web.archive.org/web/20251208134526/https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
-- The request headers are passed as printed in the example (mixed-case
-- names, "Range: bytes=0-9 " and "x-amz-date: 20130524T000000Z " with
-- surrounding spaces) to exercise lowercasing and trimming.
test("sign: S3 docs GET Object example (host;range;x-amz-content-sha256;x-amz-date)", function()
  local res = assert(sigv4.sign({
    method = "GET",
    uri = "/test.txt",
    headers = {
      Host = "examplebucket.s3.amazonaws.com",
      Range = "bytes=0-9 ",
      ["x-amz-content-sha256"] = EMPTY_SHA256,
      ["x-amz-date"] = " 20130524T000000Z ",
    },
    payload_hash = EMPTY_SHA256,
    amz_date = "20130524T000000Z",
    region = "us-east-1",
    service = "s3",
    access_key = S3_AK,
    secret_key = S3_SK,
  }))
  eq(res.canonical_request, table.concat({
    "GET",
    "/test.txt",
    "",
    "host:examplebucket.s3.amazonaws.com",
    "range:bytes=0-9",
    "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "x-amz-date:20130524T000000Z",
    "",
    "host;range;x-amz-content-sha256;x-amz-date",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  }, "\n"), "canonical request")
  eq(res.string_to_sign, table.concat({
    "AWS4-HMAC-SHA256",
    "20130524T000000Z",
    "20130524/us-east-1/s3/aws4_request",
    "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
  }, "\n"), "string to sign")
  eq(res.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "signature")
  -- The example prints the header without a space after each comma; the
  -- signer uses the ", " form of the other AWS examples (both parse).
  eq(res.authorization, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
    .. "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
    .. "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "authorization")
end)

-- Known answer 2: AWS SigV4 test suite, case "get-vanilla", as shipped in
-- awslabs/aws-c-auth (commit ace1311f8ef6ea890b26dd376031bed2721648eb):
--   https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4/get-vanilla
--   context.json                  credentials, region us-east-1, service "service",
--                                 timestamp 2015-08-30T12:36:00Z, sign_body false
--   header-canonical-request.txt  canonical request
--   header-string-to-sign.txt     string to sign
--   header-signature.txt          5fa00fa3...
--   header-signed-request.txt     Authorization header
test("sign: AWS SigV4 test suite get-vanilla", function()
  local res = assert(sigv4.sign({
    method = "GET",
    uri = "/",
    headers = { Host = "example.amazonaws.com", ["X-Amz-Date"] = "20150830T123600Z" },
    payload_hash = EMPTY_SHA256,
    amz_date = "20150830T123600Z",
    region = "us-east-1",
    service = "service",
    access_key = "AKIDEXAMPLE",
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  }))
  eq(res.canonical_request, "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n"
    .. "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "canonical request")
  eq(res.string_to_sign, "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n"
    .. "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63", "string to sign")
  eq(res.signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", "signature")
  eq(res.authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
    .. "SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    "authorization")
end)

-- Cross-check of sign_s3 against an independent implementation: a small
-- Node.js script (node:crypto only, kept outside the repository) that
-- builds the S3 canonical request with UNSIGNED-PAYLOAD from the spec
-- (canonical URI via decodeURIComponent + encodeURIComponent per segment,
-- plus escaping of !'()*; x-amz-date via Date#toISOString). The script
-- first checks itself against the two known answers above, then printed
-- these uri / amz_date / signature values (Node.js v25.6.1). All cases use
-- the S3 example credentials S3_AK / S3_SK.
local XCHECK = {
  {
    name = "raw space and pre-encoded UTF-8, host with port",
    opts = { method = "GET", host = "bucket.s3.example.com:9000", path = "/media/a b/%E4%B8%AD.png",
      region = "us-east-1", time = 1440938160 },
    uri = "/media/a%20b/%E4%B8%AD.png",
    amz_date = "20150830T123600Z",
    signature = "f7a55bb290fc7ebcac5acd1c4414f3430df9066f09d0f29b8e336907bf9be75b",
  },
  {
    name = "raw UTF-8 and spaces",
    opts = { method = "GET", host = "examplebucket.s3.amazonaws.com", path = "/photos/中文 文件.jpg",
      region = "us-east-1", time = 1369353600 },
    uri = "/photos/%E4%B8%AD%E6%96%87%20%E6%96%87%E4%BB%B6.jpg",
    amz_date = "20130524T000000Z",
    signature = "3911aa271011b4fe172076120ddce698edcf9ae216193c05e32ccb1c93232264",
  },
  {
    name = "HEAD, pre-encoded %2F, ~ and %7E",
    opts = { method = "HEAD", host = "minio.internal:9000", path = "/assets/a%2Fb/~user/%7Efile.txt",
      region = "us-east-1", time = 1800000000 },
    uri = "/assets/a/b/~user/~file.txt",
    amz_date = "20270115T080000Z",
    signature = "591a7d1e62708082e166d374690a636bb66e49ae6077e7537459383287106c89",
  },
  {
    name = "reserved characters, other region",
    opts = { method = "GET", host = "media.oss-cn-hangzhou.aliyuncs.com", path = "/k+e y!'()*@$&=;:,.txt",
      region = "cn-hangzhou", time = 1767225599 },
    uri = "/k%2Be%20y%21%27%28%29%2A%40%24%26%3D%3B%3A%2C.txt",
    amz_date = "20251231T235959Z",
    signature = "96a388df87e0bd281176748b26bf991838b7123e6d6c849dce0a179e21bd05d8",
  },
  {
    name = "root path",
    opts = { method = "GET", host = "bucket.s3.eu-west-1.amazonaws.com", path = "/",
      region = "eu-west-1", time = 1700000000 },
    uri = "/",
    amz_date = "20231114T221320Z",
    signature = "057b5a659bc51e0d7466798a4c7757001db057a83715be961fd693063a44cca5",
  },
  {
    name = "explicit payload hash",
    opts = { method = "GET", host = "bucket.s3.example.com", path = "/empty.bin",
      region = "us-east-1", time = 1440938160, payload_hash = EMPTY_SHA256 },
    uri = "/empty.bin",
    amz_date = "20150830T123600Z",
    signature = "4af46fe793425701728d81eeaae16b09867083e202c522c456a029d34aa86743",
  },
}

for _, c in ipairs(XCHECK) do
  test("sign_s3 matches Node.js reference: " .. c.name, function()
    local opts = { access_key = S3_AK, secret_key = S3_SK }
    for k, v in pairs(c.opts) do
      opts[k] = v
    end
    local h = assert(sigv4.sign_s3(opts))
    local scope = c.amz_date:sub(1, 8) .. "/" .. opts.region .. "/s3/aws4_request"
    eq(h.uri, c.uri, "uri")
    eq(h.amz_date, c.amz_date, "amz_date")
    eq(h.content_sha256, opts.payload_hash or "UNSIGNED-PAYLOAD", "content_sha256")
    eq(h.authorization, "AWS4-HMAC-SHA256 Credential=" .. S3_AK .. "/" .. scope
      .. ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" .. c.signature, "authorization")
  end)
end

test("sign_s3 agrees with sign over the same three headers", function()
  local h = assert(sigv4.sign_s3({
    method = "GET", host = "b.example.com", path = "/x y", region = "us-east-1",
    access_key = S3_AK, secret_key = S3_SK, time = 1440938160,
  }))
  local res = assert(sigv4.sign({
    method = "GET",
    uri = "/x%20y",
    headers = { host = "b.example.com", ["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD", ["x-amz-date"] = "20150830T123600Z" },
    payload_hash = "UNSIGNED-PAYLOAD",
    amz_date = "20150830T123600Z",
    region = "us-east-1",
    service = "s3",
    access_key = S3_AK,
    secret_key = S3_SK,
  }))
  eq(h.authorization, res.authorization)
end)

test("sign_s3 defaults: service s3, UNSIGNED-PAYLOAD, ngx.time()", function()
  local before = ngx.time()
  local h = assert(sigv4.sign_s3({
    method = "GET", host = "b.example.com", path = "/a", region = "us-east-1",
    access_key = S3_AK, secret_key = S3_SK,
  }))
  local after = ngx.time()
  eq(h.content_sha256, "UNSIGNED-PAYLOAD")
  local ok = h.amz_date == os.date("!%Y%m%dT%H%M%SZ", before) or h.amz_date == os.date("!%Y%m%dT%H%M%SZ", after)
  assert(ok, "amz_date " .. h.amz_date .. " is not the current time")
  assert(h.authorization:find("/us-east-1/s3/aws4_request, ", 1, true), h.authorization)
  local custom = assert(sigv4.sign_s3({
    method = "GET", host = "b.example.com", path = "/a", region = "us-east-1", service = "custom",
    access_key = S3_AK, secret_key = S3_SK, time = 1440938160,
  }))
  assert(custom.authorization:find("/20150830/us-east-1/custom/aws4_request, ", 1, true), custom.authorization)
end)

test("sign_s3 time is floored and formatted in UTC", function()
  local a = assert(sigv4.sign_s3({ method = "GET", host = "h", path = "/", region = "r", access_key = "a",
    secret_key = "s", time = 1440938160.9 }))
  eq(a.amz_date, "20150830T123600Z")
  local b = assert(sigv4.sign_s3({ method = "GET", host = "h", path = "/", region = "r", access_key = "a",
    secret_key = "s", time = 0 }))
  eq(b.amz_date, "19700101T000000Z")
end)

test("canonical_uri", function()
  local cases = {
    { nil, "/" },
    { "", "/" },
    { "/", "/" },
    { "/media/a b/%E4%B8%AD.png", "/media/a%20b/%E4%B8%AD.png" },
    { "/media/中.png", "/media/%E4%B8%AD.png" },
    { "/%e4%b8%ad", "/%E4%B8%AD", "lowercase escapes are re-encoded uppercase" },
    { "/a%2Fb", "/a/b", "%2F decodes to a path separator" },
    { "/a%2fb", "/a/b" },
    { "/~user/%7Efile", "/~user/~file" },
    { "/a%252F", "/a%252F", "decoded once only" },
    { "/AZaz09-_.~", "/AZaz09-_.~", "unreserved characters stay" },
    { "/a+b", "/a%2Bb", "+ is not a space" },
    { "/!$&'()*,;=:@", "/%21%24%26%27%28%29%2A%2C%3B%3D%3A%40" },
    { "/q%3Fx%3D1#f", "/q%3Fx%3D1%23f" },
    { "/bad%zz%", "/bad%25zz%25", "malformed escapes are kept and their % encoded" },
    { "/bad%4", "/bad%254" },
    { "/a//b/./../c/", "/a//b/./../c/", "no normalization" },
    { "/%00%09\t\127", "/%00%09%09%7F" },
    { "/\255\128", "/%FF%80", "raw non-UTF-8 bytes" },
  }
  for i, c in ipairs(cases) do
    eq(sigv4.canonical_uri(c[1]), c[2], "case " .. i .. " " .. tostring(c[1]) .. (c[3] and (" (" .. c[3] .. ")") or ""))
  end
end)

test("sign_s3 input validation", function()
  local function base()
    return {
      method = "GET", host = "b.example.com", path = "/a", region = "us-east-1",
      access_key = S3_AK, secret_key = S3_SK, time = 1440938160,
    }
  end
  local cases = {
    { "method", nil, "method" },
    { "method", "POST", "method" },
    { "method", "get", "method" },
    { "method", "PUT", "method" },
    { "host", nil, "host" },
    { "host", "", "host" },
    { "host", "   ", "host" },
    { "host", "a b.example.com", "host" },
    { "host", "b.example.com\r\nX-Evil: 1", "host" },
    { "host", 42, "host" },
    { "path", 42, "path" },
    { "path", "relative/key", "path must start with /" },
    { "region", nil, "region" },
    { "region", "", "region" },
    { "region", "us/east", "region" },
    { "region", "us east", "region" },
    { "service", "", "service" },
    { "service", "s/3", "service" },
    { "access_key", nil, "access_key" },
    { "access_key", "", "access_key" },
    { "access_key", "AK/ID", "access_key" },
    { "secret_key", nil, "secret_key" },
    { "secret_key", "", "secret_key" },
    { "secret_key", 42, "secret_key" },
    { "time", "1440938160", "time" },
    { "time", -1, "time" },
    { "time", 0 / 0, "time" },
    { "time", math.huge, "time" },
    { "payload_hash", "", "payload_hash" },
    { "payload_hash", "abc", "payload_hash" },
    { "payload_hash", EMPTY_SHA256:upper(), "payload_hash" },
    { "payload_hash", "unsigned-payload", "payload_hash" },
  }
  for _, c in ipairs(cases) do
    local opts = base()
    opts[c[1]] = c[2]
    local h, err = sigv4.sign_s3(opts)
    local label = c[1] .. "=" .. tostring(c[2])
    eq(h, nil, label)
    assert(type(err) == "string" and err:find(c[3], 1, true), label .. ": unexpected error " .. tostring(err))
  end
  local h, err = sigv4.sign_s3(nil)
  eq(h, nil)
  assert(err:find("table", 1, true), err)
  -- The base options themselves are valid, including host trimming and an
  -- empty path.
  assert(sigv4.sign_s3(base()))
  local opts = base()
  opts.host = " b.example.com "
  opts.path = ""
  local trimmed = assert(sigv4.sign_s3(opts))
  eq(trimmed.uri, "/")
  opts.host = "b.example.com"
  opts.path = nil
  eq(assert(sigv4.sign_s3(opts)).authorization, trimmed.authorization, "host value is trimmed")
end)

test("sign input validation", function()
  local function base()
    return {
      method = "GET", uri = "/", headers = { host = "h" }, payload_hash = EMPTY_SHA256,
      amz_date = "20150830T123600Z", region = "us-east-1", service = "s3", access_key = "a", secret_key = "s",
    }
  end
  assert(sigv4.sign(base()))
  local cases = {
    { "method", "", "method" },
    { "uri", "", "uri" },
    { "uri", "/a b", "uri" },
    { "query", 1, "query" },
    { "amz_date", "2015-08-30T12:36:00Z", "amz_date" },
    { "amz_date", nil, "amz_date" },
    { "payload_hash", nil, "payload_hash" },
    { "headers", nil, "headers" },
    { "headers", {}, "headers must not be empty" },
    { "headers", { ["bad name"] = "v" }, "header name" },
    { "headers", { host = "a\r\nb" }, "single-line" },
    { "headers", { host = 1 }, "single-line" },
    { "headers", { Host = "a", host = "b" }, "duplicate header host" },
    { "service", nil, "service" },
  }
  for _, c in ipairs(cases) do
    local r = base()
    r[c[1]] = c[2]
    local res, err = sigv4.sign(r)
    local label = c[1] .. "=" .. tostring(c[2])
    eq(res, nil, label)
    assert(type(err) == "string" and err:find(c[3], 1, true), label .. ": unexpected error " .. tostring(err))
  end
  local res, err = sigv4.sign("x")
  eq(res, nil)
  assert(err:find("table", 1, true), err)
end)

test("signing key cache", function()
  local opts = {
    method = "GET", host = "bucket.s3.example.com:9000", path = "/media/a b/%E4%B8%AD.png",
    region = "us-east-1", access_key = S3_AK, secret_key = S3_SK, time = 1440938160,
  }
  local want = "f7a55bb290fc7ebcac5acd1c4414f3430df9066f09d0f29b8e336907bf9be75b" -- Node.js reference above
  sigv4._cache_clear()
  eq(sigv4._cache_size(), 0)
  local first = assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 1, "miss derives and stores one key")
  local second = assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 1, "hit does not store again")
  eq(second.authorization, first.authorization, "cached key gives the same signature")
  eq(signature_of(second.authorization), want)

  -- Same day, other path and a later second: same key.
  opts.path = "/other"
  opts.time = 1440938160 + 3600
  assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 1, "same (secret, date, region, service)")
  -- Next day, other region, other secret, other service: new keys.
  opts.time = 1440938160 + 86400
  assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 2, "next day")
  opts.region = "eu-west-1"
  assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 3, "other region")
  opts.secret_key = S3_SK .. "x"
  assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 4, "other secret")
  opts.service = "custom"
  assert(sigv4.sign_s3(opts))
  eq(sigv4._cache_size(), 5, "other service")

  -- The cache is bounded and stays correct after it is dropped.
  for i = 1, 1000 do
    assert(sigv4.sign_s3({ method = "GET", host = "h", path = "/", region = "r" .. i, access_key = "a",
      secret_key = "s", time = 1440938160 }))
    assert(sigv4._cache_size() <= 256, "cache size " .. sigv4._cache_size())
  end
  local again = assert(sigv4.sign_s3({
    method = "GET", host = "bucket.s3.example.com:9000", path = "/media/a b/%E4%B8%AD.png",
    region = "us-east-1", access_key = S3_AK, secret_key = S3_SK, time = 1440938160,
  }))
  eq(again.authorization, first.authorization, "signature after eviction")
end)

test("signing key cache does not leak between known answers", function()
  -- Re-run both official vectors with a warm cache: the derived key of one
  -- must never be used for the other.
  sigv4._cache_clear()
  for _ = 1, 2 do
    local a = assert(sigv4.sign({
      method = "GET", uri = "/", headers = { host = "example.amazonaws.com", ["x-amz-date"] = "20150830T123600Z" },
      payload_hash = EMPTY_SHA256, amz_date = "20150830T123600Z", region = "us-east-1", service = "service",
      access_key = "AKIDEXAMPLE", secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    }))
    eq(a.signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
    local b = assert(sigv4.sign({
      method = "GET", uri = "/test.txt",
      headers = { host = "examplebucket.s3.amazonaws.com", range = "bytes=0-9",
        ["x-amz-content-sha256"] = EMPTY_SHA256, ["x-amz-date"] = "20130524T000000Z" },
      payload_hash = EMPTY_SHA256, amz_date = "20130524T000000Z", region = "us-east-1", service = "s3",
      access_key = S3_AK, secret_key = S3_SK,
    }))
    eq(b.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
  end
  eq(sigv4._cache_size(), 2)
  eq(sha256_hex(""), EMPTY_SHA256, "helper sanity")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
