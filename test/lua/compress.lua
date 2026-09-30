-- Compression negotiation (edgeweir.compress): Accept-Encoding parsing,
-- the choice of one coding, the response checks nginx's filters make, the
-- Vary rewrite of the origin layer and what the header filters do with
-- cached responses. Run with `make lua-test`.
local compress = require("edgeweir.compress")

local passed = 0
local function eq(got, want, msg)
  if got ~= want then
    error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2)
  end
end
local function test(name, fn)
  fn()
  passed = passed + 1
  print("ok   " .. name)
end

local ALL = { "zstd", "br", "gzip" }

test("parse reads q-values, x-gzip, duplicates and malformed elements", function()
  local q = compress.parse("gzip;q=0.5, BR , zstd;q=0, x-gzip;q=0.3, deflate;q=1.0, bad;q=2, weird;level=1, *;q=0.1")
  eq(q.gzip, 0.3, "gzip keeps its lowest q-value (x-gzip is gzip)")
  eq(q.br, 1, "br without q")
  eq(q.zstd, 0, "zstd;q=0")
  eq(q.deflate, 1)
  eq(q.bad, nil, "q above 1 is malformed")
  eq(q.weird, nil, "unknown parameters are malformed")
  eq(q["*"], 0.1)
  eq(compress.parse("gzip;q=0.123").gzip, 0.123)
  eq(compress.parse("gzip;q=0.1234").gzip, nil, "at most three decimals")
  eq(compress.parse("gzip;q=05").gzip, nil)
  eq(compress.parse("gzip ; Q = 0.5").gzip, 0.5)
  eq(next(compress.parse("")), nil)
  eq(next(compress.parse(nil)), nil)
end)

test("choose prefers zstd > br > gzip at equal q-values", function()
  eq(compress.choose("gzip, deflate, br, zstd", ALL), "zstd")
  eq(compress.choose("gzip, deflate, br", ALL), "br")
  eq(compress.choose("gzip", ALL), "gzip")
  eq(compress.choose("br;q=1, zstd;q=1, gzip;q=1", ALL), "zstd")
  eq(compress.choose("gzip, br, zstd", { "gzip", "br" }), "br", "only enabled and applicable codings")
  eq(compress.choose("zstd", { "gzip", "br" }), nil)
end)

test("choose follows q-values", function()
  eq(compress.choose("zstd;q=0.5, br;q=0.8, gzip;q=0.9", ALL), "gzip")
  eq(compress.choose("zstd;q=0.9, br;q=0.9, gzip", ALL), "gzip")
  eq(compress.choose("zstd;q=0.9, br, gzip;q=0.1", ALL), "br")
  eq(compress.choose("gzip;q=0, br;q=0, zstd;q=0", ALL), nil, "q=0 is not acceptable")
  eq(compress.choose("zstd;q=0, br;q=0.001", ALL), "br")
end)

test("choose applies * to codings the client does not name (RFC 9110)", function()
  eq(compress.choose("*", ALL), "zstd")
  eq(compress.choose("gzip;q=1, *;q=0.5", ALL), "gzip")
  eq(compress.choose("*;q=0.5, zstd;q=0", ALL), "br")
  eq(compress.choose("*;q=0", ALL), nil)
  eq(compress.choose("identity, *;q=0", ALL), nil)
  eq(compress.choose("gzip, *;q=0", ALL), "gzip")
end)

test("choose returns identity without Accept-Encoding, when empty or unknown", function()
  eq(compress.choose(nil, ALL), nil)
  eq(compress.choose("", ALL), nil)
  eq(compress.choose("identity", ALL), nil)
  eq(compress.choose("deflate, compress", ALL), nil)
  eq(compress.choose("gzip", {}), nil)
end)

local tls = {
  gzip = true, gzip_min_length = 256, gzip_types = { "text/css", "application/json" },
  brotli = true, brotli_min_length = 100, brotli_types = { "application/json" },
  zstd = true, zstd_min_length = 1000, zstd_types = { "text/css" },
}
local function codings(resp)
  return table.concat(compress.applicable(tls, resp), ",")
end

test("applicable mirrors the filters: status, encoding, length and types", function()
  eq(codings({ status = 200, content_type = "text/html; charset=utf-8", content_length = 5000 }), "zstd,br,gzip",
    "text/html is always compressible")
  eq(codings({ status = 200, content_type = "text/css", content_length = 500 }), "gzip", "zstd needs 1000 bytes; br not for css")
  eq(codings({ status = 200, content_type = "text/css", content_length = 5000 }), "zstd,gzip")
  eq(codings({ status = 200, content_type = "APPLICATION/JSON", content_length = 150 }), "br")
  eq(codings({ status = 200, content_type = "application/json" }), "br,gzip", "unknown length is compressible")
  eq(codings({ status = 404, content_type = "text/html" }), "zstd,br,gzip")
  eq(codings({ status = 403, content_type = "text/html" }), "zstd,br,gzip")
  eq(codings({ status = 206, content_type = "text/html" }), "")
  eq(codings({ status = 304, content_type = "text/html" }), "")
  eq(codings({ status = 200, content_type = "image/png", content_length = 5000 }), "")
  eq(codings({ status = 200, content_length = 5000 }), "", "no Content-Type")
  eq(codings({ status = 200, content_type = "text/html", content_encoding = "gzip" }), "", "already encoded")
  eq(codings({ status = 200, content_type = "text/html", head = true }), "", "HEAD")
  eq(#compress.applicable({ gzip = true, gzip_min_length = 0 }, { status = 200, content_type = "text/html", content_length = 0 }), 0,
    "empty bodies stay identity (minimum length 1)")
  eq(#compress.applicable(nil, { status = 200, content_type = "text/html" }), 0)
end)

test("enabled needs one of the algorithms", function()
  eq(compress.enabled({ tls = { gzip = true } }), true)
  eq(compress.enabled({ tls = { brotli = true } }), true)
  eq(compress.enabled({ tls = { zstd = true } }), true)
  eq(compress.enabled({ tls = { http2 = true } }), false)
  eq(compress.enabled({}), false)
  eq(compress.enabled(nil), false)
end)

test("strip_vary drops only Accept-Encoding", function()
  eq(compress.strip_vary("Accept-Encoding"), "")
  eq(compress.strip_vary("accept-encoding, Origin"), "Origin")
  eq(compress.strip_vary("Origin,Accept-Encoding , Accept-Language"), "Origin, Accept-Language")
  eq(compress.strip_vary("Origin"), "Origin")
  eq(compress.strip_vary("*"), "*")
  eq(compress.strip_vary(nil), nil)
end)

-- header_filter with a fake ngx: the request's Accept-Encoding after the
-- edge layer chose (nil: removed).
local function edge(site, accept_encoding, status, headers, method)
  local runtime = ngx
  local req_headers = { ["Accept-Encoding"] = accept_encoding }
  _G.ngx = {
    status = status,
    header = headers,
    var = { http_accept_encoding = accept_encoding },
    req = {
      get_method = function() return method or "GET" end,
      set_header = function(k, v) req_headers[k] = v end,
      clear_header = function(k) req_headers[k] = nil end,
    },
  }
  local ok, err = pcall(compress.header_filter, site)
  _G.ngx = runtime
  assert(ok, err)
  return req_headers["Accept-Encoding"]
end

local site = { tls = { gzip = true, gzip_min_length = 1, gzip_types = { "text/plain" }, brotli = true, brotli_min_length = 1,
  brotli_types = { "text/plain" }, zstd = true, zstd_min_length = 1, zstd_types = { "text/plain" } } }

test("a cached identity object serves zstd, br, gzip and identity clients", function()
  -- The same cached response (HIT) reaches the header filter for every
  -- client; only the request's Accept-Encoding differs.
  local cached = function() return { ["Content-Type"] = "text/plain", ["Content-Length"] = "4096", ["X-Cache"] = "HIT" } end
  eq(edge(site, "gzip, deflate, br, zstd", 200, cached()), "zstd")
  eq(edge(site, "gzip, deflate, br", 200, cached()), "br")
  eq(edge(site, "gzip", 200, cached()), "gzip")
  eq(edge(site, nil, 200, cached()), nil)
  eq(edge(site, "identity", 200, cached()), nil)
  eq(edge(site, "br;q=0.5, gzip", 200, cached()), "gzip")
end)

test("responses the origin encoded are never compressed again", function()
  eq(edge(site, "zstd, br, gzip", 200, { ["Content-Type"] = "text/plain", ["Content-Encoding"] = "gzip" }), nil)
end)

test("sites without edge compression keep the client's Accept-Encoding", function()
  eq(edge({ tls = { http2 = true } }, "gzip, br", 200, { ["Content-Type"] = "text/plain" }), "gzip, br")
  eq(edge({}, "gzip", 200, { ["Content-Type"] = "text/plain" }), "gzip")
end)

-- origin_header_filter with a fake ngx: the Vary the edge layer caches.
local function origin(site, headers)
  local runtime = ngx
  _G.ngx = { header = headers }
  local ok, err = pcall(compress.origin_header_filter, site)
  _G.ngx = runtime
  assert(ok, err)
  return headers["Vary"]
end

test("the origin layer keeps cached objects independent of Accept-Encoding", function()
  eq(origin(site, { ["Vary"] = "Accept-Encoding" }), nil, "identity response: Vary dropped")
  eq(origin(site, { ["Vary"] = "Accept-Encoding, Cookie" }), "Cookie")
  eq(origin(site, { ["Vary"] = { "Origin", "accept-encoding" } }), "Origin", "repeated Vary headers")
  eq(origin(site, { ["Vary"] = "Accept-Encoding", ["Content-Encoding"] = "br" }), "Accept-Encoding",
    "an encoded response keeps its Vary")
  eq(origin(site, { ["Vary"] = "Accept-Encoding", ["Content-Encoding"] = "identity" }), nil)
  eq(origin({ tls = { http2 = true } }, { ["Vary"] = "Accept-Encoding" }), "Accept-Encoding",
    "sites without edge compression keep the origin's Vary")
end)

print(("compression negotiation: %d tests passed"):format(passed))
