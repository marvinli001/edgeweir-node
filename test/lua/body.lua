-- The request body of the rules (proto v0.29.0, feature rules-body-v1,
-- ADR-0040): every vector of the console's body_vectors.json (form fields,
-- JSON paths, multipart file names, raw bytes, boundaries, argument checks)
-- through edgeweir.body, the parse cache, and when a body is read.
--
--   resty -I lua test/lua/body.lua
local cjson = require("cjson.safe")
local body = require("edgeweir.body")
local expressions = require("edgeweir.expressions")

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

local vectors = assert(cjson.decode(assert(io.open("/t/body_vectors.json")):read("*a")))

local function unhex(s)
  return (s:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

local checked = 0
local function check(got, want, msg)
  checked = checked + 1
  if want == cjson.null then want = nil end
  eq(got, want, msg)
end

test("vectors: form_value", function()
  for _, v in ipairs(vectors.form) do
    check(body.form_value(v.body, v.contentType, v.name), v.expected, cjson.encode(v))
  end
end)

test("vectors: json_value", function()
  for _, v in ipairs(vectors.json) do
    check(body.json_value(v.body, v.contentType, v.path), v.expected, cjson.encode(v))
  end
end)

test("vectors: file names", function()
  for _, v in ipairs(vectors.filenames) do
    check(body.filenames(v.body, v.contentType), v.expected, cjson.encode(v))
  end
end)

test("vectors: raw bytes", function()
  for _, v in ipairs(vectors.hex) do
    local fn = v.kind == "form" and body.form_value or body.json_value
    check(fn(unhex(v.bodyHex), v.contentType, v.arg), unhex(v.expectedHex), cjson.encode(v))
  end
end)

test("vectors: boundaries", function()
  for _, v in ipairs(vectors.boundary) do
    check(body.multipart_boundary(v.contentType), v.expected, v.contentType)
  end
end)

test("vectors: form names and JSON paths", function()
  for _, v in ipairs(vectors.validFormName) do check(body.valid_form_name(v.input), v.valid, v.input) end
  for _, v in ipairs(vectors.validJsonPath) do check(body.valid_json_path(v.input), v.valid, v.input) end
end)

test("vectors: every one was checked", function()
  local total = 0
  for _, list in pairs(vectors) do total = total + #list end
  eq(checked, total, "vectors checked")
  assert(total >= 100, "vectors read: " .. total)
end)

test("the expression functions read the request values like the console's evaluator", function()
  local function call(name, arg)
    return expressions.compile_value({ op = "call", field = name, value_type = "string",
      children = { { op = "const", value_type = "string", value = arg } } })
  end
  local req = { ["http.request.body.raw"] = "a=1&b=%41", ["http.request.headers.content-type"] = "application/x-www-form-urlencoded; charset=utf-8" }
  eq(call("form_value", "b")(req), "A")
  eq(call("form_value", "c")(req), "")
  eq(call("json_value", "a")(req), "", "not JSON")
  eq(call("form_value", "a")({}), "", "no body")
  -- Not bounded by MAX_VALUE, unlike computed strings.
  local long = string.rep("x", 9000)
  eq(#call("form_value", "q")({ ["http.request.body.raw"] = "q=" .. long, ["http.request.headers.content-type"] = "application/x-www-form-urlencoded" }), 9000)
  eq(#call("json_value", "q")({ ["http.request.body.raw"] = '{"q":"' .. long .. '"}', ["http.request.headers.content-type"] = "application/json" }), 9000)
  -- http.request.body.filenames comes from the body unless the values hold it.
  local names = expressions.compile({ op = "contains", field = "http.request.body.filenames", value_type = "string", value = ".php" }, {})
  local multipart = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"\r\n\r\n<?php\r\n--b--"
  eq(names({ ["http.request.body.raw"] = multipart, ["http.request.headers.content-type"] = "multipart/form-data; boundary=b" }), true)
  eq(names({ ["http.request.body.raw"] = multipart, ["http.request.headers.content-type"] = "multipart/form-data; boundary=b",
    ["http.request.body.filenames"] = "a.txt" }), false, "given")
  eq(names({}), false)
end)

test("a body is parsed once per kind and Content-Type", function()
  local real = body.parse_json
  local parses = 0
  body.parse_json = function(text) parses = parses + 1; return real(text) end
  local cache = {}
  local text = '{"a":{"b":"x"},"c":[1,2]}'
  eq(body.json_value(text, "application/json", "a.b", cache), "x")
  eq(body.json_value(text, "application/json", "c.1", cache), "2")
  eq(body.json_value(text, "application/json; charset=utf-8", "c.0", cache), "1")
  eq(parses, 2, "one parse per Content-Type")
  eq(body.json_value(text, "application/json", "a.b"), "x")
  eq(parses, 3, "no cache, no reuse")
  body.parse_json = real
  local invalid = {}
  eq(body.json_value("{", "application/json", "a", invalid), "")
  eq(body.json_value("{", "application/json", "b", invalid), "", "an invalid body is cached as invalid")
end)

test("JSON: nesting up to 128 levels, numbers as written, duplicate keys keep the last", function()
  local deep = string.rep("[", 128) .. "1" .. string.rep("]", 128)
  assert(body.parse_json(deep), "128 levels")
  eq(body.parse_json("[" .. deep .. "]"), nil, "129 levels")
  eq(body.json_value('{"n":-0.50e+3}', "application/json", "n"), "-0.50e+3")
  eq(body.json_value('{"a":"1","a":"2"}', "application/problem+json", "a"), "2")
  eq(body.json_value('{"s":"\\ud83d\\ude00\\ud800x"}', "application/json", "s"), "\240\159\152\128\239\191\189x")
  eq(body.json_value('{"a":[0,1]}', "application/json", "a.01"), "", "no leading zeros")
  for _, bad in ipairs({ "", " ", "01", "1.", "-", "[1,]", '{"a"}', "tru", '"\t"', "\239\187\191{}", "[1]x", "{'a':1}" }) do
    eq(body.parse_json(bad), nil, bad)
  end
end)

test("multipart: at most 1000 parts, malformed parts end the parse", function()
  local parts = {}
  for i = 1, 1001 do
    parts[#parts + 1] = "--b\r\nContent-Disposition: form-data; name=\"f" .. i .. "\"\r\n\r\nv" .. i .. "\r\n"
  end
  local text = table.concat(parts) .. "--b--"
  local m = body.parse_multipart(text, "multipart/form-data; boundary=b")
  eq(m.fields.f1000, "v1000")
  eq(m.fields.f1001, nil, "part 1001")
  m = body.parse_multipart("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b\r\nbroken", "multipart/form-data; boundary=b")
  eq(m.fields.a, "1")
end)

test("decide: what is read", function()
  local limit = 1024
  eq(body.decide(limit, "10", nil, 1.1, false), "read")
  eq(body.decide(limit, "1024", nil, 2.0, false), "read", "the limit itself")
  eq(body.decide(limit, "1025", nil, 1.1, false), "truncated", "over the limit")
  eq(body.decide(0, "65536", nil, 1.1, false), "read", "0 is 65536")
  eq(body.decide(0, "65537", nil, 1.1, false), "truncated")
  eq(body.decide(limit, nil, nil, 1.1, false), "empty", "HTTP/1.1 without a body")
  eq(body.decide(limit, nil, nil, 1.0, false), "empty", "HTTP/1.0 without a body")
  eq(body.decide(limit, nil, "chunked", 1.1, false), "truncated", "chunked")
  eq(body.decide(limit, "10", "chunked", 1.1, false), "truncated", "chunked with a length")
  eq(body.decide(limit, nil, nil, 2.0, false), "truncated", "HTTP/2 without Content-Length")
  eq(body.decide(limit, nil, nil, 3.0, false), "truncated", "HTTP/3 without Content-Length")
  eq(body.decide(limit, "10", nil, 1.1, true), "truncated", "WebSocket or gRPC")
  eq(body.decide(limit, "0", nil, 1.1, false), "read", "an empty body")
end)

-- with runs fn with ngx.var and ngx.req replaced: var (request variables),
-- version, data (the body in memory) or file (its temporary file).
local function with(opts, fn)
  local runtime = ngx
  local reads = 0
  local fake = setmetatable({
    var = opts.var or {},
    req = setmetatable({
      http_version = function() return opts.version or 1.1 end,
      read_body = function() reads = reads + 1; if opts.fail then error("client went away") end end,
      get_body_data = function() return opts.data end,
      get_body_file = function() return opts.file end,
    }, { __index = runtime.req }),
  }, { __index = runtime })
  _G.ngx = fake
  local ok, a, b = pcall(fn)
  _G.ngx = runtime
  assert(ok, a)
  return a, b, reads
end

test("load: reads within the limit, from memory or the temporary file, once", function()
  local site = { rules_body_limit = 2048 }
  local state = { site = site }
  local raw, truncated, reads = with({ var = { http_content_length = "5" }, data = "a=1&b" }, function() return body.load(state) end)
  eq(raw, "a=1&b"); eq(truncated, false); eq(reads, 1)
  raw = with({ var = { http_content_length = "5" }, data = "other" }, function() return body.load(state) end)
  eq(raw, "a=1&b", "read once per request")
  local path = os.tmpname()
  local f = assert(io.open(path, "wb")); f:write("q=from-file"); f:close()
  raw, truncated = with({ var = { http_content_length = "11" }, file = path }, function() return body.load({ site = site }) end)
  os.remove(path)
  eq(raw, "q=from-file"); eq(truncated, false)
  raw, truncated = with({ var = { http_content_length = "0" } }, function() return body.load({ site = site }) end)
  eq(raw, ""); eq(truncated, false, "an empty body")
  raw, truncated, reads = with({ var = { http_content_length = "4096" }, data = "x" }, function() return body.load({ site = site }) end)
  eq(raw, ""); eq(truncated, true); eq(reads, 0, "over the limit: never read")
  raw, truncated, reads = with({ var = {}, version = 2.0 }, function() return body.load({ site = site }) end)
  eq(truncated, true); eq(reads, 0, "HTTP/2 GET without Content-Length")
  raw, truncated, reads = with({ var = {}, version = 1.1 }, function() return body.load({ site = site }) end)
  eq(truncated, false); eq(reads, 0, "HTTP/1.1 without a body")
  raw, truncated, reads = with({ var = { http_content_length = "5", http_upgrade = "WebSocket" }, data = "x" }, function() return body.load({ site = site }) end)
  eq(truncated, true); eq(reads, 0, "WebSocket")
  local grpc = { rules_body_limit = 2048, grpc = true }
  raw, truncated, reads = with({ var = { http_content_length = "5", http_content_type = "application/grpc+proto" }, data = "x" },
    function() return body.load({ site = grpc }) end)
  eq(truncated, true); eq(reads, 0, "gRPC")
  raw, truncated, reads = with({ var = { http_content_length = "5", http_content_type = "application/json" }, data = "{}" },
    function() return body.load({ site = grpc }) end)
  eq(raw, "{}"); eq(truncated, false, "another request of a gRPC site")
  raw, truncated = with({ var = { http_content_length = "5" }, fail = true }, function() return body.load({ site = site }) end)
  eq(raw, ""); eq(truncated, true, "a failed read")
  eq(with({ var = { http_content_length = "123" } }, body.size), 123)
  eq(with({ var = {} }, body.size), -1)
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
