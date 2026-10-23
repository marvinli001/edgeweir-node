-- Raw paths and encoded path exemptions (edgeweir.uripath,
-- Site.encoded_path_exemptions, feature encoded-path-exemptions-v1): the
-- console's vectors (encoded_path_vectors.json, from rule-engine
-- encoded-path.ts) through classify and the access control scopes, and the
-- paths an exemption must never let through.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' --shdict 'edgeweir_health 1m' \
--     --shdict 'edgeweir_policy_logs 1m' --shdict 'edgeweir_stats 1m' --shdict 'edgeweir_topstats 1m' \
--     --shdict 'edgeweir_bans 1m' --shdict 'edgeweir_cc 1m' --shdict 'edgeweir_challenge 1m' \
--     --shdict 'edgeweir_purge 1m' --shdict 'edgeweir_tags 1m' test/lua/uripath.lua
local cjson = require("cjson.safe")
local uripath = require("edgeweir.uripath")
local access = require("edgeweir.access")
local waf = require("edgeweir.waf")

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

local vectors = assert(cjson.decode(assert(io.open("/t/encoded_path_vectors.json")):read("*a")))

-- JSON null is cjson.null.
local function null(v)
  if v == cjson.null then return nil end
  return v
end

-- exemptions turns the vectors' camelCase entries into the site table's.
local function exemptions(list)
  local out = {}
  for i, e in ipairs(list) do out[i] = { prefix = e.prefix, encoded_slash = e.encodedSlash, semicolon = e.semicolon } end
  return out
end

local function list(v)
  if v == nil then return "nil" end
  return "[" .. table.concat(v, " | ") .. "]"
end

test("vectors: ambiguous raw paths", function()
  for _, v in ipairs(vectors.ambiguous) do eq(uripath.ambiguous(v.raw), v.result, v.raw) end
end)

test("vectors: classify", function()
  for _, v in ipairs(vectors.classify) do
    local c = uripath.classify(v.raw, exemptions(v.exemptions))
    eq(c.ambiguous, v.ambiguous, v.name .. " ambiguous")
    eq(c.no_exemption, v.noExemption, v.name .. " no_exemption")
    eq(list(c.views), list(null(v.views)), v.name .. " views")
    eq(c.key, null(v.keyPath), v.name .. " key")
  end
end)

test("vectors: path scopes and grants", function()
  for _, v in ipairs(vectors.scope) do
    local c = uripath.classify(v.raw, exemptions(v.exemptions))
    eq(access.path_in_scope(v.uri, v.prefixes, v.excluded, c.ambiguous, c.no_exemption, c.views), v.result, v.name)
  end
  for _, v in ipairs(vectors.grant) do
    local c = uripath.classify(v.raw, exemptions(v.exemptions))
    eq(not c.ambiguous and access.cors_in_scope(v.uri, v.prefixes, c.views), v.result, v.name)
  end
end)

test("no exemption lets a dot segment, a parameter cut or an encoded separator through", function()
  local all = { { prefix = "/", encoded_slash = true, semicolon = true } }
  for _, raw in ipairs({ "/admin%2F..", "/admin%2F..%2Fx", "/x%2F.%2Fadmin", "/x/..;/admin", "/x/..;a=b/admin",
    "/x;a/../admin", "/x%2F..;/admin", "/x/.;/admin", "/;x/admin", "/%2Fadmin", "/x/a%252Fb", "/x/a%5Cb",
    "/x/a%2e%2e/b", "/x/a%3Bb", "/x/a\\b", "/x/a#b", "/%u002e%u002e/x" }) do
    eq(uripath.classify(raw, all).ambiguous, true, raw)
  end
  -- Without an exemption, and outside its prefix, nothing changes.
  for _, raw in ipairs({ "/files/a%2Fb", "/api/a;b" }) do
    eq(uripath.classify(raw, nil).ambiguous, true, raw)
    eq(uripath.classify(raw, { { prefix = "/other/", encoded_slash = true, semicolon = true } }).ambiguous, true, raw)
  end
  -- Prefixes compare raw bytes: no case folding, no decoding.
  eq(uripath.classify("/FILES/a%2Fb", { { prefix = "/files/", encoded_slash = true } }).ambiguous, true)
  eq(uripath.classify("/%66iles/a%2Fb", { { prefix = "/files/", encoded_slash = true } }).ambiguous, true)
end)

test("exempt paths through the access control scopes", function()
  local all = { { prefix = "/", encoded_slash = true, semicolon = true } }
  local function scope(raw, uri, prefixes, excluded)
    local c = uripath.classify(raw, all)
    return access.path_in_scope(uri, prefixes, excluded, c.ambiguous, c.no_exemption, c.views)
  end
  eq(scope("/admin;x/secret", "/admin;x/secret", { "/admin/" }, nil), true, "; cut into the prefix")
  eq(scope("/admin/public%2Fsecret", "/admin/public/secret", { "/admin/" }, { "/admin/public/" }), true,
    "an exclusion holds for one reading only")
  eq(scope("/admin/public/a%2Fb", "/admin/public/a/b", { "/admin/" }, { "/admin/public/" }), false, "every reading excluded")
  eq(scope("/files/a%2Fb", "/files/a/b", { "/admin/" }, nil), false, "an exempt path keeps its own scope")
  -- Hotlink: extension of any reading; exclusions of all.
  local h = access.compile_hotlink({ extensions = { "jpg" }, exclude_path_prefixes = { "/img/free/" } })
  local function hot(raw, uri)
    local c = uripath.classify(raw, all)
    return access.hotlink_decision(h, uri, require("edgeweir.expressions").path_extension(uri), "https://evil.test/", nil,
      function() return false end, c.ambiguous, c.no_exemption, c.views)
  end
  eq(hot("/x/a.php;.jpg", "/x/a.php;.jpg"), "deny", "the extension before the parameters")
  eq(hot("/x/a.jpg;v=1", "/x/a.jpg;v=1"), "deny", "the extension under the parameters")
  eq(hot("/img/free%2Fa.jpg", "/img/free/a.jpg"), "deny", "an exclusion for one reading only")
  eq(hot("/img/free/a%2Fb.jpg", "/img/free/a/b.jpg"), "skip", "excluded in every reading")
  eq(hot("/x/a.png", "/x/a.png"), "skip")
end)

test("CRS exclusions need every reading", function()
  local w = { exclusions = { { path = "/upload/", token = "a1" }, { path = "/upload/form", exact = true, token = "b2" } } }
  local function ex(raw, uri)
    local c = uripath.classify(raw, { { prefix = "/", encoded_slash = true, semicolon = true } })
    return waf.exclusion_value(w, uri, c.no_exemption, c.views)
  end
  eq(ex("/upload/a%2Fb", "/upload/a/b"), ",a1,")
  eq(ex("/upload%2Fa", "/upload/a"), nil, "the kept reading is outside the prefix")
  eq(ex("/upload/form;v=1", "/upload/form;v=1"), ",a1,", "exact only for the plain reading")
  eq(ex("/upload/form", "/upload/form"), ",a1,b2,")
end)

print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
