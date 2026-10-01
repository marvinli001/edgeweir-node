local cjson = require("cjson.safe")
local engine = require("edgeweir.expressions")
local rules = require("edgeweir.rules")
local vectors = assert(cjson.decode(assert(io.open("/t/expression-vectors.json")):read("*a")))
local challenge_levels = require("edgeweir.challenge").LEVELS

-- Shared vectors (packages/rule-engine/test/vectors.json in the console):
-- accepted conditions and value expressions evaluate to the expected result,
-- structured cache conditions match like their expression, derived fields
-- come out alike. Rejected patterns and IR never reach the data plane: the
-- console and configir refuse them.
local counts = { condition = 0, value = 0, structured = 0, derive = 0, actions = 0 }
for i, vector in ipairs(vectors) do
  local where = "vector " .. i .. ": " .. tostring(vector.source or vector.input)
  if vector.derive then
    local derive = assert(({ extension = engine.path_extension, media_type = engine.media_type })[vector.derive], where)
    local got = derive(vector.input)
    assert(got == vector.expected, where .. ": got " .. tostring(got))
    counts.derive = counts.derive + 1
  elseif not vector.rejected then
    local lists = {}; for id, entries in pairs(vector.lists) do lists[id] = engine.ip_set(entries) end
    if vector.value then
      local got = engine.compile_value(vector.ir)(vector.request)
      assert(got == vector.expected, where .. ": got " .. tostring(got))
      counts.value = counts.value + 1
    else
      local match = engine.compile(vector.ir, lists)
      assert(match(vector.request) == vector.expected, where)
      counts.condition = counts.condition + 1
    end
    local st = vector.structured
    if st then
      -- The structured form older nodes read matches like the expression.
      local rule = rules.prepare({ id = "v", action = "cache", ttl = 1, mode = "override",
        path_prefixes = st.pathPrefixes, paths = st.paths, extensions = st.extensions })
      assert(rules.request_matches(rule, vector.request["http.request.uri.path"]) == vector.expected, where .. " (structured)")
      counts.structured = counts.structured + 1
    end
    -- Challenge actions the console compiles name a level the edge knows.
    local action = vector.action
    if type(action) == "table" and action.kind == "challenge" and not vector.actionRejected then
      assert(challenge_levels[action.challenge], where .. ": unknown challenge " .. tostring(action.challenge))
      counts.actions = counts.actions + 1
    end
  end
end
for kind, n in pairs(counts) do assert(n > 0, "no " .. kind .. " vectors") end

-- `$` outside a class becomes \z; escaped and bracketed `$` stay literal.
local prefix = "(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(*LF)"
for pattern, want in pairs({
  [""] = "",
  ["^/a$"] = "^/a\\z",
  ["(a$|b)$"] = "(a\\z|b)\\z",
  ["\\$[$]\\\\$"] = "\\$[$]\\\\\\z",
  ["[\\]$]$"] = "[\\]$]\\z",
}) do
  assert(engine.pcre_pattern(pattern) == prefix .. want, "pcre_pattern " .. pattern)
end

local function eq(got, want, msg)
  if got ~= want then error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2) end
end
local unit = 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if not ok then error(name .. ": " .. tostring(err), 0) end
  unit = unit + 1
end

test("url_decode", function()
  for input, want in pairs({
    [""] = "", ["a+b"] = "a b", ["%41%2b%2B"] = "A++", ["%4"] = "%4", ["%"] = "%", ["%zz"] = "%zz",
    ["%%41"] = "%A", ["%4+"] = "%4 ", ["+%2B+"] = " + ", ["%e4%b8%ad"] = "中", ["%00"] = "\0",
    ["%252F"] = "%2F", ["a%2"] = "a%2", ["%G1%41"] = "%G1A",
  }) do
    eq(engine.url_decode(input), want, "url_decode " .. input)
  end
end)

test("wildcard_replace", function()
  local w = engine.wildcard_replace
  eq(w("/img/A.png", "/IMG/*", "/images/${1}"), "/images/A.png", "case-insensitive")
  eq(w("/img/A.png", "/IMG/*", "/images/${1}", "s"), "/img/A.png", "case-sensitive")
  eq(w("/a/b/c", "/*/*", "${1}|${2}"), "a|b/c", "leftmost placement")
  eq(w("/abc", "/**", "[${1}][${2}]"), "[][abc]", "adjacent wildcards")
  eq(w("/a", "/a*a", "${1}"), "/a", "suffix before the position")
  eq(w("/aa", "/a*a", "<${1}>"), "<>", "empty capture")
  eq(w("/exact", "/exact", "/other"), "/other", "no wildcard")
  eq(w("/exactly", "/exact", "/other"), "/exactly", "no wildcard, no match")
  eq(w("/a*b/x", "/a\\*b/*", "/${1}"), "/x", "escaped star")
  eq(w("/a\\b", "/a\\\\b", "/c"), "/c", "escaped backslash")
  eq(w("/éx", "/É*", "${1}"), "/éx", "non-ASCII bytes are not folded")
  eq(w("/A.HTML", "/*.html", "/${1}"), "/A", "captures keep the original bytes")
  eq(w("x/y/z", "*/*", "${2}-${1}"), "y/z-x", "first segment empty")
  eq(w("abc", "*", "<${1}>"), "<abc>", "lone wildcard")
  eq(w("", "*", "<${1}>"), "<>", "lone wildcard, empty source")
  eq(w("ab", "a*b*c", "x"), "ab", "missing segment")
  eq(w("a1b2", "a*b*", "${1}${2}${3}"), "12", "missing captures are empty")
end)

test("regex_replace and sub_template", function()
  local r = engine.regex_replace
  eq(engine.sub_template("/$1/$${1}/${2}/${9}/${x}$"), "/$$1/$$${1}/${2}/$${9}/$${x}$$")
  eq(r("/aaa", "a", "b"), "/baa", "first match only")
  eq(r("/y", "^/(x)|^/(y)$", "[${1}|${2}]"), "[|y]", "unset group")
  eq(r("/p", "^/(p)$", "/$1/$${1}"), "/$1/$p", "literal dollars")
  eq(r("/a", "^", "/v2"), "/v2/a", "empty match")
  eq(r("/x", "^/old/(.*)$", "/new/${1}"), "/x", "no match")
  eq(r("/a\n", "a$", "b"), "/a\n", "$ is the end of the value")
  eq(r("/a", "a", "\\0\\1"), "/\\0\\1", "backslashes are literal")
  eq(r("/a", "(a)", "${1}${1}${1}"), "/aaa")
  local ok, err = pcall(r, string.rep("a", 40), "^\\w*\\w*\\w*\\w*\\w*\\w*\\w*\\W", "b")
  assert(not ok and tostring(err):find("regular expression evaluation failed", 1, true), "match budget fails: " .. tostring(err))
end)

test("value expressions are at most MAX_VALUE bytes", function()
  local function call(name, typ, ...) return { op = "call", field = name, value_type = typ, children = { ... } } end
  local path = { op = "field", field = "p", value_type = "string" }
  local function const(v) return { op = "const", value_type = "string", value = v } end
  local concat = engine.compile_value(call("concat", "string", path, path))
  eq(#concat({ p = string.rep("a", 4096) }), 8192, "exactly 8192")
  assert(not pcall(concat, { p = string.rep("a", 4097) }), "8194 bytes")
  -- Fields and constants are not functions: only computed strings count.
  eq(#engine.compile_value(path)({ p = string.rep("a", 9000) }), 9000)
  local lower = engine.compile_value(call("lower", "string", path))
  assert(not pcall(lower, { p = string.rep("A", 8193) }), "lower of 8193 bytes")
  local cond = engine.compile({ op = "eq", value_type = "string", value = "x", children = { call("upper", "string", path) } }, {})
  assert(not pcall(cond, { p = string.rep("a", 8193) }), "conditions fail closed too")
  local wild = engine.compile_value(call("wildcard_replace", "string", path, const("*"), const("${1}${1}")))
  assert(not pcall(wild, { p = string.rep("a", 4097) }), "wildcard result")
  eq(#wild({ p = string.rep("a", 4096) }), 8192)
  local len = engine.compile_value(call("len", "number", path))
  eq(len({ p = string.rep("a", 10000) }), 10000, "len of a long field")
end)

test("functions in conditions", function()
  local host = { op = "field", field = "http.host", value_type = "string" }
  local function call(name, typ, ...) return { op = "call", field = name, value_type = typ, children = { ... } } end
  local function const(v) return { op = "const", value_type = "string", value = v } end
  local starts = engine.compile(call("starts_with", "boolean", host, const("")), {})
  eq(starts({}), true, "empty prefix of a missing field")
  local ends = engine.compile({ op = "not", children = { call("ends_with", "boolean", host, const(".test")) } }, {})
  eq(ends({ ["http.host"] = "a.test" }), false)
  eq(ends({ ["http.host"] = "test" }), true, "suffix longer than the value")
  local len = engine.compile({ op = "in", value_type = "number", values = { "0", "3" }, children = { call("len", "number", host) } }, {})
  eq(len({}), true, "missing field is empty")
  eq(len({ ["http.host"] = "中" }), true, "bytes, not characters")
  local m = engine.compile({ op = "matches", value_type = "string", value = "^ab$", children = { call("concat", "string", const("a"), const("b")) } }, {})
  eq(m({}), true)
  local ip = engine.compile({ op = "eq", value_type = "ip", value = "192.0.2.0/24", children = { { op = "field", field = "ip.src", value_type = "ip" } } }, {})
  eq(ip({ ["ip.src"] = "192.0.2.7" }), true)
end)

test("derived fields", function()
  eq(engine.full_uri("https", "a.test", "/p?q=1"), "https://a.test/p?q=1")
  eq(engine.media_type(nil), "")
  eq(engine.media_type("\ttext/HTML ; q"), "text/html")
  eq(engine.path_extension("/a/b.c/d.E"), "e")
  eq(rules.extension("/file."), nil, "rules.extension shares path_extension")
  eq(rules.extension("/.PNG"), "png")
end)

test("reads", function()
  local e = { op = "and", children = {
    { op = "call", field = "ip.geoip.country", value_type = "boolean", children = {} },
    { op = "eq", value_type = "string", children = { { op = "call", field = "lower", value_type = "string", children = { { op = "field", field = "tls.ja4", value_type = "string" } } } } },
  } }
  local function is(name) return function(f) return f == name end end
  eq(engine.reads(e, is("tls.ja4")), true, "nested field")
  eq(engine.reads(e, is("ip.geoip.country")), false, "function names are not fields")
  eq(engine.reads(nil, is("x")), false)
end)

print(tostring(counts.condition) .. " conditions, " .. counts.value .. " values, " .. counts.structured
  .. " structured and " .. counts.derive .. " derived shared TS/Lua vectors passed (" .. counts.actions
  .. " challenge actions), " .. unit .. " unit tests")
