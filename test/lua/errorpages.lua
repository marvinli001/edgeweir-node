-- Error pages (edgeweir.errorpages): template rendering, escaping,
-- placeholders and built-in pages.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' test/lua/errorpages.lua
local errorpages = require("edgeweir.errorpages")
local challenge = require("edgeweir.challenge")

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

local function render(template, values)
  return errorpages.render(errorpages.compile(template), values)
end

local VALUES = { status = "503", request_id = "req-1234abcd", client_ip = "203.0.113.9", host = "shop.test" }

test("placeholders are replaced, everything else is sent as it is", function()
  eq(render("<h1>{{status}}</h1><p>{{request_id}} {{client_ip}} {{host}}</p>", VALUES),
    "<h1>503</h1><p>req-1234abcd 203.0.113.9 shop.test</p>")
  eq(render("{{status}}{{status}}", VALUES), "503503", "repeated placeholders")
  eq(render("{{ status }} {{STATUS}} {{other}} {{status} {status}} {{}}", VALUES),
    "{{ status }} {{STATUS}} {{other}} {{status} {status}} {{}}", "other {{...}} untouched")
  eq(render("{{{status}}}", VALUES), "{503}")
  eq(render("{{{{host}}", VALUES), "{{shop.test")
  eq(render("no placeholder", VALUES), "no placeholder")
  eq(render("{{status}}", VALUES), "503")
  eq(render("a{{", VALUES), "a{{")
  eq(render("<script>{{host}}</script>", VALUES), "<script>shop.test</script>", "template content is never interpreted or escaped")
end)

test("values are HTML-escaped and never expanded again", function()
  local v = { status = "403", request_id = "{{status}}", client_ip = "<b>&\"'", host = "x\"><img src=x>" }
  eq(render("{{request_id}}|{{client_ip}}|{{host}}", v), "{{status}}|&lt;b&gt;&amp;&quot;&#39;|x&quot;&gt;&lt;img src=x&gt;")
  eq(render("[{{host}}]", { status = "403" }), "[]", "a missing value renders empty")
end)

test("site pages compile only valid statuses and sizes", function()
  local pages = errorpages.compile_pages({ ["403"] = "a {{status}}", ["429"] = "b", ["404"] = "not a page status",
    ["502"] = "", ["503"] = string.rep("x", 65537), ["504"] = string.rep("y", 65536), ["x"] = "junk" })
  assert(pages[403] and pages[429] and pages[504])
  eq(pages[404], nil)
  eq(pages[502], nil, "empty")
  eq(pages[503], nil, "too large")
  eq(errorpages.render(pages[403], VALUES), "a 503")
  eq(errorpages.compile_pages({ ["404"] = "x" }), nil, "no valid page")
  eq(errorpages.compile_pages(nil), nil)
  local platform = errorpages.compile_platform({ unknown_host = "u {{host}}", site_disabled = "", site_suspended = "s" })
  eq(errorpages.render(platform.unknown_host, VALUES), "u shop.test")
  eq(platform.site_disabled, nil, "empty: built-in page")
  assert(platform.site_suspended)
  eq(next(errorpages.compile_platform(nil)), nil)
end)

test("built-in pages: status, title and request id in Chinese or English", function()
  for _, case in ipairs({
    { "zh", 403, "访问被拒绝" }, { "zh", 429, "请求过于频繁" }, { "zh", 502, "无法连接源站" }, { "zh", 503, "服务暂不可用" },
    { "zh", 504, "源站响应超时" }, { "zh", 404, "站点不存在" }, { "zh", "site-disabled", "站点已停用" },
    { "zh", "site-suspended", "站点已暂停" }, { "en", 403, "Access denied" }, { "en", 429, "Too many requests" },
    { "en", 502, "Origin unreachable" }, { "en", 503, "Service unavailable" }, { "en", 504, "Origin timed out" },
    { "en", 404, "Site not found" }, { "en", "site-disabled", "Site disabled" }, { "en", "site-suspended", "Site suspended" },
  }) do
    local page = errorpages.render(errorpages.builtin(case[1], case[2]), { status = "418", request_id = "rid-<x>" })
    assert(page:find(case[3], 1, true), case[1] .. " " .. tostring(case[2]) .. " title missing")
    assert(page:find('<p class="code">418</p>', 1, true), "status")
    assert(page:find("rid-&lt;x&gt;", 1, true), "escaped request id")
    assert(page:find(case[1] == "zh" and '<html lang="zh-CN">' or '<html lang="en">', 1, true), "lang")
    assert(page:find(case[1] == "zh" and "请求 ID" or "Request ID", 1, true), "request id label")
    assert(page:find("prefers-color-scheme:dark", 1, true), "dark mode")
    assert(not page:find("https?://") and not page:find("<script", 1, true) and not page:find("src=", 1, true),
      "self-contained, no script")
  end
  eq(errorpages.builtin("fr", 403), errorpages.builtin("en", 403), "unknown language: English")
  -- The language comes from Accept-Language like the challenge pages.
  eq(challenge.language("zh-CN,zh;q=0.9,en;q=0.8"), "zh")
  eq(challenge.language("en-US,en;q=0.9,zh;q=0.5"), "en")
  eq(challenge.language(nil), "en")
end)

test("nginx's own upstream failures are told apart from origin responses", function()
  eq(errorpages.generated("-"), true, "no response header")
  eq(errorpages.generated("0.002, -"), true, "the last attempt failed")
  eq(errorpages.generated("0.002, 0.004"), false)
  eq(errorpages.generated("- : 0.010"), false, "internal redirect groups")
  eq(errorpages.generated(""), true, "no upstream attempt")
  eq(errorpages.generated(nil), true)
  eq(errorpages.origin_code(502), "origin-unreachable")
  eq(errorpages.origin_code(504), "origin-timeout")
  eq(errorpages.origin_code(503), "origin-unreachable")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
