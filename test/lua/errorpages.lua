-- Error pages (edgeweir.errorpages): template rendering, escaping,
-- placeholders, built-in pages, nginx's own errors and the origin layer's
-- replacement rules.
--
--   resty -I lua --shdict 'edgeweir_sites 1m' --shdict 'edgeweir_meta 1m' test/lua/errorpages.lua
local errorpages = require("edgeweir.errorpages")
local challenge = require("edgeweir.challenge")
local origin = require("edgeweir.origin")
local store = require("edgeweir.store")

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
  local platform = errorpages.compile_platform({ unknown_host = "u {{host}}", site_disabled = "" })
  eq(errorpages.render(platform.unknown_host, VALUES), "u shop.test")
  eq(platform.site_disabled, nil, "empty: built-in page")
  platform = errorpages.compile_platform({ unknown_host = "", site_disabled = "d {{status}}" })
  eq(platform.unknown_host, nil, "empty: built-in page")
  eq(errorpages.render(platform.site_disabled, VALUES), "d 503")
  eq(next(errorpages.compile_platform(nil)), nil)
end)

test("built-in pages: status, title and request id in Chinese or English", function()
  for _, case in ipairs({
    { "zh", 403, "访问被拒绝" }, { "zh", 429, "请求过于频繁" }, { "zh", 502, "无法连接源站" }, { "zh", 503, "服务暂不可用" },
    { "zh", 504, "源站响应超时" }, { "zh", 404, "站点不存在" }, { "zh", "site-disabled", "站点已停用" },
    { "en", 403, "Access denied" }, { "en", 429, "Too many requests" },
    { "en", 502, "Origin unreachable" }, { "en", 503, "Service unavailable" }, { "en", 504, "Origin timed out" },
    { "en", 404, "Site not found" }, { "en", "site-disabled", "Site disabled" },
    -- nginx's own errors.
    { "zh", 400, "请求无效" }, { "zh", 413, "请求内容过大" }, { "zh", 414, "网址过长" }, { "zh", 494, "请求头过大" },
    { "zh", 497, "需要使用 HTTPS" }, { "zh", 500, "边缘节点出错" }, { "en", 400, "Bad request" },
    { "en", 413, "Request too large" }, { "en", 414, "URL too long" }, { "en", 494, "Request header too large" },
    { "en", 497, "HTTPS required" }, { "en", 500, "Edge error" },
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

test("built-in pages: the failing hop, what to do and a reload link where it helps", function()
  local values = { status = "503", request_id = "req-1", client_ip = "203.0.113.9", host = "<shop>.test",
    time = "2026-10-03 03:41:28 UTC" }
  for _, case in ipairs({
    -- kind, failing hop, its state, reload link
    { "zh", 403, "边缘节点", "拦截", false }, { "zh", 429, "边缘节点", "限速", true },
    { "zh", 404, "边缘节点", "未接入", false }, { "zh", 503, "边缘节点", "暂不可用", true },
    { "zh", "503-origin", "源站", "暂不可用", true }, { "zh", 502, "源站", "无法连接", true },
    { "zh", 504, "源站", "超时", true }, { "zh", "site-disabled", "边缘节点", "已停用", false },
    { "en", 403, "Edge", "Blocked", false }, { "en", 502, "Origin", "Unreachable", true },
    { "en", 504, "Origin", "Timed out", true }, { "en", "site-disabled", "Edge", "Disabled", false },
    { "en", 500, "Edge", "Error", true }, { "zh", 500, "边缘节点", "出错", true },
    -- Requests nginx refuses fail at the visitor; reloading sends the same request.
    { "zh", 400, "你", "格式错误", false }, { "en", 400, "You", "Malformed", false },
    { "zh", 413, "你", "过大", false }, { "en", 414, "You", "Too long", false },
    { "en", 494, "You", "Too large", false }, { "zh", 497, "你", "未加密", false },
    { "en", 497, "You", "Not encrypted", false },
  }) do
    local name = case[1] .. " " .. tostring(case[2])
    local page = errorpages.render(errorpages.builtin(case[1], case[2]), values)
    assert(page:find('<li class="x"><b>' .. case[3] .. "</b><span>" .. case[4] .. "</span></li>", 1, true),
      name .. ": failing hop")
    eq(select(2, page:gsub('<li class="x">', "")), 1, name .. ": one failing hop")
    eq(page:find('<a class="btn" href="">', 1, true) ~= nil, case[5], name .. ": reload link")
    assert(page:find("<dd>&lt;shop&gt;.test</dd>", 1, true), name .. ": escaped host")
    assert(page:find("203.0.113.9</details>", 1, true), name .. ": client address")
    assert(page:find("<dd>2026-10-03 03:41:28 UTC</dd>", 1, true), name .. ": time")
    assert(not page:find("{{", 1, true), name .. ": every placeholder filled")
    assert(#page < 10240, name .. ": " .. #page .. " bytes")
  end
  -- The origin's 503 keeps the 503 title; the hops before the failing one are fine.
  local page = errorpages.render(errorpages.builtin("en", "503-origin"), values)
  assert(page:find("<h1>Service unavailable</h1>", 1, true), "503-origin title")
  assert(page:find('<li><b>Edge</b><span>OK</span></li>', 1, true), "edge passed")
  page = errorpages.render(errorpages.builtin("en", 403), values)
  assert(page:find('<li class="n"><b>Origin</b><span>Not reached</span></li>', 1, true), "origin not reached")
  -- A rate limit reads differently from a block: its own mark and weight.
  local limited = errorpages.render(errorpages.builtin("en", 429), values)
  assert(not limited:find(".code{--w:760}", 1, true) and page:find(".code{--w:760}", 1, true), "429 weight")
  assert(limited:find('d="M-3.5-4.5h7l-7 9h7z"', 1, true) and not page:find('d="M-3.5-4.5h7l-7 9h7z"', 1, true), "429 mark")
  -- {{time}} is filled on built-in pages only; templates keep it as it is.
  eq(render("{{time}} {{status}}", values), "{{time}} 503")
end)

test("nginx's own errors: the status sent, the page and the code", function()
  for _, case in ipairs({
    -- nginx's status, CRS block, then the status sent, the page and X-Edgeweir-Error
    { 400, false, 400, 400, "bad-request" }, { 400, true, 400, 400, "waf-blocked" },
    { 494, false, 400, 494, "header-too-large" }, { 414, false, 414, 414, "uri-too-long" },
    { 413, false, 413, 413, "body-too-large" }, { 497, false, 400, 497, "https-required" },
    { 500, false, 500, 500, "internal-error" }, { 500, true, 500, 500, "internal-error" },
    { 502, false, 502, 502, "origin-unreachable" }, { 504, false, 504, 504, "origin-timeout" },
    -- Statuses error_page never hands over answer as an internal error.
    { 418, false, 500, 500, "internal-error" }, { 0, false, 500, 500, "internal-error" },
  }) do
    local status, kind, code = errorpages.nginx_error(case[1], case[2])
    local name = tostring(case[1]) .. (case[2] and " (CRS)" or "")
    eq(status, case[3], name .. ": status")
    eq(kind, case[4], name .. ": page")
    eq(code, case[5], name .. ": code")
  end
  -- None of them has a site template: pages exist for STATUSES only.
  for _, status in ipairs({ 400, 413, 414, 494, 497, 500 }) do
    eq(errorpages.STATUSES[status], nil, tostring(status))
  end
  eq(errorpages.compile_pages({ ["400"] = "x", ["500"] = "y" }), nil, "no site page for nginx's own errors")
end)

test("built-in pages of requests nginx refuses: the signal fails at the visitor", function()
  local values = { status = "400", request_id = "req-1", client_ip = "203.0.113.9", host = "", time = "t" }
  for _, case in ipairs({
    -- kind, the visitor's glyph, the signal it sends, the rules the page must not carry
    { 400, 'd="M-2.4-2.2a2.4', '<span class="s sa gb">', { ".sw{", ".zz{", ".fa{", ".btn{" } },
    { 413, 'd="M-4.2 0h8.4', '<span class="s sa sw">', { ".gb{", ".zz{", ".fa{", ".btn{" } },
    { 414, 'd="M-4.2 0h8.4', '<span class="s sa sw">', { ".gb{", ".zz{", ".fa{", ".btn{" } },
    { 494, 'd="M-4.2 0h8.4', '<span class="s sa sw">', { ".gb{", ".zz{", ".fa{", ".btn{" } },
    { 497, 'd="M-2.8-.6h5.6', '<span class="s sa fa">', { ".gb{", ".sw{", ".zz{", ".btn{" } },
  }) do
    local name = tostring(case[1])
    local page = errorpages.render(errorpages.builtin("en", case[1]), values)
    assert(page:find('<body class="at0">', 1, true), name .. ": failing hop class")
    assert(page:find(".at0 .top{--at:16.667%}", 1, true), name .. ": the readout over the visitor")
    assert(page:find('<svg x="16.667%" y="28" overflow="visible" class="m1"><g><circle class="bg" r="9.5"/><path class="g" '
      .. case[2], 1, true), name .. ": the visitor's mark")
    assert(page:find(case[3], 1, true), name .. ": the signal")
    assert(page:find('<span class="s sb hl">', 1, true), name .. ": nothing reaches the origin")
    assert(page:find('<li class="n"><b>Edge</b><span>Not reached</span></li><li class="n"><b>Origin</b><span>Not reached</span></li>',
      1, true), name .. ": edge node and origin not reached")
    for _, rule in ipairs(case[4]) do
      assert(not page:find(rule, 1, true), name .. ": carries " .. rule)
    end
    eq(select(2, page:gsub("%.hl line{", "")), 1, name .. ": the held line's rule once")
    assert(page:find("<dd></dd>", 1, true), name .. ": no host")
  end
  -- The same shape, told apart by words.
  local uri, header = errorpages.builtin("en", 414), errorpages.builtin("en", 494)
  assert(errorpages.render(uri, values):find("<h1>URL too long</h1>", 1, true))
  assert(errorpages.render(header, values):find("Clear this site's cookies", 1, true))
  -- The edge node's own failure (500) keeps the visitor's plain mark.
  local page = errorpages.render(errorpages.builtin("en", 500), values)
  assert(page:find('<body class="at1">', 1, true) and not page:find(".at0 ", 1, true), "500 at the edge node")
  assert(page:find('class="m1"><circle class="rg" r="9.5"/><circle class="dt" r="3.5"/></svg>', 1, true), "500: visitor fine")
end)

test("{{host}}: without the port, empty without a valid host", function()
  eq(errorpages.host("shop.test"), "shop.test")
  eq(errorpages.host("shop.test:8443"), "shop.test")
  eq(errorpages.host("[2001:db8::1]:443"), "[2001:db8::1]")
  eq(errorpages.host("[2001:db8::1]"), "[2001:db8::1]")
  eq(errorpages.host("_"), "", "the catch-all servers' name: the request named no valid host")
  eq(errorpages.host(""), "")
  eq(errorpages.host(nil), "")
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

test("origin layer: which responses become pages", function()
  local plain = store.prepare({ id = "p", cache_zone = "z", domains = { { name = "p.test" } },
    origins = { { id = "o1", scheme = "http", address = "o.test", port = 80 } } })
  local intercept = store.prepare({ id = "i", cache_zone = "z", domains = { { name = "i.test" } },
    origins = { { id = "o1", scheme = "http", address = "o.test", port = 80 } },
    error_pages = { pages = { ["503"] = "busy {{request_id}}", ["403"] = "no" }, intercept = true } })
  local keep = store.prepare({ id = "k", cache_zone = "z", domains = { { name = "k.test" } },
    origins = { { id = "o1", scheme = "http", address = "o.test", port = 80 } },
    error_pages = { pages = { ["503"] = "busy" } } })
  eq(intercept._intercept, true)
  eq(keep._intercept, false)
  eq(plain._error_pages, nil)
  -- nginx's own failures: a page for every site (built-in or the site's).
  eq(origin.page_code(plain, 502, "-"), "origin-unreachable")
  eq(origin.page_code(plain, 504, "0.1, -"), "origin-timeout")
  eq(origin.page_code(keep, 502, "-"), "origin-unreachable")
  -- Origin responses: only intercepted, only with a page for the status.
  eq(origin.page_code(plain, 503, "0.010"), nil)
  eq(origin.page_code(keep, 503, "0.010"), nil, "pages without intercept leave origin errors alone")
  eq(origin.page_code(intercept, 503, "0.010"), "origin-error")
  eq(origin.page_code(intercept, 403, "0.010"), "origin-error")
  eq(origin.page_code(intercept, 502, "0.010"), nil, "no page for 502")
  -- nginx's own 500 (an uncaught Lua error) never reaches the header filter:
  -- error_page hands it to origin.error_page. An origin's 500 passes unchanged.
  eq(origin.page_code(intercept, 500, "-"), nil, "nginx's 500 is error_page's")
  eq(origin.page_code(intercept, 500, "0.010"), nil, "no page for an origin's 500")
  eq(origin.page_code(intercept, 404, "0.010"), nil)
  eq(origin.page_code(intercept, 200, "0.010"), nil)
end)

test("origin layer: nginx's own errors yield to the edge's stale copy like other 5xx", function()
  local cached = store.prepare({ id = "c", cache_zone = "z", domains = { { name = "c.test" } },
    origins = { { id = "o1", scheme = "http", address = "o.test", port = 80 } },
    cache_rules = { { id = "sie", action = "cache", ttl = 60, mode = "override", sie = 600 },
      { id = "plain", action = "cache", ttl = 60, mode = "override" } } })
  eq(origin.yields_to_stale(cached, 500, "sie", "EXPIRED", false), true, "500 with an expired copy")
  eq(origin.yields_to_stale(cached, 500, "plain", "EXPIRED", false), false, "the rule serves nothing stale")
  eq(origin.yields_to_stale(cached, 500, "sie", "MISS", false), false, "no copy at the edge")
  eq(origin.yields_to_stale(cached, 500, "", "EXPIRED", false), false, "the edge does not cache the request")
  eq(origin.yields_to_stale(cached, 500, "unknown-rule", "EXPIRED", false), false, "rules the site no longer has")
  for _, status in ipairs({ 400, 413, 414, 494 }) do
    eq(origin.yields_to_stale(cached, status, "sie", "EXPIRED", false), false, status .. ": only 5xx")
  end
  eq(origin.yields_to_stale(nil, 500, "sie", "EXPIRED", false), false, "no site")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
