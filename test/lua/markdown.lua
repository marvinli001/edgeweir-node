-- Markdown for Agents (edgeweir.markdown): Accept negotiation, the path
-- check, routing, the class in the cache key, Vary: Accept and the
-- converted responses in the statistics. Run with `make lua-test`.
local markdown = require("edgeweir.markdown")
local cachekey = require("edgeweir.cachekey")

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

local ALL = { include = {}, exclude = {} }
local CHROME_NAV = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
-- What coding agents send.
local AGENT = "text/markdown, text/html;q=0.9, */*;q=0.8"

test("accept: text/markdown with q > 0 only", function()
  eq(markdown.accept(AGENT), true)
  eq(markdown.accept("text/markdown"), true)
  eq(markdown.accept("TEXT/Markdown ; charset=utf-8;q=0.1, text/html"), true, "any weight above 0, any case")
  eq(markdown.accept(CHROME_NAV), false)
  eq(markdown.accept("text/*, */*"), false, "wildcards do not name it")
  eq(markdown.accept("text/markdown;q=0"), false)
  eq(markdown.accept("text/markdown;q=0.5, text/markdown;q=0"), false, "the lowest of repeated types")
  eq(markdown.accept("text/markdown;q=2"), false, "malformed q")
  eq(markdown.accept({ "text/html", "text/markdown" }), true, "field lines")
  eq(markdown.accept(nil), false)
  eq(markdown.accept("text/markdownx"), false)
end)

test("path_eligible: HTML-like paths within the prefixes", function()
  for _, p in ipairs({ "/", "/docs/intro", "/a/index.html", "/a/page.HTM", "/x.php", "/y.aspx", "/z.do" }) do
    eq(markdown.path_eligible(ALL, p), true, p)
  end
  for _, p in ipairs({ "/app.js", "/s.css", "/i.png", "/f.pdf", "/data.json", "/feed.xml", "/README.md" }) do
    eq(markdown.path_eligible(ALL, p), false, p)
  end
  local md = { include = { "/blog/", "/docs/" }, exclude = { "/docs/private/" } }
  eq(markdown.path_eligible(md, "/blog/post"), true)
  eq(markdown.path_eligible(md, "/docs/a.html"), true)
  eq(markdown.path_eligible(md, "/shop/"), false, "outside the include prefixes")
  eq(markdown.path_eligible(md, "/docs/private/x"), false, "excluded")
  eq(markdown.path_eligible({ include = {}, exclude = { "/api/" } }, "/api/v1"), false)
  eq(markdown.path_eligible({}, "/x"), true, "missing lists")
end)

test("route sends a Markdown request to the converter, unsliced; HTML requests keep their path", function()
  local site = { markdown = ALL }
  local var = { edgeweir_origin_layer = "edgeweir_origin_noverify", edgeweir_range_mode = "slice", edgeweir_markdown = "" }
  local ctx = {}
  eq(markdown.route(site, var, ctx, { accept = AGENT }, "/docs/"), "md")
  eq(var.edgeweir_origin_layer, "edgeweir_markdown")
  eq(var.edgeweir_range_mode, "", "whole documents")
  eq(var.edgeweir_markdown, "up=edgeweir_origin_noverify")
  eq(ctx.edgeweir_markdown_vary, true)
  -- A browser: Vary, nothing else changes.
  var = { edgeweir_origin_layer = "edgeweir_origin_verify", edgeweir_range_mode = "slice", edgeweir_markdown = "" }
  ctx = {}
  eq(markdown.route(site, var, ctx, { accept = CHROME_NAV }, "/docs/"), nil)
  eq(var.edgeweir_origin_layer, "edgeweir_origin_verify"); eq(var.edgeweir_range_mode, "slice"); eq(var.edgeweir_markdown, "")
  eq(ctx.edgeweir_markdown_vary, true, "the HTML varies by Accept too")
  -- Not an HTML path: no Vary, no conversion.
  ctx = {}
  eq(markdown.route(site, var, ctx, { accept = AGENT }, "/app.js"), nil)
  eq(ctx.edgeweir_markdown_vary, nil)
  eq(markdown.route({}, var, ctx, { accept = AGENT }, "/"), nil, "a site without Markdown")
end)

test("the class joins the cache key before the purge epoch; the HTML's key is unchanged", function()
  local site = { id = "s1", cache_generation = 3, cache_key = { headers = {}, cookies = {} } }
  local req = { scheme = "https", host = "a.test", path = "/docs/", args = "" }
  local html = cachekey.build(site, req, 0)
  eq(html, "s1:3:https://a.test/docs/")
  req.markdown = "md"
  eq(cachekey.build(site, req, 0), html .. "|m=md")
  eq(cachekey.build(site, req, 1700000000123), html .. "|m=md#1700000000123")
end)

test("vary adds Accept to HTML and Markdown responses once", function()
  local h = { ["Content-Type"] = "text/html; charset=utf-8" }
  markdown.vary(h); eq(h["Vary"], "Accept")
  h = { ["Content-Type"] = "text/markdown; charset=utf-8", ["Vary"] = "Accept-Encoding" }
  markdown.vary(h); eq(h["Vary"], "Accept-Encoding, Accept")
  h = { ["Content-Type"] = "application/xhtml+xml", ["Vary"] = { "Origin", "Accept-Encoding" } }
  markdown.vary(h); eq(h["Vary"][3], "Accept")
  h = { ["Content-Type"] = "text/html", ["Vary"] = "accept" }
  markdown.vary(h); eq(h["Vary"], "accept", "already there")
  h = { ["Content-Type"] = "text/html", ["Vary"] = "*" }
  markdown.vary(h); eq(h["Vary"], "*")
  h = { ["Content-Type"] = "application/json" }
  markdown.vary(h); eq(h["Vary"], nil, "other types")
end)

test("converted counts complete 200 answers to GETs only", function()
  eq(markdown.converted("1", 200, "GET"), 1)
  eq(markdown.converted("1", 200, "HEAD"), 0)
  eq(markdown.converted("1", 206, "GET"), 0)
  eq(markdown.converted(nil, 200, "GET"), 0)
  eq(markdown.converted("", 200, "GET"), 0)
end)

test("the statistics report converted responses per site and minute", function()
  local stats = require("edgeweir.stats")
  local dict = ngx.shared.edgeweir_stats
  dict:flush_all()
  local minute = math.floor(ngx.time() / 60) * 60 - 60
  dict:incr(minute .. "|s1|req", 3, 0)
  dict:incr(minute .. "|s1|md", 2, 0)
  dict:incr(minute .. "|s2|req", 1, 0)
  local total, other = 0, nil
  for _, b in ipairs(stats.drain(ngx.time())) do
    if b.site_id == "s1" then total = total + (b.markdown_responses or 0) end
    if b.site_id == "s2" then other = b.markdown_responses end
  end
  eq(total, 2)
  eq(other, nil, "a site without Markdown reports none")
end)

print(passed .. " markdown tests passed")
