-- WebP / AVIF variants (edgeweir.imageconv, ADR-0043): Accept negotiation,
-- the path check, the converter's header, routing of a cacheable request,
-- the class in the cache key, Vary: Accept and the saved bytes in the
-- statistics. Run with `make lua-test`.
local imageconv = require("edgeweir.imageconv")
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

local BOTH = { webp = true, avif = true, webp_quality = 80, avif_quality = 50, jpeg = true, png = true,
  min_size = 1024, max_size = 10485760, max_pixels = 16000000 }
local WEBP = { webp = true, webp_quality = 75, jpeg = true, min_size = 0, max_size = 1048576, max_pixels = 4000000 }

-- Accept values of browsers' image requests and navigations.
local CHROME_IMG = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
local CHROME_NAV = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
local SAFARI_IMG = "image/webp,image/avif,image/jxl,image/heic,image/heic-sequence,video/*;q=0.8,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
local OLD_IMG = "image/webp,*/*"

test("accept reads explicit q-values of image/avif, image/webp and text/html", function()
  local a, w, h = imageconv.accept(CHROME_IMG)
  eq(a, 1); eq(w, 1); eq(h, 0)
  a, w, h = imageconv.accept("image/webp;q=0.5, IMAGE/AVIF ; q=0, text/html;level=1;q=0.3")
  eq(a, 0, "q=0 does not accept"); eq(w, 0.5); eq(h, 0.3, "parameters before q")
  a, w = imageconv.accept("image/webp;q=0.9, image/webp;q=0.2")
  eq(w, 0.2, "the lowest of repeated types")
  a, w = imageconv.accept("image/*, */*")
  eq(a, 0, "image/* does not name avif"); eq(w, 0, "*/* does not name webp")
  a, w = imageconv.accept("image/webp;q=2, image/avif;q=0.1234")
  eq(w, 0, "malformed q"); eq(a, 0, "four decimals")
  a, w = imageconv.accept({ "image/avif", "image/webp;q=0.1" })
  eq(a, 1, "repeated header lines"); eq(w, 0.1)
  a, w, h = imageconv.accept(nil)
  eq(a, 0); eq(w, 0); eq(h, 0)
end)

test("class prefers avif, then webp, then the original; navigations get the original", function()
  eq(imageconv.class(BOTH, CHROME_IMG), "avif")
  eq(imageconv.class(BOTH, SAFARI_IMG), "avif", "order in Accept does not matter")
  eq(imageconv.class(BOTH, OLD_IMG), "webp")
  eq(imageconv.class(BOTH, "image/avif;q=0, image/webp"), "webp")
  eq(imageconv.class(BOTH, "*/*"), nil, "curl's default")
  eq(imageconv.class(BOTH, nil), nil, "no Accept")
  eq(imageconv.class(BOTH, CHROME_NAV), nil, "a navigation names text/html")
  eq(imageconv.class(BOTH, "image/webp, text/html;q=0"), "webp", "text/html;q=0 is no navigation")
  eq(imageconv.class(WEBP, CHROME_IMG), "webp", "a site without AVIF")
  eq(imageconv.class({ avif = true, avif_quality = 50, jpeg = true }, OLD_IMG), nil, "a site without WebP")
end)

test("path_eligible: no extension, or one of the source types' (any case)", function()
  for _, p in ipairs({ "/a.jpg", "/a.JPEG", "/d.v2/b.jpe", "/c.jfif", "/x.png", "/img/123", "/", "/dir.d/file", "" }) do
    eq(imageconv.path_eligible(BOTH, p), true, p)
  end
  for _, p in ipairs({ "/a.gif", "/a.svg", "/a.webp", "/a.avif", "/s.js", "/s.css", "/i.html", "/a.jpg.bak", "/file.", "/.hidden" }) do
    eq(imageconv.path_eligible(BOTH, p), false, p)
  end
  eq(imageconv.path_eligible(WEBP, "/x.png"), false, "PNG not a source type")
  eq(imageconv.path_eligible(WEBP, "/x.jpg"), true)
end)

test("header names the class, its quality, the limits, the source types and the origin layer", function()
  eq(imageconv.header(BOTH, "avif", "edgeweir_origin_verify"),
    "avif;q=50;min=1024;max=10485760;px=16000000;src=jpeg,png;up=edgeweir_origin_verify")
  eq(imageconv.header(BOTH, "webp", "edgeweir_origin_noverify_h2"),
    "webp;q=80;min=1024;max=10485760;px=16000000;src=jpeg,png;up=edgeweir_origin_noverify_h2")
  eq(imageconv.header(WEBP, "webp", "edgeweir_origin_verify"),
    "webp;q=75;min=0;max=1048576;px=4000000;src=jpeg;up=edgeweir_origin_verify")
  eq(imageconv.header({ avif = true, avif_quality = 1, png = true, min_size = 0, max_size = 67108864, max_pixels = 50000000 }, "avif", "u"),
    "avif;q=1;min=0;max=67108864;px=50000000;src=png;up=u")
end)

test("route sends a variant to the converter, unsliced; the original keeps its path", function()
  local site = { image_convert = BOTH }
  local var = { edgeweir_origin_layer = "edgeweir_origin_noverify", edgeweir_range_mode = "slice", edgeweir_image = "" }
  local ctx = {}
  eq(imageconv.route(site, var, ctx, { accept = CHROME_IMG }, "/p.jpg"), "avif")
  eq(var.edgeweir_origin_layer, "edgeweir_image")
  eq(var.edgeweir_range_mode, "", "variants are whole objects")
  eq(var.edgeweir_image, "avif;q=50;min=1024;max=10485760;px=16000000;src=jpeg,png;up=edgeweir_origin_noverify")
  eq(ctx.edgeweir_image_vary, true)
  -- The original: Vary, nothing else changes.
  var = { edgeweir_origin_layer = "edgeweir_origin_verify", edgeweir_range_mode = "slice", edgeweir_image = "" }
  ctx = {}
  eq(imageconv.route(site, var, ctx, { accept = "*/*" }, "/p.jpg"), nil)
  eq(var.edgeweir_origin_layer, "edgeweir_origin_verify"); eq(var.edgeweir_range_mode, "slice"); eq(var.edgeweir_image, "")
  eq(ctx.edgeweir_image_vary, true, "the original varies by Accept too")
  -- Not an image path: no Vary, no variant.
  ctx = {}
  eq(imageconv.route(site, var, ctx, { accept = CHROME_IMG }, "/app.js"), nil)
  eq(ctx.edgeweir_image_vary, nil)
  eq(imageconv.route({}, var, ctx, { accept = CHROME_IMG }, "/p.jpg"), nil, "a site without conversion")
end)

test("the class joins the cache key before the purge epoch; the original's key is unchanged", function()
  local site = { id = "s1", cache_generation = 3, cache_key = { headers = {}, cookies = {} } }
  local req = { scheme = "https", host = "img.test", path = "/p.jpg", args = "" }
  local original = cachekey.build(site, req, 0)
  eq(original, "s1:3:https://img.test/p.jpg")
  req.image = "webp"
  eq(cachekey.build(site, req, 0), original .. "|i=webp")
  req.image = "avif"
  eq(cachekey.build(site, req, 1700000000123), original .. "|i=avif#1700000000123")
end)

test("vary adds Accept to image responses once", function()
  local h = { ["Content-Type"] = "image/jpeg" }
  imageconv.vary(h); eq(h["Vary"], "Accept")
  h = { ["Content-Type"] = "image/webp; charset=binary", ["Vary"] = "Accept-Encoding" }
  imageconv.vary(h); eq(h["Vary"], "Accept-Encoding, Accept")
  h = { ["Content-Type"] = "IMAGE/AVIF", ["Vary"] = { "Origin", "accept" } }
  imageconv.vary(h); eq(#h["Vary"], 2, "already there (any case)")
  h = { ["Content-Type"] = "image/png", ["Vary"] = { "Origin" } }
  imageconv.vary(h); eq(h["Vary"][2], "Accept")
  h = { ["Content-Type"] = "image/png", ["Vary"] = "*" }
  imageconv.vary(h); eq(h["Vary"], "*")
  h = { ["Content-Type"] = "text/html" }
  imageconv.vary(h); eq(h["Vary"], nil, "not an image")
  h = { ["Content-Type"] = "image/gif" }
  imageconv.vary(h); eq(h["Vary"], nil, "a type never converted")
  h = {}
  imageconv.vary(h); eq(h["Vary"], nil)
end)

test("saved counts complete 200 answers to GETs only", function()
  eq(imageconv.saved("1234", 200, "GET"), 1234)
  eq(imageconv.saved("1234", 206, "GET"), 0, "ranges")
  eq(imageconv.saved("1234", 200, "HEAD"), 0)
  eq(imageconv.saved(nil, 200, "GET"), 0)
  eq(imageconv.saved("-5", 200, "GET"), 0)
  eq(imageconv.saved("x", 200, "GET"), 0)
  eq(imageconv.saved("12.7", 200, "GET"), 12)
end)

test("the statistics report the saved bytes per site and minute", function()
  local stats = require("edgeweir.stats")
  local dict = ngx.shared.edgeweir_stats
  dict:flush_all()
  local minute = math.floor(ngx.time() / 60) * 60 - 60
  dict:incr(minute .. "|s1|req", 2, 0)
  dict:incr(minute .. "|s1|is", 1000, 0)
  dict:incr(minute .. "|s1|is", 234, 0)
  dict:incr(minute .. "|s2|req", 1, 0)
  local total, other = 0, nil
  for _, b in ipairs(stats.drain(ngx.time())) do
    if b.site_id == "s1" then total = total + (b.image_bytes_saved or 0) end
    if b.site_id == "s2" then other = b.image_bytes_saved end
  end
  eq(total, 1234)
  eq(other, nil, "a site without savings reports none")
end)

print(passed .. " imageconv tests passed")
