-- edgeweir.uaclass: the node's user agent classification table (ADR-0041,
-- MinuteStats.browsers, operating_systems, devices).
--
-- A small ordered table of substrings, no UA parser: crawlers first (also
-- those that claim a mobile browser), then tools and libraries, then the
-- browsers whose tokens other browsers do not repeat (WeChat and QQ embed
-- QQ's browser, Edge and Opera say Chrome, Chrome says Safari). Crawlers
-- and tools get operating system "other" (their platform is no visitor's)
-- and device "crawler" or "other". Results are cached per worker for 2048
-- user agents (at most 512 bytes of each are read).
local lrucache = require("resty.lrucache")

local _M = {}

local find, lower, sub = string.find, string.lower, string.sub

_M.BROWSERS = { "chrome", "edge", "firefox", "safari", "opera", "samsung", "uc", "qq", "wechat", "yandex", "ie", "crawler", "tool", "other" }
_M.OSES = { "windows", "macos", "ios", "android", "linux", "chromeos", "harmonyos", "other" }
_M.DEVICES = { "desktop", "mobile", "tablet", "crawler", "other" }
_M.MAX_LENGTH = 512

local cache = assert(lrucache.new(2048))

local function any(ua, tokens)
  for i = 1, #tokens do
    if find(ua, tokens[i], 1, true) then return true end
  end
  return false
end

-- Crawler names, and the "+http" link crawlers put in their user agent;
-- a "bot" followed by "/", ";", "-", ")" or at the end (not a "cubot x30"
-- phone model).
local CRAWLER = {
  "crawl", "spider", "slurp", "+http", "facebookexternalhit", "mediapartners-google", "feedfetcher",
  "google-inspectiontool", "googleother", "bingpreview", "ia_archiver", "yandex.com/bots",
}
local function is_crawler(ua)
  return any(ua, CRAWLER) or find(ua, "bot[/;%-%)]") ~= nil or find(ua, "bot$") ~= nil
end

local TOOL = {
  "curl/", "wget/", "python-requests", "python-urllib", "python-httpx", "aiohttp", "go-http-client", "okhttp",
  "java/", "apache-httpclient", "libwww-perl", "lwp::", "node-fetch", "undici", "axios/", "postmanruntime",
  "insomnia/", "httpie/", "powershell/", "winhttp", "guzzlehttp", "ruby", "faraday", "reqwest", "dart:io",
  "headlesschrome", "phantomjs",
}

-- Browsers in order; the first whose tokens match wins.
local BROWSER = {
  { "wechat", { "micromessenger" } },
  { "qq", { "mqqbrowser", "qqbrowser", " qq/" } },
  { "uc", { "ucbrowser", "ucweb" } },
  { "samsung", { "samsungbrowser" } },
  { "yandex", { "yabrowser", "yandex" } },
  { "opera", { "opr/", "opera", "opt/", "opios/" } },
  { "edge", { "edg/", "edge/", "edga/", "edgios/" } },
  { "ie", { "msie ", "trident/" } },
  { "firefox", { "firefox/", "fxios/" } },
  { "chrome", { "chrome/", "crios/", "chromium/" } },
  { "safari", { "safari/" } },
}

local OS = {
  { "harmonyos", { "harmonyos", "openharmony" } },
  { "windows", { "windows" } },
  { "ios", { "iphone", "ipad", "ipod" } },
  { "chromeos", { "cros " } },
  { "android", { "android" } },
  { "macos", { "macintosh", "mac os x" } },
  { "linux", { "linux", "x11" } },
}

local TV = { "smart-tv", "smarttv", "tizen", "web0s", "webos", "hbbtv", "appletv", "roku", "crkey", "playstation", "xbox", "nintendo" }
local TABLET = { "ipad", "tablet", "kindle", "silk/", "playbook" }
local MOBILE = { "mobile", "iphone", "ipod", "phone", "opera mini", "blackberry", "bb10" }
local DESKTOP = { windows = true, macos = true, linux = true, chromeos = true }

local function first(ua, list)
  for i = 1, #list do
    if any(ua, list[i][2]) then return list[i][1] end
  end
  return "other"
end

local OTHER = { browser = "other", os = "other", device = "other" }

local function classify(ua)
  if is_crawler(ua) then return { browser = "crawler", os = "other", device = "crawler" } end
  if any(ua, TOOL) then return { browser = "tool", os = "other", device = "other" } end
  local browser, os = first(ua, BROWSER), first(ua, OS)
  -- Televisions and consoles are "other"; Android tablets do not say
  -- "Mobile".
  local device = "other"
  if any(ua, TV) then
    device = "other"
  elseif any(ua, TABLET) then
    device = "tablet"
  elseif any(ua, MOBILE) then
    device = "mobile"
  elseif os == "android" or os == "harmonyos" then
    device = "tablet"
  elseif os == "ios" then
    device = "mobile"
  elseif DESKTOP[os] then
    device = "desktop"
  end
  return { browser = browser, os = os, device = device }
end

-- classify returns the classes of a User-Agent value ({browser, os,
-- device}; a shared table, never to be changed).
function _M.classify(value)
  if type(value) == "table" then value = value[1] end
  if type(value) ~= "string" or value == "" then return OTHER end
  local ua = sub(value, 1, _M.MAX_LENGTH)
  local hit = cache:get(ua)
  if hit then return hit end
  local c = classify(lower(ua))
  cache:set(ua, c)
  return c
end

return _M
