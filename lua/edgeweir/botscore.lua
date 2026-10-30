-- edgeweir.botscore: the bot score of a request (session detection,
-- feature session-detection-v1, ADR-0068).
--
-- A deterministic function of a few signals, no model: 1 is automated, 99
-- a person, below 30 counts as automated (http.request.bot.automated).
-- compute(s) takes the signals as plain values, so the scoring is tested
-- with fixtures (test/lua/botscore_vectors.json); signals(var, ja4, pass,
-- session) reads them from the request.
--
--   s.ua              the User-Agent ("" without one)
--   s.https           the request came over TLS
--   s.accept_language, s.accept_encoding, s.sec_fetch, s.sec_ch_ua
--                     whether the request carries those headers (any
--                     Sec-Fetch-* counts)
--   s.ja4             the connection's JA4 ("" unknown)
--   s.pass            the level of the request's valid challenge pass (0-4)
--   s.session         nil, or the request's valid session:
--                     {flags = the script's bits (F_*), stale = the script
--                     stopped reporting while pages were still loaded}
--
-- Hard signals give 1 whatever else holds: an empty User-Agent, one of a
-- tool, library, crawler or headless browser (edgeweir.uaclass), and a
-- session whose script saw navigator.webdriver, automation framework
-- globals or headless traits. Otherwise a browser User-Agent starts at
-- 50, any other at 30, and the rest adds or subtracts (PENALTY, BONUS);
-- the result stays within 2-99.
local uaclass = require("edgeweir.uaclass")

local _M = {}

local find, lower, match, sub = string.find, string.lower, string.match, string.sub
local tonumber = tonumber

_M.AUTOMATED_BELOW = 30

-- Bits of the session script's report (f).
_M.F_WEBDRIVER = 1
_M.F_FRAMEWORK = 2
_M.F_HEADLESS = 4
_M.F_NO_LANGUAGES = 8
_M.F_UNTRUSTED = 16
_M.F_INPUT = 32
_M.F_ALL = 63
-- The hard bits: webdriver, framework, headless.
_M.HARD = 7

_M.PENALTY = {
  accept_language = 20, accept_encoding = 15, sec_fetch = 20, sec_ch_ua = 10,
  tls_version = 10, alpn = 15, untrusted = 30, no_languages = 15, stale = 30,
}
_M.BONUS = { pass = 10, pass_captcha = 20, session = 20, input = 25 }

-- Browser classes of edgeweir.uaclass (tool, crawler and other are not).
local BROWSERS = {
  chrome = true, edge = true, firefox = true, safari = true, opera = true, samsung = true, uc = true,
  qq = true, wechat = true, yandex = true, ie = true,
}

-- has reports whether bit (a power of two) is set in flags.
local function has(flags, bit)
  return math.floor(flags / bit) % 2 == 1
end
_M.has = has

-- engine returns the browser engine a User-Agent claims and its major
-- (and minor) version: "chromium", "firefox" or "webkit" (Safari);
-- nil for others. Chrome, Firefox and Edge on iOS are WebKit.
function _M.engine(ua)
  local l = lower(ua)
  if find(l, "crios/", 1, true) or find(l, "fxios/", 1, true) or find(l, "edgios/", 1, true)
    or find(l, "iphone", 1, true) or find(l, "ipad", 1, true) then
    local major, minor = match(l, "os (%d+)_(%d+)")
    return "webkit", tonumber(major), tonumber(minor) or 0
  end
  local v = match(l, "firefox/(%d+)")
  if v then return "firefox", tonumber(v), 0 end
  v = match(l, "chrome/(%d+)") or match(l, "chromium/(%d+)")
  if v then return "chromium", tonumber(v), 0 end
  if find(l, "safari/", 1, true) then
    local major, minor = match(l, "version/(%d+)%.(%d+)")
    if major then return "webkit", tonumber(major), tonumber(minor) end
  end
  return nil
end

-- at_least compares a version with major.minor.
local function at_least(major, minor, m, n)
  return major ~= nil and (major > m or (major == m and (minor or 0) >= n))
end

-- expects returns which headers a browser engine sends over HTTPS:
-- Sec-Fetch-* (Chromium 80, Firefox 90, Safari 16.4) and Sec-CH-UA
-- (Chromium 89).
function _M.expects(ua)
  local engine, major, minor = _M.engine(ua)
  if engine == "chromium" then return at_least(major, 0, 80, 0), at_least(major, 0, 89, 0) end
  if engine == "firefox" then return at_least(major, 0, 90, 0), false end
  if engine == "webkit" then return at_least(major, minor, 16, 4), false end
  return false, false
end

-- hard reports whether the User-Agent alone marks automation.
function _M.hard_ua(ua)
  if type(ua) ~= "string" or ua == "" then return true end
  local class = uaclass.classify(ua).browser
  return class == "tool" or class == "crawler"
end

-- compute returns the score of signals s (see the header) and whether a
-- hard signal decided it.
function _M.compute(s)
  local ua = s.ua or ""
  if _M.hard_ua(ua) then return 1, true end
  local session = s.session
  local flags = session and tonumber(session.flags) or 0
  if session and flags % 8 ~= 0 then return 1, true end
  local browser = BROWSERS[uaclass.classify(ua).browser] == true
  local score = browser and 50 or 30
  local P, B = _M.PENALTY, _M.BONUS
  if browser then
    if not s.accept_language then score = score - P.accept_language end
    if not s.accept_encoding then score = score - P.accept_encoding end
    if s.https then
      local fetch, ch = _M.expects(ua)
      if fetch and not s.sec_fetch then score = score - P.sec_fetch end
      if ch and not s.sec_ch_ua then score = score - P.sec_ch_ua end
      local ja4 = s.ja4 or ""
      -- t13d1516h2_...: TLS version (2-3), ALPN's first value (9-10).
      if #ja4 >= 10 then
        if sub(ja4, 2, 3) ~= "13" then score = score - P.tls_version end
        local alpn = sub(ja4, 9, 10)
        if alpn ~= "h2" and alpn ~= "h3" then score = score - P.alpn end
      end
    end
  end
  local pass = tonumber(s.pass) or 0
  if pass >= 4 then
    score = score + B.pass_captcha
  elseif pass >= 2 then
    score = score + B.pass
  end
  if session then
    score = score + B.session
    if has(flags, _M.F_INPUT) then score = score + B.input end
    if has(flags, _M.F_UNTRUSTED) then score = score - P.untrusted end
    if has(flags, _M.F_NO_LANGUAGES) then score = score - P.no_languages end
    if session.stale then score = score - P.stale end
  end
  if score < 2 then score = 2 elseif score > 99 then score = 99 end
  return score, false
end

-- hard_flags reports whether a session's flags carry a hard signal.
function _M.hard_flags(flags)
  return (tonumber(flags) or 0) % 8 ~= 0
end

-- band_of returns the MinuteStats.bot_scores key of a score: "1" for 1-9,
-- "10" for 10-19, ... "90" for 90-99.
function _M.band_of(score)
  local tens = math.floor(score / 10) * 10
  return tens == 0 and "1" or tostring(tens)
end

-- signals reads a request's signals (ja4: the request's JA4 or ""; pass:
-- its pass level; session: as in compute).
function _M.signals(var, ja4, pass, session)
  local ua = var.http_user_agent
  if type(ua) == "table" then ua = ua[1] end
  return {
    ua = ua or "",
    https = var.scheme == "https",
    accept_language = var.http_accept_language ~= nil,
    accept_encoding = var.http_accept_encoding ~= nil,
    sec_fetch = var.http_sec_fetch_mode ~= nil or var.http_sec_fetch_dest ~= nil or var.http_sec_fetch_site ~= nil,
    sec_ch_ua = var.http_sec_ch_ua ~= nil,
    ja4 = ja4 or "",
    pass = pass or 0,
    session = session,
  }
end

return _M
