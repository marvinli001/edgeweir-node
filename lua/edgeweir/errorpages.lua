-- edgeweir.errorpages: error pages of node-generated responses.
--
-- Pages replace the plain-text answers of status 403 (bans, rule and list
-- denials, CRS blocks, missing challenge passes), 429 (rate limits), 502,
-- 503 and 504 (edge 503s, origin-layer failures including nginx's own
-- upstream failures) and, with the site's intercept_origin_errors, origin
-- responses whose status has a template of the site. The template is the
-- site's page for the status (Site.error_pages), else the built-in page.
-- Hosts no site serves get the platform's unknown_host page (404), the
-- offline hosts of disabled sites the platform's site_disabled page
-- (503). nginx's own errors get built-in pages too (nginx_page, through
-- error_page in nginx.conf): malformed requests and CRS blocks with
-- status 400, request headers (494, sent as 400) and URIs (414) that are
-- too long, bodies over client_max_body_size (413), plain HTTP on an
-- HTTPS port (497, sent as 400), uncaught Lua errors (500) and, at the
-- edge, failures towards the origin layer (502, 504). Other statuses the
-- node answers itself (404, 405, 421, 508, ...) keep their plain text.
--
-- Templates are compiled once (per site table version) into literal parts
-- and placeholders: {{status}}, {{request_id}}, {{client_ip}}, {{host}}
-- and, since proto v0.22.0 (feature rules-v3), {{time}} (when the node
-- answered, UTC, RFC 3339) and {{path}} (the request path, $uri) are
-- replaced with HTML-escaped values; anything else, including other
-- {{...}}, is sent as it is. Template content is never interpreted.
--
-- Built-in pages are self-contained (inline CSS and SVG, no script, no
-- external URL, light and dark), in Chinese or English by Accept-Language,
-- and show the status, which hop failed (the visitor for requests nginx
-- refuses, the edge node or the origin), a short title, what to do, the
-- request id, the host and the client address.
--
-- Every page: Content-Type text/html; charset=utf-8, Cache-Control:
-- no-store, the exact Content-Length and X-Edgeweir-Error: <code>. The edge
-- layer renders its access-phase denials directly (respond). The origin
-- layer renders its own failures directly and replaces nginx's upstream
-- failures (no response header from the last attempt) and intercepted
-- origin errors in its header filter (replace) and body filter
-- (body_filter); its pages also carry X-Accel-Expires: 0 so the edge never
-- caches them. The edge layer's CRS locations replace CRS blocks the same
-- way. nginx's own errors are rendered in the locations error_page hands
-- them to (nginx_page; edgeweir.router.error_page and
-- edgeweir.origin.error_page). Values: the request id is
-- $edgeweir_request_id at the edge and the
-- X-Request-Id request header in the origin layer, the client address
-- $remote_addr at the edge and X-Real-IP in the origin layer, the host the
-- request's host without port ("" when the request named no valid host).
local _M = {}

local concat, find, match, sub, gsub = table.concat, string.find, string.match, string.sub, string.gsub
local ipairs, pairs, tonumber, tostring, type = ipairs, pairs, tonumber, tostring, type

-- STATUSES are the statuses of node-generated responses that get error
-- pages (the site's page of the status or of its class, else the built-in
-- page) instead of plain text; 405 (S3 origins refusing a method) and 413
-- (a site's body limit) since proto v0.24.0.
_M.STATUSES = { [400] = true, [403] = true, [405] = true, [413] = true, [414] = true, [429] = true,
  [500] = true, [502] = true, [503] = true, [504] = true }

-- PAGE_STATUSES are the statuses and classes (4: 4xx, 5: 5xx) a site may
-- have pages for (feature site-content-v1 beyond 403, 429, 502-504).
_M.PAGE_STATUSES = { [4] = true, [5] = true, [400] = true, [401] = true, [403] = true, [404] = true,
  [405] = true, [410] = true, [429] = true, [500] = true, [502] = true, [503] = true, [504] = true }

-- REDIRECT_NAMES are the placeholders of an error page's redirect URL,
-- replaced with percent-encoded values.
local REDIRECT_NAMES = { status = true, request_id = true }

_M.MAX_TEMPLATE = 65536

local NAMES = { status = true, request_id = true, client_ip = true, host = true, time = true, path = true }

-- Built-in pages show the time the node answered in their own format
-- ({{display_time}}, which templates do not know).
local BUILTIN_NAMES = { status = true, request_id = true, client_ip = true, host = true, display_time = true }

-- times returns {{time}} (RFC 3339, UTC) and the built-in pages' time.
local function times()
  local now = ngx.time()
  return os.date("!%Y-%m-%dT%H:%M:%SZ", now), os.date("!%Y-%m-%d %H:%M:%S UTC", now)
end

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }

function _M.escape(s)
  return (gsub(tostring(s or ""), "[&<>\"']", ESCAPES))
end

-- compile splits a template into literal strings and placeholders
-- ({ name } tables); names defaults to the placeholders of templates.
function _M.compile(template, names)
  names = names or NAMES
  local parts, n = {}, 0
  local pos, literal = 1, 1
  while true do
    local s = find(template, "{{", pos, true)
    if not s then
      break
    end
    local name, after = match(template, "^([%l_]+)}}()", s + 2)
    if name and names[name] then
      if s > literal then
        n = n + 1
        parts[n] = sub(template, literal, s - 1)
      end
      n = n + 1
      parts[n] = { name }
      pos, literal = after, after
    else
      pos = s + 1
    end
  end
  if literal <= #template then
    n = n + 1
    parts[n] = sub(template, literal)
  end
  return parts
end

-- render fills a compiled template with values (name -> string).
function _M.render(parts, values)
  local out, escaped = {}, {}
  for i = 1, #parts do
    local p = parts[i]
    if type(p) == "table" then
      local name = p[1]
      local v = escaped[name]
      if not v then
        v = _M.escape(values[name])
        escaped[name] = v
      end
      out[i] = v
    else
      out[i] = p
    end
  end
  return concat(out)
end

-- compile_pages compiles a site's pages ({"<status>": {template,
-- redirect, status}}, or a template string) into {[status] = page}: page
-- = { parts, status } (status: the one to send, nil keeps it) or
-- { redirect = parts }. nil without a valid page.
function _M.compile_pages(pages)
  if type(pages) ~= "table" then
    return nil
  end
  local out, any = {}, false
  for status, page in pairs(pages) do
    local code = tonumber(status)
    if type(page) == "string" then
      page = { template = page }
    end
    if code and _M.PAGE_STATUSES[code] and type(page) == "table" then
      local template, redirect = page.template, page.redirect
      if type(redirect) == "string" and redirect ~= "" then
        out[code] = { redirect = _M.compile(redirect, REDIRECT_NAMES) }
        any = true
      elseif type(template) == "string" and template ~= "" and #template <= _M.MAX_TEMPLATE then
        local send = tonumber(page.status)
        out[code] = { parts = _M.compile(template), status = (send and send >= 200 and send <= 599) and send or nil }
        any = true
      end
    end
  end
  return any and out or nil
end

-- page_for returns the site's page for status: the status's own, else its
-- class's (4xx, 5xx); nil when the site has neither.
function _M.page_for(site, status)
  local pages = site and site._error_pages
  if not pages or type(status) ~= "number" then
    return nil
  end
  return pages[status] or pages[math.floor(status / 100)]
end

-- render_url fills a compiled redirect URL with percent-encoded values
-- (everything but RFC 3986 unreserved characters).
function _M.render_url(parts, values)
  local out = {}
  for i = 1, #parts do
    local p = parts[i]
    out[i] = type(p) == "table" and ngx.escape_uri(tostring(values[p[1]] or "")) or p
  end
  return concat(out)
end

-- compile_platform compiles the platform's pages ({unknown_host,
-- site_disabled}); empty or missing ones stay nil.
function _M.compile_platform(pages)
  local out = {}
  if type(pages) ~= "table" then
    return out
  end
  for _, name in ipairs({ "unknown_host", "site_disabled" }) do
    local template = pages[name]
    if type(template) == "string" and template ~= "" and #template <= _M.MAX_TEMPLATE then
      out[name] = _M.compile(template)
    end
  end
  return out
end

-- ---------------------------------------------------------------------
-- Built-in pages
--
-- A built-in page reads one request like an instrument: a signal runs from
-- the visitor through the edge node to the origin and stops, thins out or
-- breaks at the hop that failed (SHAPES), under the status set large. A
-- request nginx refuses (malformed, too large, plain HTTP on an HTTPS
-- port) fails at the visitor: its signal never gets through to the edge
-- node. The hops say in words which one failed; below come the title, what
-- to do, a reload link where reloading can help, the request id, the host
-- and the client address (shown on request). Motion is CSS only and stops
-- under prefers-reduced-motion; the page has no script and no external
-- URL.
--
-- Kinds are statuses, nginx's own 494 (request header too large) and 497
-- (plain HTTP on an HTTPS port), both sent as 400, "site-disabled" and
-- "503-origin" (see builtin).

local TITLES = {
  zh = {
    [400] = "请求无效", [403] = "访问被拒绝", [404] = "站点不存在", [413] = "请求内容过大", [414] = "网址过长",
    [429] = "请求过于频繁", [494] = "请求头过大", [497] = "需要使用 HTTPS", [500] = "边缘节点出错",
    [502] = "无法连接源站", [503] = "服务暂不可用", [504] = "源站响应超时", ["site-disabled"] = "站点已停用",
    [405] = "不支持的请求方法", maintenance = "维护中",
  },
  en = {
    [400] = "Bad request", [403] = "Access denied", [404] = "Site not found", [413] = "Request too large",
    [414] = "URL too long", [429] = "Too many requests", [494] = "Request header too large", [497] = "HTTPS required",
    [500] = "Edge error", [502] = "Origin unreachable", [503] = "Service unavailable", [504] = "Origin timed out",
    ["site-disabled"] = "Site disabled", [405] = "Method not allowed", maintenance = "Under maintenance",
  },
}
local LANG = { zh = "zh-CN", en = "en" }
local REQUEST_ID = { zh = "请求 ID", en = "Request ID" }

-- TEXT: the hops, their states and the page's other words; stamp is the
-- failing hop's state, todo what the visitor can do.
local TEXT = {
  zh = {
    hops = { "你", "边缘节点", "源站" }, ok = "正常", unreached = "未到达",
    host = "域名", ip = "你的 IP", show = "显示", reload = "重新加载", time = "时间",
    stamp = {
      [400] = "格式错误", [403] = "拦截", [404] = "未接入", [413] = "过大", [414] = "过长", [429] = "限速",
      [494] = "过大", [497] = "未加密", [500] = "出错", [502] = "无法连接", [503] = "暂不可用", [504] = "超时",
      ["site-disabled"] = "已停用", other = "出错", [405] = "不支持", maintenance = "维护中",
    },
    todo = {
      [400] = "边缘节点无法解析这个请求，请检查网址后重试。",
      [403] = "如果你认为这是误拦，请把请求 ID 发给网站管理员。",
      [404] = "这台边缘节点没有为此域名配置网站，请检查网址。",
      [413] = "上传的内容超过了边缘节点允许的大小，请减小后重试。",
      [414] = "网址超过了边缘节点允许的长度，请检查链接。",
      [429] = "请稍等片刻再试。",
      [494] = "请清除此网站的 Cookie 后重试。",
      [497] = "此端口只接受 HTTPS，请在网址中使用 https。",
      [500] = "请稍后重试；问题持续时，请把请求 ID 发给网站管理员。",
      [502] = "源站可能暂时离线，请稍后重试。",
      [503] = "请稍后重试。",
      [504] = "源站没有及时响应，请稍后重试。",
      ["site-disabled"] = "网站管理员已停用此站点。",
      [405] = "这个网址不接受这种请求方法。",
      maintenance = "网站正在维护，请稍后再来。",
      other = "请稍后重试。",
    },
  },
  en = {
    hops = { "You", "Edge", "Origin" }, ok = "OK", unreached = "Not reached",
    host = "Host", ip = "Your IP", show = "Show", reload = "Reload", time = "Time",
    stamp = {
      [400] = "Malformed", [403] = "Blocked", [404] = "No site", [413] = "Too large", [414] = "Too long",
      [429] = "Rate limited", [494] = "Too large", [497] = "Not encrypted", [500] = "Error", [502] = "Unreachable",
      [503] = "Unavailable", [504] = "Timed out", ["site-disabled"] = "Disabled", other = "Error",
      [405] = "Not allowed", maintenance = "Maintenance",
    },
    todo = {
      [400] = "The edge couldn't read this request. Check the URL and try again.",
      [403] = "If you think this is a mistake, send the request ID to the site's owner.",
      [404] = "This edge serves no site at this address. Check the URL.",
      [413] = "The upload is larger than the edge accepts. Make it smaller, then try again.",
      [414] = "The address is longer than the edge accepts. Check the link.",
      [429] = "Wait a moment, then try again.",
      [494] = "Clear this site's cookies, then try again.",
      [497] = "This port only accepts HTTPS. Use https in the address.",
      [500] = "Try again shortly. If it keeps happening, send the request ID to the site's owner.",
      [502] = "The origin may be offline for a moment. Try again shortly.",
      [503] = "Try again shortly.",
      [504] = "The origin didn't answer in time. Try again shortly.",
      ["site-disabled"] = "The site's owner has turned this site off.",
      [405] = "This address does not accept this request method.",
      maintenance = "The site is under maintenance. Please come back later.",
      other = "Try again shortly.",
    },
  },
}

-- SHAPES: the failing hop (at: 0 the visitor, 1 the edge node, 2 the
-- origin), the signal from the visitor to the edge node (a) and on to the
-- origin (b), the failing hop's mark, the readout's weight and whether
-- reloading can help. 503-origin is a 503 of the origin (nginx's own
-- upstream failure). A request nginx refuses leaves the visitor garbled
-- (malformed), swollen against the edge node's limit (too large) or
-- fading out unencrypted (plain HTTP on an HTTPS port).
local SHAPES = {
  [400] = { at = 0, a = "garble", b = "held", mark = "query", w = 640 },
  [403] = { at = 1, a = "flow", b = "held", mark = "stop", w = 760 },
  [404] = { at = 1, a = "flow", b = "fade", mark = "logo", w = 250, void = true },
  [413] = { at = 0, a = "swell", b = "held", mark = "wide", w = 880 },
  [414] = { at = 0, a = "swell", b = "held", mark = "wide", w = 880 },
  [429] = { at = 1, a = "chirp", b = "held", mark = "hourglass", w = 560, retry = true },
  [494] = { at = 0, a = "swell", b = "held", mark = "wide", w = 880 },
  [497] = { at = 0, a = "fade", b = "held", mark = "lock", w = 420 },
  [500] = { at = 1, a = "flow", b = "held", mark = "cross", w = 680, retry = true },
  [502] = { at = 2, a = "flow", b = "noise", mark = "cross", w = 700, retry = true },
  [503] = { at = 1, a = "flow", b = "held", mark = "pause", w = 600, retry = true },
  ["503-origin"] = { at = 2, a = "flow", b = "flow", mark = "pause", w = 600, retry = true },
  [504] = { at = 2, a = "flow", b = "slow", mark = "clock", w = 200, retry = true },
  ["site-disabled"] = { at = 1, a = "flow", b = "held", mark = "pause", w = 500 },
  [405] = { at = 1, a = "flow", b = "held", mark = "stop", w = 700 },
  maintenance = { at = 1, a = "flow", b = "held", mark = "pause", w = 500, retry = true },
  other = { at = 1, a = "flow", b = "held", mark = "cross", w = 600, retry = true },
}

local STYLE = [=[:root{color-scheme:light dark;--bg:#fff;--fg:#0a0a0a;--mu:#737373;--gr:#e5e5e5;--de:#cfcfcf;--sg:#2a78d6;--bd:#e7000b;--bt:#1447e6;--bf:#eff6ff;--lk:#1447e6;--h:1px;--e:cubic-bezier(.16,1,.3,1);--sa:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}]=]
  .. [=[@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--fg:#fafafa;--mu:#a1a1a1;--gr:#232323;--de:#3d3d3d;--sg:#3987e5;--bd:#ff6467;--bt:#193cb8;--bf:#eff6ff;--lk:#3987e5}}]=]
  .. [=[@media (min-resolution:2dppx){:root{--h:.5px}}*{box-sizing:border-box}html,body{margin:0}]=]
  .. [=[body{background:var(--bg);color:var(--fg);font:15px/1.5 var(--sa);-webkit-font-smoothing:antialiased}]=]
  .. [=[::selection{background:color-mix(in srgb,var(--sg) 22%,transparent)}:focus-visible{outline:2px solid var(--sg);outline-offset:3px}]=]
  .. [=[main{min-height:100vh;min-height:100svh;display:grid;place-items:center;padding:56px 20px;overflow:hidden}]=]
  .. [=[.f{position:relative;width:min(100%,960px)}.f:before,.f:after,.top:before,.top:after{content:"";position:absolute;pointer-events:none}]=]
  .. [=[.f:before{inset:0 -100vw;border-block:var(--h) dashed var(--gr)}.f:after{inset:-100vh 0;border-inline:var(--h) dashed var(--gr)}]=]
  .. [=[.top:after{inset:auto -100vw 0;border-top:var(--h) dashed var(--gr)}]=]
  .. [=[.top:before{inset:auto 0 0;height:5px;background:repeating-linear-gradient(90deg,var(--de) 0 var(--h),transparent 0 2.0833%)}]=]
  .. [=[.d{position:absolute;width:7px;height:7px;margin:-3.5px;background:var(--bg);border:var(--h) solid var(--de);z-index:1}]=]
  .. [=[.d1,.d3{top:0}.d2,.d4,.d5,.d6{top:100%}.d1,.d2,.d5{left:0}.d3,.d4,.d6{left:100%}]=]
  .. [=[.top{position:relative;padding:44px 0 26px;--at:50%}.at2 .top{--at:83.333%}]=]
  .. [=[.code{width:max-content;margin:0 0 0 var(--at);transform:translateX(-50%);font-size:clamp(76px,13vw,136px);line-height:.78;letter-spacing:-.04em;font-weight:var(--w);font-variant-numeric:tabular-nums;animation:wt 1.2s var(--e) both}]=]
  .. [=[@keyframes wt{from{font-weight:100;opacity:0}}.tr{position:relative;height:56px;margin-top:30px}.df{position:absolute;width:0;height:0}]=]
  .. [=[.cur{position:absolute;left:var(--at);top:-26px;height:38px;border-left:var(--h) dashed var(--fg);opacity:.45;animation:fd .5s .9s both}]=]
  .. [=[.hd{position:absolute;top:28px;left:16.667%;width:7px;height:7px;margin:-3.5px;border-radius:50%;background:var(--sg);opacity:0;animation:h1 .9s .1s both;z-index:2}.hd:after{content:"";position:absolute;inset:-4px;border:1px solid var(--sg);border-radius:50%;opacity:.5}]=]
  .. [=[@keyframes h1{0%{opacity:1;left:16.667%;animation-timing-function:var(--e)}78%{opacity:1;left:50%}to{opacity:0;left:50%;scale:2.4}}]=]
  .. [=[.s{position:absolute;top:0;height:56px;width:33.333%}.s svg{display:block;width:100%;height:56px}]=]
  .. [=[.sa{left:16.667%;animation:wp .7s .1s var(--e) both}.sb{left:50%;animation:wp .6s .8s var(--e) both}@keyframes wp{from{clip-path:inset(0 100% 0 0)}}]=]
  .. [=[.ln{fill:none;stroke:var(--sg);stroke-width:1.5;stroke-linecap:round;vector-effect:non-scaling-stroke;animation:fl 1.6s linear infinite}@keyframes fl{to{translate:var(--p,-24px)}}]=]
  .. [=[.mk{position:absolute;inset:0;width:100%;height:56px;overflow:visible}.mk *{vector-effect:non-scaling-stroke}.dt{fill:var(--fg)}.rg{fill:var(--bg);stroke:var(--de)}]=]
  .. [=[.bg,.bx{fill:var(--bg);stroke:var(--fg);stroke-width:1.5}.g{fill:none;stroke:var(--fg);stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}]=]
  .. [=[.at1 .m2 *,.at2 .m3 *{stroke:var(--bd)}.at1 .m2 g,.at2 .m3 g{transform-origin:0 0;animation:pp .5s .75s var(--e) both}@keyframes pp{from{opacity:0;scale:.5}}]=]
  .. [=[.hops{list-style:none;margin:18px 0 0;padding:0;display:grid;grid-template-columns:repeat(3,1fr);text-align:center}.hops li{display:grid;justify-items:center;min-width:0}]=]
  .. [=[.hops b{font-weight:560;font-size:14px}.hops span{font-size:12.5px;color:var(--mu)}.hops .x span{color:var(--bd);font-weight:560;animation:fd .3s .8s both}.hops .n b{color:var(--mu);font-weight:500}]=]
  .. [=[.bot{display:grid;gap:28px 64px;padding:34px 4px 36px;animation:rs .7s .4s var(--e) both}@keyframes rs{from{opacity:0;translate:0 10px}}@keyframes fd{from{opacity:0}}]=]
  .. [=[@media (min-width:720px){.bot{grid-template-columns:minmax(0,1fr) minmax(0,16.5rem);padding:44px 44px 48px}}]=]
  .. [=[h1{margin:0;font-size:28px;line-height:1.15;font-weight:620;letter-spacing:-.02em;text-wrap:balance}.todo{margin:10px 0 0;color:var(--mu);max-width:34em;text-wrap:pretty}]=]
  .. [=[dl{margin:0;display:grid;gap:12px;align-content:start}dl div{display:grid;gap:3px;padding-top:11px;border-top:var(--h) solid var(--gr)}dt{color:var(--mu);font-size:12px}]=]
  .. [=[dd{margin:0;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}.rid{user-select:all}]=]
  .. [=[summary{cursor:pointer;width:max-content;font:13px/1.5 var(--sa);color:var(--lk);list-style:none}summary::-webkit-details-marker{display:none}details[open] summary{display:none}]=]
  .. [=[@media (max-width:719px){.at2 .code{margin:0 10px 0 auto;transform:none}}@media (prefers-reduced-motion:reduce){*,:before,:after{animation:none!important}}]=]

-- Rules only some pages need.
local STYLES = {
  at0 = [=[.at0 .top{--at:16.667%}.at0 .hd{animation:h0 .6s .1s both}@keyframes h0{0%{opacity:1}to{opacity:0;scale:2.4}}]=]
    .. [=[.at0 .m1 *{stroke:var(--bd)}.at0 .m1 g{transform-origin:0 0;animation:pp .5s .25s var(--e) both}.at0 .cur{animation-delay:.4s}.at0 .hops .x span{animation-delay:.3s}]=]
    .. [=[@media (max-width:719px){.at0 .code{margin:0 0 0 10px;transform:none}}]=],
  at2 = [=[.at2 .cur{animation-delay:1.5s}.at2 .hd{animation:h2 1.55s .1s both}.at2 .m3 g{animation-delay:1.35s}.at2 .hops .x span{animation-delay:1.4s}]=]
    .. [=[@keyframes h2{0%{opacity:1;left:16.667%;animation-timing-function:var(--e)}45%{left:50%;animation-timing-function:var(--e)}87%{opacity:1;left:83.333%}to{opacity:0;left:83.333%;scale:2.4}}]=],
  held = [=[.hl line{stroke:var(--mu);stroke-dasharray:1 5;stroke-linecap:round;vector-effect:non-scaling-stroke}]=],
  chirp = [=[.ch path{fill:none;stroke:var(--sg);stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke;animation:pr 1.4s ease-in-out infinite}@keyframes pr{50%{translate:4px}}]=],
  slow = [=[.sl .ln{transform:scale(2,.6);transform-origin:0 28px;animation-duration:4.8s;--p:-48px}]=],
  fade = [=[.fa{-webkit-mask:linear-gradient(90deg,#000 15%,transparent 70%);mask:linear-gradient(90deg,#000 15%,transparent 70%)}]=],
  noise = [=[.ou{-webkit-mask:linear-gradient(90deg,#000 30%,transparent 62%);mask:linear-gradient(90deg,#000 30%,transparent 62%)}]=]
    .. [=[.zz{-webkit-mask:linear-gradient(90deg,transparent 34%,#000 66%);mask:linear-gradient(90deg,transparent 34%,#000 66%)}]=],
  garble = [=[.gb{-webkit-mask:linear-gradient(90deg,#000 10%,transparent 58%);mask:linear-gradient(90deg,#000 10%,transparent 58%)}]=],
  jitter = [=[.zz path,.gb path{fill:none;stroke:var(--bd);stroke-width:1.25;stroke-linejoin:round;vector-effect:non-scaling-stroke;animation:jt .16s steps(2) infinite}@keyframes jt{50%{translate:0 1.5px}}]=],
  swell = [=[.sw{-webkit-mask:linear-gradient(90deg,#000 64%,transparent 0);mask:linear-gradient(90deg,#000 64%,transparent 0)}.sw .ln{transform:scale(1,2.6);transform-origin:0 28px}]=]
    .. [=[.hl .lm{stroke:var(--bd);stroke-width:1.5;stroke-dasharray:none}]=],
  decay = [=[.code{animation:dc 2.6s var(--e) both}@keyframes dc{0%{font-weight:100;opacity:0}28%{font-weight:620;opacity:1}}]=],
  void = [=[.bx.v{stroke:var(--mu);stroke-dasharray:2.5 2.5}]=],
  retry = [=[.btn{display:inline-flex;align-items:center;height:36px;margin-top:22px;padding:0 15px;border-radius:999px;background:var(--bt);color:var(--bf);font-size:14px;font-weight:560;text-decoration:none}.btn:hover{filter:brightness(1.1)}]=],
}

-- RULES are the STYLES each signal needs.
local RULES = {
  held = { "held" }, chirp = { "chirp" }, fade = { "fade" }, slow = { "slow", "fade", "decay" },
  noise = { "noise", "jitter" }, garble = { "held", "garble", "jitter" }, swell = { "held", "swell" },
}

-- The signal: Edgeweir's wave (24px period), long enough to fill a third of
-- the frame; for a rate limit, waves that shorten and rise as they pile up
-- against the edge node (drawn leftwards from it).
local WAVE = "M-24 30.5" .. string.rep("c6 0 6-5 12-5s6 5 12 5", 17)
local CHIRP = "M-332.7 28c7.5 0 7.5-2.5 15-2.5c6.8 0 6.8 5 13.5 5c6.1 0 6.1-5 12.2-5c5.5 0 5.5 5 10.9 5c4.9 0 4.9-5 9.8-5c4.4 0 4.4 5 8.9 5c4 0 4-5.1 8-5.1c3.6 0 3.6 5.1 7.2 5.1c3.2 0 3.2-5.1 6.5-5.1c2.9 0 2.9 5.2 5.8 5.2c2.6 0 2.6-5.2 5.2-5.2c2.4 0 2.4 5.2 4.7 5.2c2.1 0 2.1-5.3 4.2-5.3c1.9 0 1.9 5.3 3.8 5.3c1.8 0 1.8-5.4 3.5-5.4c1.8 0 1.8 5.4 3.5 5.4c1.8 0 1.8-5.5 3.5-5.5c1.8 0 1.8 5.6 3.5 5.6c1.8 0 1.8-5.7 3.5-5.7c1.8 0 1.8 5.7 3.5 5.7c1.8 0 1.8-5.8 3.5-5.8c1.8 0 1.8 5.9 3.5 5.9c1.8 0 1.8-6 3.5-6c1.8 0 1.8 6.1 3.5 6.1c1.8 0 1.8-6.2 3.5-6.2c1.8 0 1.8 6.3 3.5 6.3c1.8 0 1.8-6.4 3.5-6.4c1.8 0 1.8 6.5 3.5 6.5c1.8 0 1.8-6.6 3.5-6.6c1.8 0 1.8 6.7 3.5 6.7c1.8 0 1.8-6.9 3.5-6.9c1.8 0 1.8 7 3.5 7c1.8 0 1.8-7.1 3.5-7.1c1.8 0 1.8 7.3 3.5 7.3c1.8 0 1.8-7.4 3.5-7.4c1.8 0 1.8 7.5 3.5 7.5c1.8 0 1.8-7.7 3.5-7.7c1.8 0 1.8 7.8 3.5 7.8c1.8 0 1.8-8 3.5-8c1.8 0 1.8 8.2 3.5 8.2c1.8 0 1.8-8.3 3.5-8.3c1.8 0 1.8 8.5 3.5 8.5c1.8 0 1.8-8.7 3.5-8.7c1.8 0 1.8 8.9 3.5 8.9c1.8 0 1.8-9 3.5-9c1.8 0 1.8 9.2 3.5 9.2c1.8 0 1.8-9.4 3.5-9.4c1.8 0 1.8 9.6 3.5 9.6c1.8 0 1.8-9.8 3.5-9.8c1.8 0 1.8 10 3.5 10c1.8 0 1.8-10.2 3.5-10.2c1.8 0 1.8 10.4 3.5 10.4c1.8 0 1.8-10.7 3.5-10.7c1.8 0 1.8 10.9 3.5 10.9c1.8 0 1.8-11.1 3.5-11.1c1.8 0 1.8 11.3 3.5 11.3c1.8 0 1.8-11.6 3.5-11.6c1.8 0 1.8 11.8 3.5 11.8c1.8 0 1.8-12.1 3.5-12.1c1.8 0 1.8 12.3 3.5 12.3c1.8 0 1.8-12.6 3.5-12.6c1.8 0 1.8 12.8 3.5 12.8c1.8 0 1.8-13.1 3.5-13.1c1.8 0 1.8 13.3 3.5 13.3c1.8 0 1.8-13.6 3.5-13.6c1.8 0 1.8 13.9 3.5 13.9c1.8 0 1.8-14.2 3.5-14.2c1.8 0 1.8 14.4 3.5 14.4c1.8 0 1.8-14.7 3.5-14.7c1.8 0 1.8 15 3.5 15c1.8 0 1.8-15.3 3.5-15.3c1.8 0 1.8 15.6 3.5 15.6c1.8 0 1.8-15.9 3.5-15.9c1.8 0 1.8 16.2 3.5 16.2c1.8 0 1.8-16.5 3.5-16.5c1.8 0 1.8 16.8 3.5 16.8"
local NOISE = "M0 28L6 37 10 18 16 39 24 21 30 36 34 16 40 41 44 17 50 35 58 19 64 40 70 22 74 35 82 17 86 39"
  .. " 92 20 98 37 106 18 110 41 116 24 120 36 126 16 134 38 140 22 146 41 152 18 156 35 162 21 170 38 176 17"
  .. " 180 40 186 23 192 36 200 19 206 37 210 16 216 39 224 22 230 35"

local LINE = '<svg><use href="#w" class="ln"/></svg>'
local HELD = '<line x1="0" y1="28" x2="100%" y2="28"/>'

-- seg is the signal from one hop to the next (side a or b): held (nothing
-- gets through), noise (the wave breaks up), garble (it breaks up as it
-- leaves), swell (an oversized wave stopped at the limit), fade, chirp,
-- slow, or the wave flowing.
local function seg(kind, side)
  local c = '<span class="s s' .. side
  if kind == "held" then
    return c .. ' hl"><svg>' .. HELD .. "</svg></span>"
  elseif kind == "noise" then
    return c .. ' ou">' .. LINE .. "</span>" .. c .. ' zz"><svg><path d="' .. NOISE .. '"/></svg></span>'
  elseif kind == "garble" then
    return c .. ' hl"><svg>' .. HELD .. "</svg></span>" .. c .. ' gb"><svg><path d="' .. NOISE .. '"/></svg></span>'
  elseif kind == "swell" then
    return c .. ' hl"><svg>' .. HELD .. '<line class="lm" x1="66%" y1="13" x2="66%" y2="43"/></svg></span>'
      .. c .. ' sw">' .. LINE .. "</span>"
  elseif kind == "fade" then
    return c .. ' fa">' .. LINE .. "</span>"
  elseif kind == "chirp" then
    return c .. ' ch"><svg><svg x="100%" overflow="visible"><path d="' .. CHIRP .. '"/></svg></svg></span>'
  elseif kind == "slow" then
    return c .. ' sl fa">' .. LINE .. "</span>"
  end
  return c .. '">' .. LINE .. "</span>"
end

-- GLYPHS are drawn inside the failing hop's mark; logo is the edge node's
-- own mark (Edgeweir's crest over the wave). The visitor's: query (the
-- request could not be read), wide (too large), lock (not encrypted).
local GLYPHS = {
  logo = '<path class="g" d="M-4.5 0l4.5-4.5 4.5 4.5M-5.5 4c1.4 0 1.4-1.3 2.75-1.3s1.4 1.3 2.75 1.3 1.4-1.3 2.75-1.3 1.4 1.3 2.75 1.3"/>',
  stop = '<path class="g" d="M-4.6-4.6l9.2 9.2"/>',
  pause = '<path class="g" d="M-2.5-4v8M2.5-4v8"/>',
  cross = '<path class="g" d="M-2.6-2.6l5.2 5.2M2.6-2.6l-5.2 5.2"/>',
  clock = '<path class="g" d="M0-3.5V0l2.5 1.8"/>',
  hourglass = '<path class="g" d="M-3.5-4.5h7l-7 9h7z"/>',
  query = '<path class="g" d="M-2.4-2.2a2.4 2.4 0 1 1 3.3 2.2c-.6.3-.9.7-.9 1.3v.6M0 4.1v.1"/>',
  wide = '<path class="g" d="M-4.2 0h8.4M-1.9-2.3l-2.3 2.3 2.3 2.3M1.9-2.3l2.3 2.3-2.3 2.3"/>',
  lock = '<path class="g" d="M-2.8-.6h5.6v4.4h-5.6zM-1.7-.6v-1.6a1.7 1.7 0 0 1 3.4 0v1.6"/>',
}

-- marks are the three hops on the signal: the visitor, the edge node and the
-- origin, the failing one drawn in red with its glyph.
local function marks(s)
  local visitor = s.at == 0 and ('<g><circle class="bg" r="9.5"/>' .. GLYPHS[s.mark] .. "</g>")
    or '<circle class="rg" r="9.5"/><circle class="dt" r="3.5"/>'
  local edge = s.at == 1 and GLYPHS[s.mark] or GLYPHS.logo
  local origin = s.at == 2 and GLYPHS[s.mark] or ""
  return '<svg class="mk"><svg x="16.667%" y="28" overflow="visible" class="m1">' .. visitor .. "</svg>"
    .. '<svg x="50%" y="28" overflow="visible" class="m2"><g><circle class="bg" r="11"/>' .. edge .. "</g></svg>"
    .. '<svg x="83.333%" y="28" overflow="visible" class="m3"><g><rect class="bx' .. (s.void and " v" or "")
    .. '" x="-7" y="-7" width="14" height="14" rx="3"/>' .. origin .. "</g></svg></svg>"
end

local builtins = {}

-- builtin returns the compiled built-in page of lang ("zh" or "en") for
-- kind: a status, nginx's 494 / 497 (sent as 400), "site-disabled", or
-- "503-origin" (the 503 page of an origin failure).
function _M.builtin(lang, kind)
  lang = TITLES[lang] and lang or "en"
  local k = lang .. "|" .. tostring(kind)
  local parts = builtins[k]
  if parts then
    return parts
  end
  local key = kind == "503-origin" and 503 or kind
  local text = TEXT[lang]
  local s = SHAPES[kind] or SHAPES.other
  local title = TITLES[lang][key] or (lang == "zh" and "错误" or "Error")
  local stamp, todo = text.stamp[key] or text.stamp.other, text.todo[key] or text.todo.other
  local style, used = { STYLE, ".code{--w:", s.w, "}" }, {}
  local function add(names)
    for _, name in ipairs(names or {}) do
      if not used[name] then
        used[name] = true
        style[#style + 1] = STYLES[name]
      end
    end
  end
  if s.at ~= 1 then
    add({ "at" .. s.at })
  end
  add(RULES[s.a])
  add(RULES[s.b])
  if s.void then
    add({ "void" })
  end
  if s.retry then
    add({ "retry" })
  end
  local hops = {}
  for i = 0, 2 do
    local cls, state = "", text.ok
    if i == s.at then
      cls, state = ' class="x"', stamp
    elseif i > s.at then
      cls, state = ' class="n"', text.unreached
    end
    hops[#hops + 1] = "<li" .. cls .. "><b>" .. text.hops[i + 1] .. "</b><span>" .. state .. "</span></li>"
  end
  parts = _M.compile(concat({
    '<!doctype html><html lang="', LANG[lang], '"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">',
    "<title>{{status}} ", title, "</title><style>", concat(style), "</style></head>",
    '<body class="at', s.at, '"><main><div class="f"><i class="d d1"></i><i class="d d2"></i><i class="d d3"></i><i class="d d4"></i>',
    '<div class="top"><i class="d d5"></i><i class="d d6"></i><p class="code">{{status}}</p>',
    '<div class="tr" aria-hidden="true"><svg class="df"><path id="w" d="', WAVE, '"/></svg>',
    '<i class="cur"></i><i class="hd"></i>', seg(s.a, "a"), seg(s.b, "b"), marks(s), "</div>",
    '<ol class="hops">', concat(hops), "</ol></div>",
    '<div class="bot"><div><h1>', title, '</h1><p class="todo">', todo, "</p>",
    s.retry and ('<a class="btn" href="">' .. text.reload .. "</a>") or "",
    "</div><dl><div><dt>", REQUEST_ID[lang], '</dt><dd class="rid">{{request_id}}</dd></div>',
    "<div><dt>", text.time, "</dt><dd>{{display_time}}</dd></div>",
    "<div><dt>", text.host, "</dt><dd>{{host}}</dd></div>",
    "<div><dt>", text.ip, "</dt><dd><details><summary>", text.show, "</summary>{{client_ip}}</details></dd></div></dl></div>",
    "</div></main></body></html>\n",
  }), BUILTIN_NAMES)
  builtins[k] = parts
  return parts
end

-- language picks the language of built-in pages from Accept-Language.
local function language(header)
  return require("edgeweir.challenge").language(header)
end

-- host returns the {{host}} value of $host: without its port, and "" for
-- "_", the name of the node's catch-all servers, which nginx reports when
-- a request names no valid host (none, or one it refused).
function _M.host(host)
  if type(host) ~= "string" or host == "_" then
    return ""
  end
  if sub(host, 1, 1) == "[" then
    return match(host, "^(%[[^%]]*%])") or host
  end
  return match(host, "^([^:]*)") or host
end

-- edge_values are the placeholder values at the edge layer.
function _M.edge_values(status)
  local var = ngx.var
  local time, display_time = times()
  return {
    status = tostring(status),
    request_id = var.edgeweir_request_id or var.request_id,
    client_ip = var.remote_addr,
    host = _M.host(var.host),
    time = time,
    display_time = display_time,
    path = var.uri,
  }
end

-- origin_values are the placeholder values in the origin layer.
function _M.origin_values(status)
  local var = ngx.var
  local time, display_time = times()
  return {
    status = tostring(status),
    request_id = var.http_x_request_id,
    client_ip = var.http_x_real_ip,
    host = _M.host(var.host),
    time = time,
    display_time = display_time,
    path = var.uri,
  }
end

-- template returns the page for status of site: its own page (of the
-- status or its class), else the built-in one of kind (default: the
-- status; for a 503 of the origin, code origin-unreachable, the one marking
-- the origin) as { parts }.
local function template(site, status, code, kind)
  local page = _M.page_for(site, status)
  if page then
    return page
  end
  kind = kind or ((status == 503 and code == "origin-unreachable") and "503-origin" or status)
  return { parts = _M.builtin(language(ngx.var.http_accept_language), kind) }
end

-- send answers the request with a page (access or content phase): a
-- redirect page with 302 to its URL, else the rendered template with the
-- page's status or status.
local function send(status, code, page, values)
  local h = ngx.header
  h["Cache-Control"] = "no-store"
  h["X-Edgeweir-Error"] = code
  if page.redirect then
    ngx.status = 302
    h["Location"] = _M.render_url(page.redirect, values)
    h["Content-Length"] = 0
    return ngx.exit(ngx.HTTP_OK)
  end
  local body = _M.render(page.parts, values)
  ngx.status = page.status or status
  h["Content-Type"] = "text/html; charset=utf-8"
  h["Content-Length"] = #body
  if ngx.req.get_method() ~= "HEAD" then
    ngx.print(body)
  end
  return ngx.exit(ngx.HTTP_OK)
end

-- respond answers an edge-layer request with the page of status (one of
-- STATUSES) for site (nil: built-in page) and X-Edgeweir-Error code.
function _M.respond(status, code, site)
  return send(status, code, template(site, status, code), _M.edge_values(status))
end

-- maintenance answers an edge-layer request of a site in maintenance
-- (Site.maintenance): 503 with the site's maintenance page or the built-in
-- one, Retry-After when set.
function _M.maintenance(site)
  local retry = tonumber(site.maintenance.retry_after)
  if retry and retry > 0 then
    ngx.header["Retry-After"] = tostring(retry)
  end
  local parts = site._maintenance_page or _M.builtin(language(ngx.var.http_accept_language), "maintenance")
  return send(503, "maintenance", { parts = parts }, _M.edge_values(503))
end

-- NGINX are nginx's own errors error_page hands to the error pages: the
-- status sent, the page and the X-Edgeweir-Error code. 494 (request header
-- too large) and 497 (plain HTTP on an HTTPS port) are nginx's names for
-- two kinds of 400; 502 and 504 come from the edge layer only, when the
-- origin layer failed or dropped the connection and no stale copy could be
-- served instead.
local NGINX = {
  [400] = { 400, 400, "bad-request" },
  [413] = { 413, 413, "body-too-large" },
  [414] = { 414, 414, "uri-too-long" },
  [494] = { 400, 494, "header-too-large" },
  [497] = { 400, 497, "https-required" },
  [500] = { 500, 500, "internal-error" },
  [502] = { 502, 502, "origin-unreachable" },
  [504] = { 504, 504, "origin-timeout" },
}

-- nginx_error returns the status to send, the page kind and the
-- X-Edgeweir-Error code for nginx's own error status; waf: the CRS blocked
-- the request (its 400s are waf-blocked). Other statuses answer as 500.
function _M.nginx_error(status, waf)
  if waf and status == 400 then
    return 400, 400, "waf-blocked"
  end
  local e = NGINX[status] or NGINX[500]
  return e[1], e[2], e[3]
end

-- nginx_page answers nginx's own error status (content phase of the error
-- locations) with the page for site (nil: built-in page); waf: the CRS
-- blocked the request; origin: the origin layer (values from the forwarded
-- request headers, X-Accel-Expires: 0), else the edge layer (with
-- X-Request-Id, which the error locations do not add).
function _M.nginx_page(status, site, waf, origin)
  local out, kind, code = _M.nginx_error(status, waf)
  local page = template(site, out, code, kind)
  if origin then
    ngx.header["X-Accel-Expires"] = 0
    return send(out, code, page, _M.origin_values(out))
  end
  local values = _M.edge_values(out)
  ngx.header["X-Request-Id"] = values.request_id
  return send(out, code, page, values)
end

-- offline_reason returns the reason (disabled) of a host no site serves
-- when it is a domain of an offline site (exact, a wildcard on its parent
-- domain, a suffix of any depth or a pattern, like site domains), or nil.
-- cfg is the site table's settings (edgeweir.store.config).
function _M.offline_reason(cfg, host)
  local offline = cfg and cfg.offline
  if not offline or type(host) ~= "string" then
    return nil
  end
  local reason = offline.exact[host]
  local dot = find(host, ".", 1, true)
  if not reason and dot then
    reason = offline.wild[sub(host, dot + 1)]
  end
  while not reason and dot and offline.suffix do
    reason = offline.suffix[sub(host, dot + 1)]
    dot = find(host, ".", dot + 1, true)
  end
  if not reason and offline.patterns then
    for _, p in ipairs(offline.patterns) do
      if ngx.re.find(host, p.source, "jo") then
        return p.reason
      end
    end
  end
  return reason
end

-- unknown_host answers a host no site serves: the platform's page of an
-- offline host (503), else the unknown host page (404).
function _M.unknown_host(cfg, host)
  local reason = _M.offline_reason(cfg, host)
  local pages = cfg and cfg.platform_pages or {}
  local lang = language(ngx.var.http_accept_language)
  if reason == "disabled" then
    return send(503, "site-disabled", { parts = pages.site_disabled or _M.builtin(lang, "site-disabled") }, _M.edge_values(503))
  end
  return send(404, "unknown-host", { parts = pages.unknown_host or _M.builtin(lang, 404) }, _M.edge_values(404))
end

-- origin_fail answers an origin-layer failure (access phase) with the page
-- of status; the edge never caches it.
function _M.origin_fail(status, code, site)
  ngx.header["X-Accel-Expires"] = 0
  return send(status, code, template(site, status, code), _M.origin_values(status))
end

-- replace turns the response being sent into the page of status (header
-- filter); body_filter then sends the page instead of the response body.
-- origin: the origin layer (values from the forwarded request headers, and
-- X-Accel-Expires: 0).
function _M.replace(status, code, site, origin)
  local values = origin and _M.origin_values(status) or _M.edge_values(status)
  local page = template(site, status, code)
  local h = ngx.header
  local body
  if page.redirect then
    body = ""
    ngx.status = 302
    h["Location"] = _M.render_url(page.redirect, values)
    h["Content-Type"] = nil
  else
    body = _M.render(page.parts, values)
    if page.status then
      ngx.status = page.status
    end
    h["Content-Type"] = "text/html; charset=utf-8"
  end
  h["Cache-Control"] = "no-store"
  h["Content-Length"] = #body
  h["X-Edgeweir-Error"] = code
  h["Content-Encoding"] = nil
  h["ETag"] = nil
  h["Last-Modified"] = nil
  h["Expires"] = nil
  if origin then
    h["X-Accel-Expires"] = 0
  end
  ngx.ctx.edgeweir_page = body
end

-- body_filter sends the page that replace() prepared instead of the
-- response body (the body filter of the origin layer and of the CRS
-- locations; nothing happens for other responses).
function _M.body_filter()
  local ctx = ngx.ctx
  local body = ctx.edgeweir_page
  if not body then
    return
  end
  if body == true then
    ngx.arg[1] = nil
    return
  end
  ctx.edgeweir_page = true
  ngx.arg[1] = body
  ngx.arg[2] = true
end

-- generated reports whether the response of the origin layer is nginx's
-- own: its last upstream attempt received no response header.
function _M.generated(upstream_header_time)
  if not upstream_header_time or upstream_header_time == "" then
    return true
  end
  local last = match(upstream_header_time, "([^,:%s]+)%s*$")
  return last == nil or last == "-"
end

-- origin_code returns the X-Edgeweir-Error code of an origin-layer
-- failure nginx generated.
function _M.origin_code(status)
  if status == 504 then
    return "origin-timeout"
  end
  return "origin-unreachable"
end

return _M
