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
-- external URL, no web font, light and dark), in Chinese or English by
-- Accept-Language, and show the status, which hop failed (the visitor for
-- requests nginx refuses, the edge node or the origin), a short title,
-- what to do, the request id, the host, the client address and the time.
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
-- (a site's body limit) since proto v0.24.0, 401 (access authentication,
-- respond_auth) since proto v0.27.0.
_M.STATUSES = { [400] = true, [401] = true, [403] = true, [405] = true, [413] = true, [414] = true,
  [429] = true, [500] = true, [502] = true, [503] = true, [504] = true }

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
-- A built-in page is a card on a gray canvas under Edgeweir's tile, like
-- the console's status pages: the status with a pill naming what failed,
-- the title, what to do, then the hop trace of the request from the
-- visitor through the edge node to the origin. The hops before the one
-- that failed are healthy, the failing one is red (a rate limit holds the
-- request there in orange) and the ones after it were not reached. A
-- request nginx refuses (malformed, too large, plain HTTP on an HTTPS
-- port) fails at the visitor. Under the trace come the request id, the
-- host, the client address (shown on request) and the time, and a retry
-- button where retrying can help. The card fades in once and the failing
-- hop's badge after it; nothing loops, nothing moves under
-- prefers-reduced-motion, and the page has no script, no external URL and
-- no web font. The challenge pages (edgeweir.challenge) use the same
-- style, tile and trace.
--
-- Kinds are statuses, nginx's own 494 (request header too large) and 497
-- (plain HTTP on an HTTPS port), both sent as 400, "site-disabled" and
-- "503-origin" (see builtin).

local TITLES = {
  zh = {
    [400] = "请求无效", [403] = "访问被拒绝", [404] = "站点不存在", [413] = "请求内容过大", [414] = "网址过长",
    [429] = "请求过于频繁", [494] = "请求头过大", [497] = "需要使用 HTTPS", [500] = "边缘节点出错",
    [502] = "无法连接源站", [503] = "服务暂不可用", [504] = "源站响应超时", ["site-disabled"] = "站点已停用",
    [405] = "不支持的请求方法", maintenance = "维护中", [401] = "需要认证",
  },
  en = {
    [400] = "Bad request", [403] = "Access denied", [404] = "Site not found", [413] = "Request too large",
    [414] = "URL too long", [429] = "Too many requests", [494] = "Request header too large", [497] = "HTTPS required",
    [500] = "Edge error", [502] = "Origin unreachable", [503] = "Service unavailable", [504] = "Origin timed out",
    ["site-disabled"] = "Site disabled", [405] = "Method not allowed", maintenance = "Under maintenance",
    [401] = "Authentication required",
  },
}
local LANG = { zh = "zh-CN", en = "en" }
local REQUEST_ID = { zh = "请求 ID", en = "Request ID" }

-- TEXT: the hops, their states and the page's other words; stamp is the
-- failing hop's state (also the status pill), todo what the visitor can do.
local TEXT = {
  zh = {
    hops = { "访客", "边缘节点", "源站" }, ok = "正常", unreached = "未到达",
    host = "主机", ip = "客户端 IP", show = "显示", reload = "重试", time = "时间",
    stamp = {
      [400] = "格式错误", [403] = "拦截", [404] = "未接入", [413] = "过大", [414] = "过长", [429] = "限速",
      [494] = "过大", [497] = "未加密", [500] = "出错", [502] = "无法连接", [503] = "暂不可用", [504] = "超时",
      ["site-disabled"] = "已停用", other = "出错", [405] = "不支持", maintenance = "维护中", [401] = "未认证",
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
      [401] = "这个网址需要登录，请输入用户名和密码后重试。",
      other = "请稍后重试。",
    },
  },
  en = {
    hops = { "Visitor", "Edge", "Origin" }, ok = "Working", unreached = "Not reached",
    host = "Host", ip = "Client IP", show = "Show", reload = "Retry", time = "Time",
    stamp = {
      [400] = "Malformed", [403] = "Blocked", [404] = "No site", [413] = "Too large", [414] = "Too long",
      [429] = "Rate limited", [494] = "Too large", [497] = "Not encrypted", [500] = "Error", [502] = "Unreachable",
      [503] = "Unavailable", [504] = "Timed out", ["site-disabled"] = "Disabled", other = "Error",
      [405] = "Not allowed", maintenance = "Maintenance", [401] = "Not signed in",
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
      [401] = "This address needs a sign-in. Enter your user name and password, then try again.",
      other = "Try again shortly.",
    },
  },
}

-- FAILS: the failing hop of each kind (0 the visitor, 1 the edge node, 2
-- the origin), whether retrying can help and whether the request is held
-- there (a rate limit: orange, not red). 503-origin is a 503 of the origin
-- (nginx's own upstream failure).
local FAILS = {
  [400] = { 0 }, [401] = { 0 }, [403] = { 1 }, [404] = { 1 }, [405] = { 1 }, [413] = { 0 }, [414] = { 0 },
  [429] = { 1, retry = true, held = true }, [494] = { 0 }, [497] = { 0 }, [500] = { 1, retry = true },
  [502] = { 2, retry = true }, [503] = { 1, retry = true }, ["503-origin"] = { 2, retry = true },
  [504] = { 2, retry = true }, ["site-disabled"] = { 1 }, maintenance = { 1, retry = true },
  other = { 1, retry = true },
}

-- STYLE: the console's tokens (light and dark), the canvas, the tile, the
-- card, the status line, the hop trace and the details well; shared with
-- the challenge pages. A held page (body class w) turns the failing hop's
-- red (--x, --xi, --xl) orange. The light --warn-ink is a step darker
-- than the console's #be5a00 so the pill's words reach 4.5:1 on its tint.
_M.STYLE = [=[:root{color-scheme:light dark;--bg:#f3f4f7;--panel:#fff;--faint:#f7f8fa;--line:#e7e8eb;--fg:rgb(0 0 0/90%);--mu:rgb(0 0 0/60%);--brand:#0052d9;--ink:#0052d9;--ok:#2ba471;--warn:#e37318;--warn-ink:#ad5200;--err:#d54941;--err-ink:#c4342c;--shadow:0 6px 30px rgb(0 0 0/5%),0 2px 8px rgb(0 0 0/4%);--bo:transparent;]=]
  .. [=[--sa:Inter,"PingFang SC","HarmonyOS Sans SC","Microsoft YaHei","Noto Sans SC",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mo:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}]=]
  .. [=[@media (prefers-color-scheme:dark){:root{--bg:#181818;--panel:#242424;--faint:#2c2c2c;--line:#383838;--fg:rgb(255 255 255/90%);--mu:rgb(255 255 255/60%);--brand:#3a6fd8;--ink:#699ef5;--ok:#56c08d;--warn:#f08a3c;--warn-ink:#f5a15b;--err:#f36d64;--err-ink:#f7857d;--shadow:none;--bo:var(--line)}}]=]
  .. [=[*{box-sizing:border-box}html,body,p{margin:0}body{background:var(--bg);color:var(--fg);font:14px/22px var(--sa);-webkit-font-smoothing:antialiased}:focus-visible{outline:2px solid var(--ink);outline-offset:2px}]=]
  .. [=[main{min-height:100vh;min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}]=]
  .. [=[.br{display:flex;align-items:center;gap:8px;margin-bottom:24px;font-size:16px;line-height:24px;font-weight:500}.br svg{width:28px;height:28px}.br rect{fill:var(--brand)}.br path{fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}]=]
  .. [=[.cd{--x:var(--err);--xi:var(--err-ink);--xl:var(--line);width:100%;max-width:560px;padding:40px;border:1px solid var(--bo);border-radius:12px;background:var(--panel);box-shadow:var(--shadow);animation:in .2s cubic-bezier(.2,0,0,1) both}.w .cd{--x:var(--warn);--xi:var(--warn-ink);--xl:var(--warn)}]=]
  .. [=[.st{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}.code{font-size:40px;line-height:48px;font-weight:500;font-variant-numeric:tabular-nums}]=]
  .. [=[.pl{padding:2px 8px;border-radius:4px;font-size:12px;line-height:20px;color:var(--xi);background:color-mix(in srgb,var(--x) 8%,transparent)}]=]
  .. [=[h1{margin:16px 0 0;font-size:20px;line-height:28px;font-weight:500}.todo,.hint{margin-top:8px;color:var(--mu);max-width:34em}]=]
  .. [=[.hops{list-style:none;margin:28px 0 0;padding:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));text-align:center}.hops li{position:relative;display:flex;flex-direction:column;align-items:center;padding:0 4px}]=]
  .. [=[.hops li+li:before{content:"";position:absolute;top:15px;left:calc(22px - 50%);right:calc(50% + 22px);border-top:2px solid var(--brand)}.hops .x:before{border-top-style:dashed;border-color:var(--xl)}.hops .n:before{border-top-style:dashed;border-color:var(--line)}]=]
  .. [=[.hops i{position:relative;display:grid;place-items:center;width:32px;height:32px;margin-bottom:8px;border-radius:50%;color:var(--brand);background:color-mix(in srgb,var(--brand) 12%,transparent)}]=]
  .. [=[.hops .x i{color:var(--x);background:color-mix(in srgb,var(--x) 12%,transparent)}.hops .n i{color:var(--mu);background:var(--faint)}]=]
  .. [=[.hops svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}]=]
  .. [=[.hops .bd{position:absolute;right:-3px;bottom:-3px;width:12px;height:12px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 2px var(--panel);stroke:#fff}.hops .x .bd{background:var(--x);animation:fd .15s .2s both}]=]
  .. [=[.hops b{font-size:13px;line-height:20px;font-weight:400}.hops span{font-size:12px;line-height:18px;color:var(--mu)}.hops .x span{color:var(--xi);font-weight:500}]=]
  .. [=[dl{display:grid;gap:8px;margin:28px 0 0;padding:16px;border-radius:8px;background:var(--faint)}dl div{display:grid;grid-template-columns:88px minmax(0,1fr);gap:8px}]=]
  .. [=[dt{font-size:12px;line-height:20px;color:var(--mu)}dd{margin:0;font:13px/20px var(--mo);overflow-wrap:anywhere}.rid{user-select:all}]=]
  .. [=[summary{cursor:pointer;width:max-content;font:13px/20px var(--sa);color:var(--ink);list-style:none}summary::-webkit-details-marker{display:none}dd details[open] summary{display:none}]=]
  .. [=[.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}@keyframes in{from{opacity:0;transform:translateY(4px)}}@keyframes fd{from{opacity:0}}]=]
  .. [=[@media (max-width:479px){main{padding:16px}.cd{padding:24px}.st{flex-direction:column;align-items:flex-start}}@media (prefers-reduced-motion:reduce){*{animation:none!important}}]=]

-- BUTTON: the primary button (retry, the captcha's verify).
_M.BUTTON = [=[.btn{display:inline-flex;align-items:center;height:32px;padding:0 16px;border:0;border-radius:6px;background:var(--brand);color:#fff;font:14px/22px var(--sa);text-decoration:none;cursor:pointer}.btn:hover{filter:brightness(1.1)}]=]

-- BRAND: Edgeweir's tile (the weir crest over two waves, white on the
-- brand fill) and name above the card.
_M.BRAND = '<div class="br"><svg viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="6"/>'
  .. '<path transform="translate(5 5) scale(.75)" d="M3 17c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 3 2M3 21c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 3 2M4 12l8-8 8 8"/></svg>Edgeweir</div>'

-- ICONS: the visitor, the edge node and the origin (Hugeicons' user,
-- server stack and database); BADGES: a healthy hop's check, a failing
-- hop's cross and a held hop's exclamation mark.
local ICONS = {
  '<path d="M20 21c-.3-3.7-3.3-6.7-7-6.9L12 14c-.4 0-.7 0-1 .04C7.3 14.2 4.3 17.3 4 21"/><circle cx="12" cy="7" r="4"/>',
  '<rect x="2" y="4" width="20" height="6" rx="3"/><rect x="2" y="14" width="20" height="6" rx="3"/><path d="M6 7h.01M10 7h.01M6 17h.01M10 17h.01"/>',
  '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M20 12c0 1.7-3.6 3-8 3s-8-1.3-8-3M20 5v14c0 1.7-3.6 3-8 3s-8-1.3-8-3V5M7 10.8c.6.2 1.3.3 2 .4M7 17.8c.6.2 1.3.3 2 .4"/>',
}
local BADGES = { ok = "M3.5 6.2l1.7 1.7 3.3-3.6", x = "M4.2 4.2l3.6 3.6m0-3.6L4.2 7.8", held = "M6 3.2v3.3M6 8.6v.1" }

-- hops returns the hop trace in lang: hops[i] = { class ("" healthy, "x"
-- failing or held, "n" not reached), state words, badge (BADGES; nil for
-- none) } for the visitor, the edge node and the origin.
function _M.hops(lang, hops)
  local names = (TEXT[lang] or TEXT.en).hops
  local out = { '<ol class="hops">' }
  for i = 1, 3 do
    local h = hops[i]
    out[i + 1] = (h[1] == "" and "<li>" or ('<li class="' .. h[1] .. '">')) .. '<i aria-hidden="true"><svg viewBox="0 0 24 24">'
      .. ICONS[i] .. "</svg>" .. (h[3] and ('<svg class="bd" viewBox="0 0 12 12"><path d="' .. BADGES[h[3]] .. '"/></svg>') or "")
      .. "</i><b>" .. names[i] .. "</b><span>" .. h[2] .. "</span></li>"
  end
  out[5] = "</ol>"
  return concat(out)
end

-- pending is the state of a hop the request has not reached: a dash, and
-- the words for screen readers.
function _M.pending(words)
  return '—<em class="sr">' .. words .. "</em>"
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
  local f = FAILS[kind] or FAILS.other
  local title = TITLES[lang][key] or (lang == "zh" and "错误" or "Error")
  local stamp, todo = text.stamp[key] or text.stamp.other, text.todo[key] or text.todo.other
  local hops = {}
  for i = 0, 2 do
    if i < f[1] then
      hops[i + 1] = { "", text.ok, "ok" }
    elseif i == f[1] then
      hops[i + 1] = { "x", stamp, f.held and "held" or "x" }
    else
      hops[i + 1] = { "n", _M.pending(text.unreached) }
    end
  end
  parts = _M.compile(concat({
    '<!doctype html><html lang="', LANG[lang], '"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">',
    "<title>{{status}} ", title, "</title><style>", _M.STYLE, f.retry and (_M.BUTTON .. ".ac{margin-top:24px}") or "",
    "</style></head><body", f.held and ' class="w"' or "", "><main>", _M.BRAND,
    '<div class="cd"><div class="st"><p class="code">{{status}}</p><span class="pl">', stamp, "</span></div>",
    "<h1>", title, '</h1><p class="todo">', todo, "</p>", _M.hops(lang, hops),
    "<dl><div><dt>", REQUEST_ID[lang], '</dt><dd class="rid">{{request_id}}</dd></div>',
    "<div><dt>", text.host, "</dt><dd>{{host}}</dd></div>",
    "<div><dt>", text.ip, "</dt><dd><details><summary>", text.show, "</summary>{{client_ip}}</details></dd></div>",
    "<div><dt>", text.time, "</dt><dd>{{display_time}}</dd></div></dl>",
    f.retry and ('<p class="ac"><a class="btn" href="">' .. text.reload .. "</a></p>") or "",
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

-- respond_auth answers a request access authentication (Basic) refused:
-- 401 with WWW-Authenticate and the site's 401 page (or its 4xx page),
-- else the built-in one. Redirect pages and replacement statuses do not
-- apply: a redirect would drop the challenge, and browsers ask for
-- credentials only on a 401.
function _M.respond_auth(site, realm)
  local page = _M.page_for(site, 401)
  if page and page.redirect then
    local pages = site._error_pages
    page = pages[4] and not pages[4].redirect and pages[4] or nil
  end
  if page then
    page = { parts = page.parts }
  else
    page = { parts = _M.builtin(language(ngx.var.http_accept_language), 401) }
  end
  ngx.header["WWW-Authenticate"] = 'Basic realm="' .. realm .. '", charset="UTF-8"'
  return send(401, "auth-required", page, _M.edge_values(401))
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
-- ip_host tells whether a host names no host: "_" (no Host), an IPv4
-- address or an IPv6 address in brackets (node IP access). Such hosts are
-- looked up by exact name only (edgeweir.store, nginx's server names).
function _M.ip_host(host)
  return host == "_" or find(host, "^%[") ~= nil or find(host, "^%d+%.%d+%.%d+%.%d+$") ~= nil
end

function _M.offline_reason(cfg, host)
  local offline = cfg and cfg.offline
  if not offline or type(host) ~= "string" then
    return nil
  end
  local reason = offline.exact[host]
  if reason or _M.ip_host(host) then
    return reason
  end
  local dot = find(host, ".", 1, true)
  if dot == 1 then
    dot = nil
  end
  if not reason and dot then
    reason = offline.wild[sub(host, dot + 1)]
  end
  while not reason and dot and offline.suffix do
    reason = offline.suffix[sub(host, dot + 1)]
    dot = find(host, ".", dot + 1, true)
  end
  if not reason and offline.patterns and #host <= 253 then
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
