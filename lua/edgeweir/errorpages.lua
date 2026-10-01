-- edgeweir.errorpages: error pages of node-generated responses.
--
-- Pages replace the plain-text answers of status 403 (bans, rule and list
-- denials, CRS blocks, missing challenge passes), 429 (rate limits), 502,
-- 503 and 504 (edge 503s, origin-layer failures including nginx's own
-- upstream failures) and, with the site's intercept_origin_errors, origin
-- responses whose status has a template of the site. The template is the
-- site's page for the status (Site.error_pages), else the built-in page.
-- Hosts no site serves get the platform's unknown_host page (404), the
-- offline hosts of disabled and suspended sites the platform's
-- site_disabled / site_suspended page (503). Other statuses (404, 405,
-- 421, 508, ...) keep their plain text.
--
-- Templates are compiled once (per site table version) into literal parts
-- and placeholders: {{status}}, {{request_id}}, {{client_ip}} and {{host}}
-- are replaced with HTML-escaped values; anything else, including other
-- {{...}}, is sent as it is. Template content is never interpreted.
--
-- Built-in pages are self-contained (inline CSS, no external URL, light and
-- dark), in Chinese or English by Accept-Language, and show the status, a
-- short title and the request id.
--
-- Every page: Content-Type text/html; charset=utf-8, Cache-Control:
-- no-store, the exact Content-Length and X-Edgeweir-Error: <code>. The edge
-- layer renders its access-phase denials directly (respond). The origin
-- layer renders its own failures directly and replaces nginx's upstream
-- failures (no response header from the last attempt) and intercepted
-- origin errors in its header filter (replace) and body filter
-- (body_filter); its pages also carry X-Accel-Expires: 0 so the edge never
-- caches them. The edge layer's CRS locations replace CRS blocks the same
-- way. Values: the request id is $edgeweir_request_id at the edge and the
-- X-Request-Id request header in the origin layer, the client address
-- $remote_addr at the edge and X-Real-IP in the origin layer, the host the
-- request's host without port.
local _M = {}

local concat, find, match, sub, gsub = table.concat, string.find, string.match, string.sub, string.gsub
local ipairs, pairs, tonumber, tostring, type = ipairs, pairs, tonumber, tostring, type

-- STATUSES are the statuses pages apply to (besides the platform's 404).
_M.STATUSES = { [403] = true, [429] = true, [502] = true, [503] = true, [504] = true }

_M.MAX_TEMPLATE = 65536

local NAMES = { status = true, request_id = true, client_ip = true, host = true }

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }

function _M.escape(s)
  return (gsub(tostring(s or ""), "[&<>\"']", ESCAPES))
end

-- compile splits a template into literal strings and placeholders
-- ({ name } tables).
function _M.compile(template)
  local parts, n = {}, 0
  local pos, literal = 1, 1
  while true do
    local s = find(template, "{{", pos, true)
    if not s then
      break
    end
    local name, after = match(template, "^([%l_]+)}}()", s + 2)
    if name and NAMES[name] then
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

-- compile_pages compiles a site's pages ({"<status>": template}) into
-- {[status] = parts}; nil without a valid page.
function _M.compile_pages(pages)
  if type(pages) ~= "table" then
    return nil
  end
  local out, any = {}, false
  for status, template in pairs(pages) do
    local code = tonumber(status)
    if code and _M.STATUSES[code] and type(template) == "string" and template ~= "" and #template <= _M.MAX_TEMPLATE then
      out[code] = _M.compile(template)
      any = true
    end
  end
  return any and out or nil
end

-- compile_platform compiles the platform's pages ({unknown_host,
-- site_disabled, site_suspended}); empty or missing ones stay nil.
function _M.compile_platform(pages)
  local out = {}
  if type(pages) ~= "table" then
    return out
  end
  for _, name in ipairs({ "unknown_host", "site_disabled", "site_suspended" }) do
    local template = pages[name]
    if type(template) == "string" and template ~= "" and #template <= _M.MAX_TEMPLATE then
      out[name] = _M.compile(template)
    end
  end
  return out
end

-- ---------------------------------------------------------------------
-- Built-in pages

local TITLES = {
  zh = {
    [403] = "访问被拒绝", [404] = "站点不存在", [429] = "请求过于频繁", [502] = "无法连接源站",
    [503] = "服务暂不可用", [504] = "源站响应超时", ["site-disabled"] = "站点已停用",
    ["site-suspended"] = "站点已暂停",
  },
  en = {
    [403] = "Access denied", [404] = "Site not found", [429] = "Too many requests", [502] = "Origin unreachable",
    [503] = "Service unavailable", [504] = "Origin timed out", ["site-disabled"] = "Site disabled",
    ["site-suspended"] = "Site suspended",
  },
}
local LANG = { zh = "zh-CN", en = "en" }
local REQUEST_ID = { zh = "请求 ID", en = "Request ID" }

local STYLE = ":root{color-scheme:light dark;--bg:#f5f6f8;--fg:#16181c;--mute:#5d636d;--card:#fff;--line:#e2e5e9}"
  .. "@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--fg:#e7e9ec;--mute:#9aa1ab;--card:#161a20;--line:#2a2f37}}"
  .. "*{box-sizing:border-box}html,body{margin:0}"
  .. 'body{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}'
  .. "main{width:100%;max-width:420px;padding:28px;background:var(--card);border:1px solid var(--line);border-radius:14px}"
  .. ".code{margin:0;color:var(--mute);font-size:13px;font-variant-numeric:tabular-nums}"
  .. "h1{margin:4px 0 0;font-size:20px;font-weight:600}"
  .. ".id{margin:20px 0 0;color:var(--mute);font-size:12px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}"

local builtins = {}

-- builtin returns the compiled built-in page of lang ("zh" or "en") for
-- kind: a status, or "site-disabled" / "site-suspended".
function _M.builtin(lang, kind)
  lang = TITLES[lang] and lang or "en"
  local k = lang .. "|" .. tostring(kind)
  local parts = builtins[k]
  if parts then
    return parts
  end
  local title = TITLES[lang][kind] or (lang == "zh" and "错误" or "Error")
  parts = _M.compile(concat({
    '<!doctype html><html lang="', LANG[lang], '"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">',
    "<title>{{status}} ", title, "</title><style>", STYLE, "</style></head><body><main>",
    '<p class="code">{{status}}</p><h1>', title, "</h1>",
    '<p class="id">', REQUEST_ID[lang], " {{request_id}}</p></main></body></html>\n",
  }))
  builtins[k] = parts
  return parts
end

-- language picks the language of built-in pages from Accept-Language.
local function language(header)
  return require("edgeweir.challenge").language(header)
end

-- host_of strips the port of a Host value.
local function host_of(host)
  if type(host) ~= "string" then
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
  return {
    status = tostring(status),
    request_id = var.edgeweir_request_id or var.request_id,
    client_ip = var.remote_addr,
    host = host_of(var.host),
  }
end

-- origin_values are the placeholder values in the origin layer.
function _M.origin_values(status)
  local var = ngx.var
  return {
    status = tostring(status),
    request_id = var.http_x_request_id,
    client_ip = var.http_x_real_ip,
    host = host_of(var.host),
  }
end

-- template returns the compiled template for status of site: its own
-- page, else the built-in one.
local function template(site, status)
  local pages = site and site._error_pages
  local t = pages and pages[status]
  if t then
    return t
  end
  return _M.builtin(language(ngx.var.http_accept_language), status)
end

-- send answers the request with a rendered page (access or content
-- phase).
local function send(status, code, parts, values)
  local body = _M.render(parts, values)
  ngx.status = status
  local h = ngx.header
  h["Content-Type"] = "text/html; charset=utf-8"
  h["Cache-Control"] = "no-store"
  h["Content-Length"] = #body
  h["X-Edgeweir-Error"] = code
  if ngx.req.get_method() ~= "HEAD" then
    ngx.print(body)
  end
  return ngx.exit(ngx.HTTP_OK)
end

-- respond answers an edge-layer request with the page of status (one of
-- STATUSES) for site (nil: built-in page) and X-Edgeweir-Error code.
function _M.respond(status, code, site)
  return send(status, code, template(site, status), _M.edge_values(status))
end

-- offline_reason returns the reason (disabled or suspended) of a host no
-- site serves when it is a domain of an offline site (exact, or a wildcard
-- on its parent domain like site domains), or nil. cfg is the site table's
-- settings (edgeweir.store.config).
function _M.offline_reason(cfg, host)
  local offline = cfg and cfg.offline
  if not offline or type(host) ~= "string" then
    return nil
  end
  local reason = offline.exact[host]
  if not reason then
    local dot = find(host, ".", 1, true)
    reason = dot and offline.wild[sub(host, dot + 1)] or nil
  end
  return reason
end

-- unknown_host answers a host no site serves: the platform's page of an
-- offline host (503), else the unknown host page (404).
function _M.unknown_host(cfg, host)
  local reason = _M.offline_reason(cfg, host)
  local pages = cfg and cfg.platform_pages or {}
  local lang = language(ngx.var.http_accept_language)
  if reason == "suspended" then
    return send(503, "site-suspended", pages.site_suspended or _M.builtin(lang, "site-suspended"), _M.edge_values(503))
  elseif reason == "disabled" then
    return send(503, "site-disabled", pages.site_disabled or _M.builtin(lang, "site-disabled"), _M.edge_values(503))
  end
  return send(404, "unknown-host", pages.unknown_host or _M.builtin(lang, 404), _M.edge_values(404))
end

-- origin_fail answers an origin-layer failure (access phase) with the page
-- of status; the edge never caches it.
function _M.origin_fail(status, code, site)
  ngx.header["X-Accel-Expires"] = 0
  return send(status, code, template(site, status), _M.origin_values(status))
end

-- replace turns the response being sent into the page of status (header
-- filter); body_filter then sends the page instead of the response body.
-- origin: the origin layer (values from the forwarded request headers, and
-- X-Accel-Expires: 0).
function _M.replace(status, code, site, origin)
  local values = origin and _M.origin_values(status) or _M.edge_values(status)
  local body = _M.render(template(site, status), values)
  local h = ngx.header
  h["Content-Type"] = "text/html; charset=utf-8"
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
