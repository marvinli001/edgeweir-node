local expressions = require("edgeweir.expressions")
local ratelimit = require("edgeweir.ratelimit")
local _M = {}
_M.phases = { "request-transform", "redirect", "config", "waf-custom", "ratelimit", "cache", "origin" }

function _M.prepare_rules(rules, lists)
  local groups = {}
  for _, rule in ipairs(rules or {}) do
    local group = groups[rule.phase] or {}; groups[rule.phase] = group
    group[#group + 1] = { id = rule.id, match = expressions.compile(rule.expression, lists), action = rule.action }
  end
  return groups
end
function _M.prepare_config(cfg)
  cfg.lists, cfg.blocks, cfg.allows = {}, {}, {}
  for _, list in ipairs(cfg.ip_lists or {}) do
    local matcher = expressions.ip_set(list.entries)
    cfg.lists[list.id] = matcher
    if list.platform then
      if list.kind == "allow" then cfg.allows[#cfg.allows + 1] = matcher end
      if list.kind == "block" then cfg.blocks[#cfg.blocks + 1] = matcher end
    end
  end
  cfg.groups = _M.prepare_rules(cfg.platform_rules, cfg.lists)
  return cfg
end

function _M.request(site, headers)
  local var = ngx.var
  local values = {
    ["http.host"] = var.host, ["http.request.method"] = ngx.req.get_method(),
    ["http.request.uri.path"] = var.uri, ["http.request.uri.query"] = var.args or "",
    ["http.request.uri"] = var.request_uri, ["ip.src"] = var.remote_addr,
    ssl = var.scheme == "https",
  }
  for name, value in pairs(headers) do
    values["http.request.headers." .. name:lower()] = type(value) == "table" and table.concat(value, ", ") or value
  end
  -- JA4 comes from the TLS handshake (edgeweir.ja4); "" on plain HTTP.
  if site._ja4 then values["tls.ja4"] = require("edgeweir.ja4").value() end
  -- GeoIP is read once in the access phase; response filters cannot yield.
  if site._geo then
    local geo = assert(require("edgeweir.geoip").lookup(var.remote_addr), "GeoIP unavailable")
    values["ip.geoip.country"], values["ip.geoip.subdivision"], values["ip.geoip.asnum"] = geo.country or "", geo.subdivision or "", geo.asnum or 0
  end
  return values
end

local function run_group(group, values, site, ctx, phase, namespace)
  for _, rule in ipairs(group or {}) do
    if rule.match(values) then
      local a = rule.action
      if a.kind == "block" then return { status = a.status_code } end
      if a.kind == "allow" then -- this WAF scope only; never skips platform rules or rate limits
        ctx.allowed = true -- but exempts the request from Under Attack and CC challenges
        break
      end
      if a.kind == "challenge" then
        -- A sufficient pass continues with the next rules; otherwise the
        -- request is challenged here.
        local challenge = require("edgeweir.challenge")
        local level = challenge.LEVELS[a.challenge]
        if not level then return { status = 503 } end
        if challenge.pass_level(site) < level then return { challenge = a.challenge, level = level } end
      end
      if a.kind == "log" then
        -- IDs only: expressions, URL, headers and client addresses are never logged.
        local key = "log:" .. site.id .. ":" .. rule.id
        if ngx.shared.edgeweir_policy_logs:safe_add(key, true, 60) then
          ngx.log(ngx.NOTICE, "edgeweir: WAF match site=", site.id, " rule=", rule.id)
        end
      elseif a.kind == "redirect" then return { status = a.status_code, location = a.value }
      elseif a.kind == "rewrite" then
        ngx.req.set_uri(a.value, false)
        values["http.request.uri.path"] = a.value
        values["http.request.uri"] = a.value .. (ngx.var.args and ("?" .. ngx.var.args) or "")
      elseif a.kind == "request_header" then
        if a.remove then ngx.req.clear_header(a.header) else ngx.req.set_header(a.header, a.value or "") end
        values["http.request.headers." .. a.header] = a.remove and "" or (a.value or "")
      elseif a.kind == "response_header" then
        ngx.header[a.header] = not a.remove and (a.value or "") or nil
        values["http.response.headers." .. a.header] = a.remove and "" or (a.value or "")
      elseif a.kind == "config" then
        if a.cache_bypass ~= nil then ctx.cache_bypass = a.cache_bypass end
        if a.force_https ~= nil then ctx.force_https = a.force_https end
        if a.gzip == false then ctx.gzip = false end
      elseif a.kind == "rate_limit" then
        local result = ratelimit.check(site._rate_limit_dict, namespace, rule.id, a, values[a.key])
        if result then return result end
      end
    end
  end
end

function _M.access(site, headers)
  local values = _M.request(site, headers)
  local cfg = site._config
  local ctx = { values = values, force_https = site.tls and site.tls.force_https }
  ngx.ctx.edgeweir_policy = ctx
  local allowed = false
  for _, match in ipairs(cfg.allows or {}) do if match(values["ip.src"]) then allowed = true; break end end
  ctx.platform_allowed = allowed
  if not allowed then
    for _, match in ipairs(cfg.blocks or {}) do if match(values["ip.src"]) then return { status = 403 } end end
  end
  for _, phase in ipairs(_M.phases) do
    local result = run_group(cfg.groups and cfg.groups[phase], values, site, ctx, phase, "platform")
    if result then return result end
    result = run_group(site._rule_groups[phase], values, site, ctx, phase, "site")
    if result then return result end
  end
  if ctx.force_https and ngx.var.scheme ~= "https" then
    if not site.certificate_id or site.certificate_id == "" then return { status = 503 } end
    return { status = 301, location = "https://" .. ngx.var.host .. ngx.var.request_uri }
  end
  if ctx.gzip == false then ngx.req.clear_header("Accept-Encoding"); ctx.cache_bypass = true end
end
function _M.response(site)
  local ctx = ngx.ctx.edgeweir_policy
  if not ctx then return end
  local values = ctx.values
  values["http.response.code"] = ngx.status
  for name, value in pairs(ngx.resp.get_headers(0)) do
    values["http.response.headers." .. name:lower()] = type(value) == "table" and table.concat(value, ", ") or value
  end
  run_group(site._config.groups and site._config.groups["response-transform"], values, site, ctx, "response-transform", "platform")
  run_group(site._rule_groups["response-transform"], values, site, ctx, "response-transform", "site")
end
return _M
