-- edgeweir.waf: OWASP CRS (ModSecurity) for the sites that run it.
--
-- nginx.conf loads ModSecurity only while a site runs the CRS and turns it
-- on only in the edge layer's named locations @edgeweir_waf_<body limit>,
-- one per request body limit (init() receives the limits of the loaded
-- nginx.conf). Every other request never passes through ModSecurity. At
-- the end of its access phase the router hands a CRS site's request to its
-- location (ngx.exec): ModSecurity inspects it in that location's rewrite
-- and preaccess phases, before the cache lookup, so cache hits are
-- inspected as well. The location repeats the edge layer's proxy and cache
-- settings.
--
-- An internal redirect clears ngx.ctx; stash_ctx() keeps the request's
-- context in a per-worker table under a reference held in the nginx
-- variable $edgeweir_ctx_ref, and restore() puts it back (in the CRS
-- location's access, header filter and log phases: a request ModSecurity
-- blocks never reaches the access phase). The gRPC location
-- (edgeweir.router.grpc_enter) hands its requests over the same way.
--
-- The site's settings travel to ModSecurity in X-Edgeweir-Waf
-- ("<site>;<mode>;<paranoia>;<threshold>", read by the generated rules;
-- clients cannot send X-Edgeweir-* headers). Since proto v0.29.0 (feature
-- waf-v2, ADR-0040): a config rule's CRS mode replaces the site's for the
-- request (off: the request does not enter the CRS location, nor does one
-- a skip action exempts from the CRS), and the site's exclusion entries
-- whose path matches the client's normalized path (the original $uri, a
-- signed URL's signature removed; exact, or as a byte prefix; empty: every
-- path) are named by their tokens in X-Edgeweir-Waf-Ex (",<token>,...,"):
-- the generated rules remove their CRS rules or targets. Both headers are
-- removed before the request goes to the origin layer.
local _M = {}

local HEADER = "X-Edgeweir-Waf"
_M.HEADER = HEADER
local EX_HEADER = "X-Edgeweir-Waf-Ex"
_M.EX_HEADER = EX_HEADER

-- limits[<request body limit>] = true for the locations nginx.conf has.
local limits = {}

-- init records the request body limits of the loaded nginx.conf's CRS
-- locations (init_by_lua).
function _M.init(body_limits)
  limits = {}
  for _, limit in ipairs(body_limits or {}) do
    local n = tonumber(limit)
    if n and n >= 0 and n == math.floor(n) then
      limits[n] = true
    end
  end
end

-- location returns the named location for a site's CRS setting, or nil
-- when the loaded nginx.conf has no CRS location at all. Right after a
-- reload the site table may still name a body limit the new nginx.conf
-- dropped (or not yet name the one it added): such requests are still
-- inspected, with the largest limit available. Without any CRS location
-- (the last CRS site was just switched off) the request goes on
-- uninspected, as the new configuration wants.
function _M.location(waf)
  local limit = tonumber(waf and waf.request_body_limit)
  if limit and limits[limit] then
    return "@edgeweir_waf_" .. string.format("%d", limit)
  end
  local best
  for l in pairs(limits) do
    if not best or l > best then best = l end
  end
  if best then
    return "@edgeweir_waf_" .. string.format("%d", best)
  end
  return nil
end

-- header_value is the X-Edgeweir-Waf value of a site; mode, when given,
-- replaces the site's (a config rule's CRS mode).
function _M.header_value(site_id, waf, mode)
  return string.format("%s;%s;%d;%d", site_id, mode or waf.mode, tonumber(waf.paranoia_level) or 1,
    tonumber(waf.anomaly_threshold) or 5)
end

-- exclusion_value is the X-Edgeweir-Waf-Ex value of a request with the
-- normalized path: the tokens of the site's exclusion entries whose path
-- matches, ",<token>,<token>,"; nil when none does.
function _M.exclusion_value(waf, path)
  local list = waf and waf.exclusions
  if type(list) ~= "table" or #list == 0 or type(path) ~= "string" then return nil end
  local tokens = {}
  for i = 1, #list do
    local e = list[i]
    local p = type(e) == "table" and e.path or nil
    if type(p) == "string" and type(e.token) == "string" and e.token:match("^%x+$") then
      local hit
      if p == "" then
        hit = true
      elseif e.exact then
        hit = path == p
      else
        hit = string.sub(path, 1, #p) == p
      end
      if hit then tokens[#tokens + 1] = e.token end
    end
  end
  if #tokens == 0 then return nil end
  return "," .. table.concat(tokens, ",") .. ","
end

-- mode returns the CRS mode of a request of the site: the site's, a config
-- rule's (detect, block), or nil when the request skips the CRS (a config
-- rule's off, a skip action's crs).
function _M.mode(site, pctx)
  if pctx and (pctx.skip_crs or pctx.crs == "off") then return nil end
  return pctx and pctx.crs or site.waf.mode
end

-- Per-worker stash of request contexts across ngx.exec; entries live for
-- one request only, stale ones (a request aborted in between) are swept.
local stash, stash_time = {}, {}
local next_ref, stashed = 0, 0
local STALE = 300

local function sweep(now)
  for ref, t in pairs(stash_time) do
    if now - t > STALE then
      stash[ref], stash_time[ref] = nil, nil
      stashed = stashed - 1
    end
  end
end

-- stash_ctx stores ctx and returns its reference.
function _M.stash_ctx(ctx, now)
  now = now or ngx.now()
  if stashed > 10000 then sweep(now) end
  next_ref = next_ref + 1
  local ref = tostring(next_ref)
  stash[ref], stash_time[ref] = ctx, now
  stashed = stashed + 1
  return ref
end

-- take_ctx removes and returns the context stored under ref.
function _M.take_ctx(ref)
  local ctx = stash[ref]
  if ctx ~= nil then
    stash[ref], stash_time[ref] = nil, nil
    stashed = stashed - 1
  end
  return ctx
end

-- stashed_count is the number of contexts waiting (tests).
function _M.stashed_count()
  return stashed
end

-- enter hands the request to the site's CRS location, or returns without
-- doing anything when there is none or the request skips the CRS.
function _M.enter(site)
  local name = _M.location(site.waf)
  if not name then return end
  local ctx = ngx.ctx
  local mode = _M.mode(site, ctx.edgeweir_policy)
  if not mode then return end
  ngx.req.set_header(HEADER, _M.header_value(site.id, site.waf, mode))
  local ex = _M.exclusion_value(site.waf, ctx.edgeweir_original_path or ngx.var.uri)
  if ex then ngx.req.set_header(EX_HEADER, ex) end
  ctx.edgeweir_waf = true
  ngx.var.edgeweir_ctx_ref = _M.stash_ctx(ctx)
  return ngx.exec(name)
end

-- restore puts the stashed context back after the internal redirect.
function _M.restore()
  local var = ngx.var
  local ref = var.edgeweir_ctx_ref
  if not ref or ref == "" then return end
  var.edgeweir_ctx_ref = ""
  local ctx = _M.take_ctx(ref)
  if ctx then ngx.ctx = ctx end
end

-- access runs in the CRS location's access phase: ModSecurity has seen the
-- request; the headers must not reach the origin.
function _M.access()
  _M.restore()
  ngx.req.clear_header(HEADER)
  ngx.req.clear_header(EX_HEADER)
end

-- rule_ids parses $modsecurity_triggered_rules ("id,id,..." in match
-- order) into at most max unique rule ids (numbers).
function _M.rule_ids(value, max)
  local ids, seen = {}, {}
  if not value or value == "" then return ids end
  max = max or 16
  for id in string.gmatch(value, "%d+") do
    local n = tonumber(id)
    if n and n > 0 and n <= 4294967295 and not seen[n] then
      seen[n] = true
      ids[#ids + 1] = n
      if #ids >= max then break end
    end
  end
  return ids
end

-- result returns the matched rule ids (at most 16) and whether ModSecurity
-- blocked the request; nil when the request did not go through the CRS.
function _M.result()
  if not ngx.ctx.edgeweir_waf then return nil end
  local var = ngx.var
  return _M.rule_ids(var.modsecurity_triggered_rules, 16), var.modsecurity_intervention == "1"
end

return _M
