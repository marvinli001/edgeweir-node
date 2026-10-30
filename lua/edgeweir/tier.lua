-- edgeweir.tier: the tiered cache (ADR-0073).
--
-- Lower tier. route() runs at the end of edgeweir.router's access phase for
-- requests the edge may cache, of sites whose plan gives this node upper
-- tiers (Site.tier): the edge sends them to the tier layer (unix socket,
-- nginx.conf) instead of the site's origin layer, with the cache key, the
-- URL the purge markers match and the site's origin layer as the fallback.
-- In the tier layer, access() picks the upper tiers (in the plan's order;
-- ones marked down, or that the request already passed per CDN-Loop, are
-- left out), balance() connects to them over mutual TLS (nginx.conf: the
-- node certificate both ways, checked against the node CA and the upper
-- tier's node id), header_filter() turns the upper tier's answer into one
-- the edge cache takes like an origin's (edgeweir.origin.edge_cache_headers:
-- the TTL and stale extensions of the site's cache rules; a 5xx closes the
-- connection when the edge may serve its stale copy) and names the upper
-- tier and its cache status for the access log, and log() counts the
-- fetch (MinuteStats.tier_fetches) and keeps the upper tiers' health. When
-- no upper tier answers, nginx's 502 / 504 goes to @edgeweir_tier_fallback:
-- the site's own origin layer, as the edge would have used it.
--
-- Upper tier. upper_access() runs on the tier listener (TLS, client
-- certificate of the node CA required): the client must be a node
-- (O=Edgeweir Node) that some plan names as this node's lower tier
-- (tier_clients). No ban, rule, challenge or CRS applies (the lower tier
-- made those checks). The cache key is the lower tier's, with the higher of
-- the two cache generations and of the two key epochs: the lower tier's
-- epoch moves the key when it applied a purge this node has not applied
-- yet, this node's epoch when it applied one first, so neither ever serves
-- the other an object a purge it applied removed. upper_header_filter()
-- returns the origin's response as it was (Cache-Control, Cache-Tag,
-- Set-Cookie of fetched responses, the affinity announcement), never the
-- edge's client-side changes; the cache status travels in
-- X-Edgeweir-Tier-Cache. A node that is an upper tier and has upper tiers
-- of its own (a regional tier) passes the request on, up to MAX_HOPS.
local store = require("edgeweir.store")
local purge = require("edgeweir.purge")
local cachekey = require("edgeweir.cachekey")
local cachetags = require("edgeweir.cachetags")
local origin = require("edgeweir.origin")
local policy = require("edgeweir.policy")
local compress = require("edgeweir.compress")
local setcookie = require("edgeweir.setcookie")
local ngx_balancer = require("ngx.balancer")

local _M = {}

local find, gsub, match, sub = string.find, string.gsub, string.match, string.sub
local tonumber, tostring = tonumber, tostring

-- MAX_HOPS: lower tier, regional tier, upper tier (TierHop).
_M.MAX_HOPS = 2
-- An upper tier is skipped for RECOVERY seconds after MAX_FAILS
-- consecutive failed attempts (connection, TLS, timeout).
_M.MAX_FAILS = 2
_M.RECOVERY = 15
-- CONNECT is the connect timeout towards upper tiers (nginx.conf); the read
-- and send timeouts are the site's plus MARGIN, so the upper tier's own
-- origin timeout ends first.
_M.CONNECT = 3
_M.MARGIN = 5
-- STATUSES are the cache statuses counted by name (others count as "-").
_M.STATUSES = { HIT = true, MISS = true, EXPIRED = true, STALE = true, UPDATING = true, REVALIDATED = true, BYPASS = true }
-- FALLBACK names fetches that went to the origins because no upper tier
-- answered (MinuteStats.tier_fetches, AccessLog.tier).
_M.FALLBACK = "origin"
_M.NODE_ORGANIZATION = "Edgeweir Node"

local HEALTH_PREFIX = "tier|"

-- ---------------------------------------------------------------- pure

-- escape and unescape the parts of X-Edgeweir-Tier-Url.
local function escape(v)
  return (gsub(v or "", "[^A-Za-z0-9._~!$&'()*+,;=:@/-]", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

local function unescape(v)
  return (gsub(v, "%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

-- url_value encodes what the purge markers match (edgeweir.purge.epoch):
-- the host, the normalized path and "?" and the query string, "-" for
-- none ("?" is escaped inside the parts).
function _M.url_value(host, path, args)
  return escape(host) .. " " .. escape(path) .. " " .. (args and ("?" .. escape(args)) or "-")
end

-- parse_url returns host, path, args of url_value's value, nil if invalid.
function _M.parse_url(value)
  if type(value) ~= "string" then return nil end
  local h, p, a = match(value, "^(%S+) (%S+) (%S+)$")
  if not h or sub(p, 1, 1) ~= "/" then return nil end
  local args
  if sub(a, 1, 1) == "?" then
    args = unescape(sub(a, 2))
  elseif a ~= "-" then
    return nil
  end
  return unescape(h), unescape(p), args
end

-- split_key returns the base of a cache key and its epoch (0 without one):
-- cachekey escapes "#" everywhere else.
function _M.split_key(key)
  if type(key) ~= "string" then return nil end
  local i = find(key, "#", 1, true)
  if not i then return key, 0 end
  local e = tonumber(sub(key, i + 1))
  if not e or not match(sub(key, i + 1), "^%d+$") then return nil end
  return sub(key, 1, i - 1), e
end

-- greater_generation compares two cache generations (decimal strings of
-- uint64, beyond Lua's exact numbers).
local function greater_generation(a, b)
  if #a ~= #b then return #a > #b end
  return a > b
end

-- upper_key returns the cache key an upper tier uses for the lower tier's
-- key of site: the base with the higher generation, and the higher of the
-- two epochs (e_local: this node's for the request). nil when the key is
-- not the site's.
function _M.upper_key(site, key, e_local_fn)
  local base, e_lower = _M.split_key(key)
  if not base then return nil end
  local id, gen, rest = match(base, "^([A-Za-z0-9_-]+):(%d+):(.*)$")
  if id ~= site.id or rest == "" then return nil end
  local own = tostring(site.cache_generation or "0")
  if greater_generation(own, gen) then
    base = id .. ":" .. own .. ":" .. rest
  end
  local e_local = e_local_fn(base) or 0
  return cachekey.with_epoch(base, math.max(e_lower, e_local)), base
end

-- client_node returns the node id of a client certificate's subject
-- ($ssl_client_s_dn, RFC 2253: "CN=<id>,O=Edgeweir Node") when it is a
-- node's, nil otherwise.
function _M.client_node(dn)
  if type(dn) ~= "string" then return nil end
  local cn, o
  for part in string.gmatch(dn, "[^,]+") do
    local k, v = match(part, "^%s*(%a+)=(.*)$")
    if k == "CN" then
      if cn then return nil end
      cn = v
    elseif k == "O" then
      if o then return nil end
      o = v
    end
  end
  if o ~= _M.NODE_ORGANIZATION or not cn or not match(cn, "^[A-Za-z0-9_-]+$") then return nil end
  return cn
end

-- candidates returns the upper tiers of peers a request may try: not in
-- the CDN-Loop value (loop_has(cdn_id)), not marked down (down(id)).
function _M.candidates(peers, loop_has, down)
  local out = {}
  for i = 1, #peers do
    local p = peers[i]
    if not loop_has(p.cdn_id) and not down(p.id) then
      out[#out + 1] = p
    end
  end
  return out
end

-- status_key is the counter of a cache status (STATUSES, else "-").
function _M.status_key(cs)
  if cs and _M.STATUSES[cs] then return cs end
  return "-"
end

-- log_value is AccessLog.tier: "<upper id> <status>", FALLBACK, or nil.
function _M.log_value(header)
  if type(header) ~= "string" then return nil end
  if header == _M.FALLBACK then return header end
  local id, cs = match(header, "^([A-Za-z0-9_-]+) (%S+)$")
  if id then return id .. " " .. _M.status_key(cs) end
  return nil
end

-- ---------------------------------------------------------------- health

local function health()
  return ngx.shared.edgeweir_health
end

local function down(id)
  local d = health()
  return d ~= nil and d:get(HEALTH_PREFIX .. "d|" .. id) ~= nil
end

local function failed(id)
  local d = health()
  if not d then return end
  local n = d:incr(HEALTH_PREFIX .. "f|" .. id, 1, 0, 300)
  if n and n >= _M.MAX_FAILS then
    d:set(HEALTH_PREFIX .. "d|" .. id, true, _M.RECOVERY)
    d:delete(HEALTH_PREFIX .. "f|" .. id)
  end
end

local function succeeded(id)
  local d = health()
  if d then d:delete(HEALTH_PREFIX .. "f|" .. id) end
end

-- ---------------------------------------------------------------- stats

local function count(site_id, metric, status)
  if not site_id or site_id == "" then return end
  local minute = math.floor(ngx.time() / 60) * 60
  ngx.shared.edgeweir_stats:incr(minute .. "|" .. site_id .. "|" .. metric .. status, 1, 0, 7200)
end

-- ---------------------------------------------------------------- lower tier

-- route sends a cacheable request of site to the tier layer (edge access
-- phase, after the cache key is set). path is the normalized path the
-- purge markers match.
function _M.route(site, var, host, path)
  if not site.tier or #site.tier == 0 or var.edgeweir_image ~= "" then
    return
  end
  var.edgeweir_tier_fallback = var.edgeweir_origin_layer
  var.edgeweir_origin_layer = "edgeweir_tier"
  var.edgeweir_tier_key = var.edgeweir_cache_key
  var.edgeweir_tier_url = _M.url_value(host, path, var.args)
  if var.edgeweir_tier_hops == "" then
    var.edgeweir_tier_hops = "1"
  end
end

local function valid_layer(name)
  return type(name) == "string" and match(name, "^edgeweir_origin_[a-z0-9_]+$") ~= nil
end

function _M.access()
  local var = ngx.var
  local fallback = var.http_x_edgeweir_tier_fallback
  if not valid_layer(fallback) then
    ngx.log(ngx.ERR, "edgeweir: tier layer without a valid fallback layer")
    return ngx.exit(502)
  end
  var.edgeweir_tier_fallback = fallback
  local site = store.site_current(var.http_x_edgeweir_site or "")
  local hops = tonumber(var.http_x_edgeweir_tier_hops or "") or 1
  if not site or not site.tier or hops > _M.MAX_HOPS then
    return ngx.exec("@edgeweir_tier_fallback")
  end
  local loop = var.http_cdn_loop
  local cands = _M.candidates(site.tier, function(id)
    return require("edgeweir.router").cdn_loop_contains(loop, id)
  end, down)
  if #cands == 0 then
    return ngx.exec("@edgeweir_tier_fallback")
  end
  local ctx = ngx.ctx
  ctx.site = site
  ctx.cands = cands
  ctx.chain = origin.chain_from_header(site, var.http_x_edgeweir_rules)
  ctx.authorized = var.http_authorization ~= nil
  ctx.override = policy.parse_origin_header(var.http_x_edgeweir_origin) or {}
end

function _M.balance()
  local ctx = ngx.ctx
  local n = (ctx.try or 0) + 1
  ctx.try = n
  local c = ctx.cands and ctx.cands[n]
  if not c then
    return ngx.exit(ngx.ERROR)
  end
  ngx.var.edgeweir_ssl_name = c.id
  local ok, err = ngx_balancer.set_current_peer(c.address, c.port, "tier|" .. c.id)
  if not ok then
    ngx.log(ngx.ERR, "edgeweir: set_current_peer tier ", c.address, ":", c.port, ": ", err)
    return ngx.exit(ngx.ERROR)
  end
  if n == 1 and #ctx.cands > 1 then
    ngx_balancer.set_more_tries(#ctx.cands - 1)
  end
  local _, send, read = origin.timeouts(ctx.site.conn, ctx.override, false)
  ngx_balancer.set_timeouts(_M.CONNECT, send + _M.MARGIN, read + _M.MARGIN)
  ngx_balancer.enable_keepalive(60, 1000)
  local tried = ctx.tried or {}
  tried[n] = c
  ctx.tried = tried
  -- For the fallback location's log phase (the redirect empties ngx.ctx).
  local var = ngx.var
  var.edgeweir_tier_tried = n == 1 and c.id or (var.edgeweir_tier_tried .. "," .. c.id)
end

function _M.header_filter()
  local ctx = ngx.ctx
  local h = ngx.header
  local var = ngx.var
  -- Only the tier layer names the upper tier; only an origin layer stashes
  -- the Cache-Control the edge restores, carries cached Set-Cookie lines
  -- or names what an image variant saved.
  local cs = h["X-Edgeweir-Tier-Cache"]
  h["X-Edgeweir-Tier-Cache"] = nil
  h["X-Edgeweir-CC"] = nil
  h[setcookie.HEADER] = nil
  h["X-Edgeweir-Image-Saved"] = nil
  local site = ctx.site
  local tried = ctx.tried
  local peer = tried and tried[#tried]
  if not site or not peer then
    return
  end
  h["X-Edgeweir-Tier"] = peer.id .. " " .. _M.status_key(type(cs) == "string" and cs or nil)
  h[origin.UPSTREAM] = origin.last_upstream(var.upstream_addr)
  local status = ngx.status
  -- The upper tier's 5xx (its origin failed and it had no stale copy):
  -- the edge's stale copy wins, as for an origin's.
  if origin.defer_to_stale(status, var.http_x_edgeweir_cache_status, ctx.chain, ctx.authorized) then
    return ngx.exit(ngx.ERROR)
  end
  compress.origin_header_filter(site)
  if h["X-Edgeweir-Error"] then
    -- The upper tier's own error page: never cached here.
    h["X-Accel-Expires"] = 0
  elseif ctx.chain then
    origin.edge_cache_headers(h, ctx.chain, status, ctx.authorized)
  end
end

-- statuses of $upstream_status and whether each attempt got a response
-- header ($upstream_header_time).
local function attempts(var)
  local out = {}
  local statuses, times = {}, {}
  for v in string.gmatch(var.upstream_status or "", "[^,:%s]+") do statuses[#statuses + 1] = v end
  for v in string.gmatch(var.upstream_header_time or "", "[^,:%s]+") do times[#times + 1] = v end
  for i = 1, #statuses do
    out[i] = { status = statuses[i], answered = times[i] ~= nil and times[i] ~= "-" }
  end
  return out
end

-- account keeps the health of the upper tiers tried (by $edgeweir_tier_tried
-- order) from the attempts' outcomes.
local function account(ids, var)
  local list = attempts(var)
  for i, id in ipairs(ids) do
    local a = list[i]
    if a then
      if not a.answered and (a.status == "502" or a.status == "504") then
        failed(id)
      else
        succeeded(id)
      end
    end
  end
end

function _M.log()
  local ctx = ngx.ctx
  local tried = ctx.tried
  if not tried or #tried == 0 then
    return
  end
  local ids = {}
  for i = 1, #tried do ids[i] = tried[i].id end
  account(ids, ngx.var)
  local cs = ngx.var.upstream_http_x_edgeweir_tier_cache
  count(ctx.site.id, "tf", _M.status_key(cs))
end

-- fallback_access runs in @edgeweir_tier_fallback (the redirect emptied
-- ngx.ctx) and counts the fetch as one of the origins.
function _M.fallback_access()
  if not valid_layer(ngx.var.edgeweir_tier_fallback) then
    return ngx.exit(502)
  end
  local site_id = ngx.var.http_x_edgeweir_site or ""
  count(site_id, "tf", _M.FALLBACK)
end

function _M.fallback_header_filter()
  ngx.header["X-Edgeweir-Tier"] = _M.FALLBACK
end

-- fallback_log keeps the health of the upper tiers that failed before the
-- fallback ($upstream_status lists their attempts first).
function _M.fallback_log()
  local ids = {}
  for id in string.gmatch(ngx.var.edgeweir_tier_tried or "", "[^,]+") do
    ids[#ids + 1] = id
  end
  if #ids > 0 then
    account(ids, ngx.var)
  end
end

-- ---------------------------------------------------------------- upper tier

local function refuse(status, code)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Edgeweir-Error"] = code
  ngx.print(code, "\n")
  return ngx.exit(ngx.HTTP_OK)
end

-- clients returns the set of node ids allowed on the tier listener.
local function allowed_client(cfg, id)
  local list = cfg.tier_clients
  if type(list) ~= "table" then return false end
  local set = cfg._tier_clients
  if not set then
    set = {}
    for _, v in ipairs(list) do set[v] = true end
    cfg._tier_clients = set
  end
  return set[id] == true
end

function _M.upper_access()
  local var = ngx.var
  local cfg = store.config()
  if var.ssl_client_verify ~= "SUCCESS" then
    return refuse(403, "tier-client-refused")
  end
  local client = _M.client_node(var.ssl_client_s_dn)
  if not client or not allowed_client(cfg, client) then
    return refuse(403, "tier-client-refused")
  end
  -- What the lower tier sends, then every internal header goes: the edge
  -- proxy settings below set their own.
  local headers = ngx.req.get_headers(0)
  local site_id = headers["x-edgeweir-site"]
  local key = headers["x-edgeweir-tier-key"]
  local url = headers["x-edgeweir-tier-url"]
  local hops = tonumber(headers["x-edgeweir-tier-hops"] or "") or 1
  local rules = headers["x-edgeweir-rules"]
  local override = headers["x-edgeweir-origin"]
  for name in pairs(headers) do
    if sub(name, 1, 11) == "x-edgeweir-" then
      ngx.req.clear_header(name)
    end
  end
  local cdn_id = cfg.cdn_id
  if cdn_id and cdn_id ~= "" then
    local router = require("edgeweir.router")
    local loop = var.http_cdn_loop
    if router.cdn_loop_contains(loop, cdn_id) then
      return refuse(508, "loop-detected")
    end
    var.edgeweir_cdn_loop = router.cdn_loop_value(loop, cdn_id)
  end
  local site = type(site_id) == "string" and store.site_current(site_id) or nil
  if not site then
    return refuse(404, "unknown-site")
  end
  local host, path, args = _M.parse_url(url)
  if not host or type(key) ~= "string" then
    return refuse(400, "tier-request-invalid")
  end
  local final, base = _M.upper_key(site, key, function(b)
    local epoch = purge.epoch(site.id, site.cache_key, host, path, args)
    local tmax = purge.tag_max(site.id)
    if tmax then
      return cachetags.key_epoch(site.id, b, epoch, tmax)
    end
    return epoch
  end)
  if not final then
    return refuse(400, "tier-request-invalid")
  end
  local ctx = ngx.ctx
  ctx.edgeweir_site = site
  ctx.edgeweir_tier_client = client
  var.edgeweir_site = site.id
  var.edgeweir_cache_zone = site.cache_zone
  var.edgeweir_origin_layer = require("edgeweir.router").origin_layer(site)
  if compress.enabled(site) then
    var.edgeweir_strip_ae = "1"
  end
  if type(rules) == "string" then var.edgeweir_rules = rules end
  if type(override) == "string" and override ~= "" then var.edgeweir_origin_override = override end
  var.edgeweir_cache_key = final
  var.edgeweir_cache_bypass = "0"
  var.edgeweir_no_cache = "0"
  if site.slice then
    var.edgeweir_range_mode = "slice"
  end
  -- A regional tier: on to its own upper tiers, with this key.
  if site.tier and #site.tier > 0 and hops < _M.MAX_HOPS then
    var.edgeweir_tier_hops = tostring(hops + 1)
    var.edgeweir_tier_fallback = var.edgeweir_origin_layer
    var.edgeweir_origin_layer = "edgeweir_tier"
    var.edgeweir_tier_key = final
    var.edgeweir_tier_url = url
  end
  ctx.edgeweir_tier_base = base
end

-- FROM_CACHE: cache statuses of responses the cache served.
local FROM_CACHE = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }

function _M.upper_header_filter()
  local h = ngx.header
  local var = ngx.var
  local cs = var.upstream_cache_status
  if (cs == "MISS" or cs == "EXPIRED") and var.edgeweir_no_cache == "0" then
    cachetags.record(var.edgeweir_site, var.edgeweir_cache_key, var.upstream_http_cache_tag, store.config().tag_ttl)
  end
  -- The origin's response as it was: the lower tier caches it and makes
  -- the client-side changes itself.
  setcookie.restore(h, var.upstream_http_x_edgeweir_set_cookie, cs, ngx.is_subrequest)
  h["Cache-Tag"] = var.upstream_http_cache_tag
  if not FROM_CACHE[cs or ""] then
    h["X-Edgeweir-Affinity"] = var.upstream_http_x_edgeweir_affinity
  end
  local stashed = h["X-Edgeweir-CC"]
  if stashed then
    h["X-Edgeweir-CC"] = nil
    if stashed == "-" then
      h["Cache-Control"] = nil
    else
      h["Cache-Control"] = stashed
    end
  end
end

function _M.upper_log()
  local ctx = ngx.ctx
  local site = ctx.edgeweir_site
  if site and ctx.edgeweir_tier_client then
    count(site.id, "tv", _M.status_key(ngx.var.upstream_cache_status))
  end
end

return _M
