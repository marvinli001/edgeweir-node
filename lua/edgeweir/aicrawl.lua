-- edgeweir.aicrawl: AI crawl control (proto vNEXT, feature ai-crawlers-v1,
-- ADR-0070).
--
-- The console ships the crawler catalogue (NodeConfig.ai_crawlers, site
-- table field "ai_crawlers"); nodes never download crawler lists. A request
-- claims a crawler when its User-Agent contains one of the crawler's tokens
-- (ASCII case-insensitive, the longest matching token wins, then the
-- smaller id). The claim is verified when the client address lies in the
-- crawler's published ranges, or by reverse DNS of the address and a
-- forward lookup of that name (edgeweir.bots.check) for crawlers with
-- domains: "verified", "failed" (an impersonator), "unverifiable" (the
-- operator publishes no way to verify) or "pending" (a lookup was in flight
-- or failed). request() decides it once per request, in the access phase
-- (DNS lookups need cosockets); the log phase only claims (pending).
--
-- A site's policy (Site.ai_crawl, "ai_crawl") acts after the site's rules:
-- allow (a verified claim also skips Under Attack and CC challenges),
-- block (403 or 402, the built-in error page or the site's text; never for
-- /robots.txt, which crawlers always may read), challenge
-- (the router asks the policy's challenge unless a pass covers it) and
-- charge: pay per crawl, the protocol only (HTTP 402 with crawler-price,
-- crawler-exact-price / crawler-max-price from the crawler, crawler-charged
-- on a 2xx, crawler-error on refusals). Only verified claims may pay; the
-- node records the charged price and moves no money. With dynamic pricing
-- the origin's crawler-price header prices the response (header_filter);
-- the header reaches clients only on a 402. Impersonators get the policy's
-- impersonator action.
--
-- The managed robots.txt: GET and HEAD of exactly /robots.txt get the
-- policy's text before the origin's file (a 200 text/plain response that is
-- not content-encoded), or alone for a 404, 410 or a 200 that is no text
-- file (an application's fallback page). The edge changes the response on
-- delivery, cache hits included: the cache keeps the origin's file.
local bots = require("edgeweir.bots")
local errorpages = require("edgeweir.errorpages")
local expressions = require("edgeweir.expressions")
local reasons = require("edgeweir.reasons")

local _M = {}

local find, lower, match, sub, floor = string.find, string.lower, string.match, string.sub, math.floor
local concat = table.concat

-- FREE_PATHS are never charged.
_M.FREE_PATHS = {
  ["/robots.txt"] = true, ["/sitemap.xml"] = true, ["/security.txt"] = true,
  ["/.well-known/security.txt"] = true, ["/crawlers.json"] = true,
}

-- prepare_catalogue compiles the catalogue: each crawler's range set and
-- domains, and every token with its crawler, longest first (ties: the
-- smaller id), so the first token found is the claim. nil without
-- crawlers.
function _M.prepare_catalogue(list)
  if type(list) ~= "table" or #list == 0 then return nil end
  local tokens, crawlers = {}, {}
  for _, c in ipairs(list) do
    if type(c) == "table" and type(c.id) == "string" and type(c.tokens) == "table" then
      local cidrs = type(c.cidrs) == "table" and #c.cidrs > 0 and c.cidrs or nil
      local domains = type(c.domains) == "table" and #c.domains > 0 and c.domains or nil
      local entry = { id = c.id, operator = c.operator, domains = domains }
      if cidrs then
        local ok, set = pcall(expressions.ip_set, cidrs)
        if ok then entry.ranges = set end
      end
      entry.verifiable = entry.ranges ~= nil or domains ~= nil
      crawlers[c.id] = entry
      for _, t in ipairs(c.tokens) do
        if type(t) == "string" and t ~= "" then tokens[#tokens + 1] = { lower(t), entry } end
      end
    end
  end
  table.sort(tokens, function(a, b)
    if #a[1] ~= #b[1] then return #a[1] > #b[1] end
    if a[2].id ~= b[2].id then return a[2].id < b[2].id end
    return a[1] < b[1]
  end)
  return { tokens = tokens, crawlers = crawlers }
end

-- claim returns the catalogue entry a User-Agent claims, or nil.
function _M.claim(catalogue, ua)
  if type(ua) == "table" then ua = ua[1] end
  if not catalogue or type(ua) ~= "string" or ua == "" then return nil end
  local l = lower(ua)
  local tokens = catalogue.tokens
  for i = 1, #tokens do
    if find(l, tokens[i][1], 1, true) then return tokens[i][2] end
  end
  return nil
end

-- verify returns the verification of crawler c for addr. Without
-- cosockets (no_dns: the log phase) reverse DNS stays "pending".
function _M.verify(c, addr, no_dns)
  if not c.verifiable then return "unverifiable" end
  if c.ranges and c.ranges(addr) then return "verified" end
  if c.domains then
    if no_dns then return "pending" end
    return bots.check("ai:" .. c.id, c, addr)
  end
  return "failed"
end

-- prepare precomputes the site's policy (store.prepare); nil: none.
function _M.prepare(s)
  local p = s.ai_crawl
  if type(p) ~= "table" then
    s.ai_crawl, s._ai = nil, nil
    return
  end
  local robots = type(p.robots_txt) == "string" and p.robots_txt ~= "" and p.robots_txt or nil
  s._ai = {
    actions = type(p.actions) == "table" and p.actions or {},
    impersonators = (p.impersonators == "block" or p.impersonators == "challenge") and p.impersonators or nil,
    challenge = type(p.challenge) == "string" and p.challenge or "js",
    block_status = tonumber(p.block_status) == 402 and 402 or 403,
    block_body = type(p.block_body) == "string" and p.block_body ~= "" and p.block_body or nil,
    robots = robots,
    price = tonumber(p.price_micros) or 0,
    dynamic = p.dynamic_pricing == true,
  }
end

-- request returns the request's claim { id, verification } (nil: none),
-- verifying it the first time (access phase). The log phase passes
-- claim_only for requests refused before the access phase got that far:
-- published ranges still verify them, reverse DNS leaves them "pending".
function _M.request(site, claim_only)
  local ctx = ngx.ctx
  local r = ctx.edgeweir_crawler
  if r ~= nil then return r or nil end
  local cfg = site and site._config
  local catalogue = cfg and cfg.ai_crawlers
  if not catalogue then return nil end
  local var = ngx.var
  local c = _M.claim(catalogue, var.http_user_agent)
  if not c then
    ctx.edgeweir_crawler = false
    return nil
  end
  local verification = "pending"
  local ok, v = pcall(_M.verify, c, var.remote_addr, claim_only)
  if ok and v then verification = v end
  r = { id = c.id, verification = verification }
  ctx.edgeweir_crawler = r
  return r
end

-- parse_price returns the millionths of a US dollar of a price header
-- ("USD 0.01"), or nil.
function _M.parse_price(v)
  if type(v) == "table" then return nil end
  if type(v) ~= "string" then return nil end
  local whole, frac = match(v, "^%s*USD%s+(%d+)%.?(%d*)%s*$")
  if not whole or #whole > 7 or #frac > 6 then return nil end
  if frac == "" and find(v, ".", 1, true) then return nil end
  return tonumber(whole) * 1000000 + tonumber(sub(frac .. "000000", 1, 6))
end

-- format_price is the header form of micros: "USD 0.01", at least two
-- decimals.
function _M.format_price(micros)
  local whole = floor(micros / 1000000)
  local frac = string.format("%06d", micros % 1000000):gsub("0+$", "")
  if #frac < 2 then frac = frac .. string.rep("0", 2 - #frac) end
  return "USD " .. whole .. "." .. frac
end

-- answer refuses the request (status, crawler-error, optional price) with
-- a short plain-text body.
local function answer(status, err, price, reason)
  local ctx = ngx.ctx
  ctx.edgeweir_crawler_blocked = true
  reasons.set(reason or "pay_per_crawl")
  local h = ngx.header
  ngx.status = status
  if price then h["crawler-price"] = _M.format_price(price) end
  if err then h["crawler-error"] = err end
  h["Content-Type"] = "text/plain; charset=utf-8"
  h["Cache-Control"] = "no-store"
  local body = (status == 402 and "Payment required" or status == 403 and "Forbidden" or "Bad request") .. "\n"
  h["Content-Length"] = #body
  if ngx.req.get_method() ~= "HEAD" then ngx.print(body) end
  ngx.exit(ngx.HTTP_OK)
  return "done"
end

-- block answers with the policy's block response.
function _M.block(site, p)
  local ctx = ngx.ctx
  ctx.edgeweir_crawler_blocked = true
  reasons.set("ai_crawler")
  local h = ngx.header
  if p.price > 0 then h["crawler-error"] = "CrawlerForbidden" end
  if not p.block_body and p.block_status == 403 then
    errorpages.respond(403, "ai-crawler-blocked", site)
    return "done"
  end
  ngx.status = p.block_status
  h["Content-Type"] = "text/plain; charset=utf-8"
  h["Cache-Control"] = "no-store"
  h["X-Edgeweir-Error"] = "ai-crawler-blocked"
  local body = p.block_body or "Payment required\n"
  h["Content-Length"] = #body
  if ngx.req.get_method() ~= "HEAD" then ngx.print(body) end
  ngx.exit(ngx.HTTP_OK)
  return "done"
end

-- charge runs pay per crawl for a request whose crawler is charged.
function _M.charge(site, p, r, path)
  local ctx = ngx.ctx
  if p.price <= 0 then return _M.block(site, p) end
  if _M.FREE_PATHS[path] then return nil end
  local var = ngx.var
  local exact_raw, max_raw = var.http_crawler_exact_price, var.http_crawler_max_price
  if exact_raw and max_raw then return answer(400, "ConflictingPriceHeaders") end
  local raw = exact_raw or max_raw
  local offered = raw and _M.parse_price(raw)
  if raw and not offered then return answer(400, "InvalidCrawlerPriceValue") end
  if offered and r.verification ~= "verified" then return answer(400, "StrongAuthRequired") end
  if p.dynamic then
    -- The origin prices the response: decided in header_filter.
    ctx.edgeweir_ppc = { offered = offered, exact = exact_raw ~= nil, default = p.price }
    return nil
  end
  if not offered then return answer(402, "MissingCrawlerPrice", p.price) end
  if exact_raw and offered ~= p.price then return answer(402, "InvalidCrawlerExactPrice", p.price) end
  if not exact_raw and offered < p.price then return answer(402, "InvalidCrawlerMaxPrice", p.price) end
  ctx.edgeweir_ppc = { price = p.price }
  return nil
end

-- access runs the site's policy after the rules (exempt: allow rules, skip
-- actions with challenges, allow lists, the local listeners, ACME). path
-- is the request's normalized path. Returns nil to go on, "done" when it
-- answered, or "challenge", level, kind for the router to challenge.
function _M.access(site, exempt, path)
  local r = _M.request(site)
  local p = site._ai
  if not p then return nil end
  local method = ngx.req.get_method()
  if p.robots and path == "/robots.txt" and (method == "GET" or method == "HEAD") then
    -- The origin sends the file uncompressed, and as a whole: the edge puts
    -- text before it (header_filter).
    ngx.ctx.edgeweir_robots = true
    ngx.var.edgeweir_strip_ae = "1"
    ngx.req.clear_header("Range")
    ngx.req.clear_header("If-None-Match")
    ngx.req.clear_header("If-Modified-Since")
    ngx.req.clear_header("If-Range")
  end
  -- Crawlers always read robots.txt: it tells them what the site allows.
  if not r or exempt or path == "/robots.txt" then return nil end
  local action = p.actions[r.id]
  if r.verification == "failed" and p.impersonators and action ~= "block" then
    action = p.impersonators
  end
  if action == "allow" then
    if r.verification == "verified" then ngx.ctx.edgeweir_crawler_allowed = true end
    return nil
  elseif action == "block" then
    return _M.block(site, p)
  elseif action == "challenge" then
    return "challenge", require("edgeweir.challenge").LEVELS[p.challenge] or 2, p.challenge
  elseif action == "charge" then
    return _M.charge(site, p, r, path)
  end
  return nil
end

-- rewrites reports whether the response's body may change (the managed
-- robots.txt, a 402 the origin's price leads to): the router hands such
-- requests to a location with a body filter.
function _M.rewrites()
  local ctx = ngx.ctx
  local ppc = ctx.edgeweir_ppc
  return ctx.edgeweir_robots == true or (type(ppc) == "table" and ppc.default ~= nil)
end

-- allowed reports whether a verified crawler the site allows skips Under
-- Attack and CC challenges.
function _M.allowed()
  return ngx.ctx.edgeweir_crawler_allowed == true
end

-- text_type reports whether a Content-Type is plain text (or absent).
local function text_type(ct)
  if type(ct) == "table" then ct = ct[1] end
  if ct == nil or ct == "" then return true end
  return find(lower(ct), "^%s*text/plain") ~= nil
end

local function payment_required(ctx, h, price, err)
  ctx.edgeweir_crawler_blocked = true
  reasons.set("pay_per_crawl")
  ngx.status = 402
  h["crawler-price"] = _M.format_price(price)
  h["crawler-error"] = err
  h["Content-Type"] = "text/plain; charset=utf-8"
  h["Cache-Control"] = "no-store"
  h["Content-Length"], h["Content-Encoding"], h["Content-Range"] = nil, nil, nil
  h["ETag"], h["Last-Modified"], h["Accept-Ranges"] = nil, nil, nil
  ctx.edgeweir_replace = "Payment required\n"
end

-- header_filter applies pay per crawl and the managed robots.txt to the
-- response (edge layer).
function _M.header_filter(site)
  local p = site and site._ai
  if not p then return end
  local ctx = ngx.ctx
  -- The node's own refusals (access phase) keep their headers.
  if ctx.edgeweir_crawler_blocked then return end
  local h = ngx.header
  local status = ngx.status
  -- The origin's crawler-price reaches clients only on a 402 the node sends.
  local origin_price
  if p.price > 0 then
    origin_price = h["crawler-price"]
    if origin_price ~= nil then h["crawler-price"] = nil end
  end
  local ppc = ctx.edgeweir_ppc
  if type(ppc) == "table" then
    local price = ppc.price
    if ppc.default then
      price = ppc.default
      if origin_price ~= nil then
        local parsed = _M.parse_price(origin_price)
        if not parsed then
          ctx.edgeweir_crawler_blocked = true
          reasons.set("pay_per_crawl")
          ngx.status = 502
          h["crawler-error"] = "InvalidContentPrice"
          h["Content-Type"] = "text/plain; charset=utf-8"
          h["Cache-Control"] = "no-store"
          h["Content-Length"], h["Content-Encoding"], h["ETag"], h["Last-Modified"] = nil, nil, nil, nil
          ctx.edgeweir_replace = "Bad gateway\n"
          return
        end
        price = parsed
      end
      if price > 0 and status >= 200 and status < 300 then
        local o = ppc.offered
        if not o then return payment_required(ctx, h, price, "MissingCrawlerPrice") end
        if ppc.exact and o ~= price then return payment_required(ctx, h, price, "InvalidCrawlerExactPrice") end
        if not ppc.exact and o < price then return payment_required(ctx, h, price, "InvalidCrawlerMaxPrice") end
      end
    end
    -- Only successful responses are charged.
    if price and price > 0 and status >= 200 and status < 300 then
      h["crawler-charged"] = _M.format_price(price)
      ctx.edgeweir_charged = price
    end
  end
  if ctx.edgeweir_robots == true and p.robots then
    local enc = h["Content-Encoding"]
    local mode
    if status == 200 and (enc == nil or enc == "identity") and text_type(h["Content-Type"]) then
      mode = "prepend"
    elseif status == 200 or status == 404 or status == 410 then
      mode = "replace"
      ngx.status = 200
      h["Content-Type"] = "text/plain; charset=utf-8"
      h["Content-Encoding"] = nil
    end
    if mode then
      h["Content-Length"], h["ETag"], h["Accept-Ranges"], h["Content-Range"] = nil, nil, nil, nil
      if mode == "replace" then
        ctx.edgeweir_replace = p.robots
      else
        ctx.edgeweir_robots = "prepend"
        ctx.edgeweir_robots_text = p.robots
      end
    end
  end
end

-- body_filter sends what header_filter decided: a replacement body, or the
-- managed robots.txt text before the origin's.
function _M.body_filter()
  local ctx = ngx.ctx
  local body = ctx.edgeweir_replace
  if body then
    if body == true then
      ngx.arg[1] = nil
      return
    end
    ctx.edgeweir_replace = true
    ngx.arg[1] = body
    ngx.arg[2] = true
    return
  end
  if ctx.edgeweir_robots == "prepend" then
    ctx.edgeweir_robots = "sent"
    ngx.arg[1] = concat({ ctx.edgeweir_robots_text, ngx.arg[1] or "" })
  end
end

-- active reports whether the body filter has anything to do.
function _M.filtering()
  local ctx = ngx.ctx
  return ctx.edgeweir_replace ~= nil or ctx.edgeweir_robots == "prepend"
end

return _M
