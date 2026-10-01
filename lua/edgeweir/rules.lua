-- edgeweir.rules: cache rule evaluation.
--
-- Rules arrive sorted by (priority, id). Request conditions (exact paths,
-- path prefixes, extensions, or since proto v0.13.0 a typed expression,
-- `condition`, of phase cache) are checked on the edge layer when the
-- request arrives, against the client's original request (the values
-- edgeweir.policy keeps before any rewrite, like the cache key); response
-- conditions (status codes, size) on the origin layer when the origin
-- answers. Empty lists match everything; when several conditions are set,
-- all of them must match (see CacheRuleMatch in edgeweir/proto).
--
-- chain() returns the rules whose request conditions match, in order, up to
-- and including the first rule that matches every response (later rules can
-- never apply). decide() picks the first rule of the chain whose response
-- conditions match.
--
-- Requests that carry Authorization (RFC 9111, section 3.5): a caching rule
-- without cache_authorized acts as a bypass rule for them, so they are
-- neither looked up nor stored unless the rule that applies allows it.
--
-- browser_cache_control() is the Cache-Control a rule's browser TTL gives
-- clients (edge header filter).
local expressions = require("edgeweir.expressions")

local _M = {}

local sub = string.sub
local lower = string.lower

-- Statuses a rule without explicit status codes may cache. Error responses
-- are only cached when a rule lists them (or the origin asks for it and the
-- rule respects origin headers).
local DEFAULT_CACHEABLE = { [200] = true, [203] = true, [206] = true, [300] = true, [301] = true, [308] = true }

-- extension returns the lowercase extension of the last path segment of
-- uri ("/a/b.PNG" -> "png"), or nil: http.request.uri.path.extension
-- (edgeweir.expressions.path_extension) without the empty string.
function _M.extension(uri)
  local ext = expressions.path_extension(uri)
  if ext == "" then
    return nil
  end
  return ext
end

local function set_of(list)
  local set = {}
  for _, v in ipairs(list or {}) do
    set[v] = true
  end
  return set, next(set) ~= nil
end

-- prepare precomputes lookup tables on a decoded rule; lists are the IP
-- lists a condition may name (in_list).
function _M.prepare(rule, lists)
  rule._ext_set, rule._has_ext = set_of(rule.extensions)
  rule._path_set, rule._has_path = set_of(rule.paths)
  rule._status_set, rule._has_status = set_of(rule.status_codes)
  rule._prefixes = rule.path_prefixes or {}
  rule.ttl = tonumber(rule.ttl) or 0
  rule.min_size = tonumber(rule.min_size) or 0
  rule.max_size = tonumber(rule.max_size) or 0
  rule.swr = tonumber(rule.swr) or 0
  rule.sie = tonumber(rule.sie) or 0
  rule.cache_authorized = rule.cache_authorized == true
  rule.browser_ttl = tonumber(rule.browser_ttl) or 0
  if type(rule.condition) == "table" then
    rule._condition = expressions.compile(rule.condition, lists or {})
  end
  -- Acts as a bypass rule for requests with Authorization.
  rule._auth_bypass = rule.action == "cache" and not rule.cache_authorized
  -- A rule without response conditions that bypasses or respects origin
  -- headers matches every response: rules after it can never apply.
  local unconditional = not rule._has_status and rule.min_size == 0 and rule.max_size == 0
  rule._always = unconditional and (rule.action ~= "cache" or rule.mode == "respect")
  rule._always_auth = unconditional and (rule.action ~= "cache" or rule._auth_bypass or rule.mode == "respect")
  return rule
end

-- action returns the action of rule for a request (authorized: it carries
-- Authorization).
function _M.action(rule, authorized)
  if authorized and rule._auth_bypass then
    return "bypass"
  end
  return rule.action
end

-- request_matches checks the request conditions against the normalized
-- request path uri.
function _M.request_matches(rule, uri)
  local prefixes = rule._prefixes
  if #prefixes > 0 then
    local ok = false
    for i = 1, #prefixes do
      local p = prefixes[i]
      if sub(uri, 1, #p) == p then
        ok = true
        break
      end
    end
    if not ok then
      return false
    end
  end
  if rule._has_path and not rule._path_set[uri] then
    return false
  end
  if rule._has_ext then
    local ext = _M.extension(uri)
    if not ext or not rule._ext_set[ext] then
      return false
    end
  end
  return true
end

-- chain returns the list of rules that may decide the request (see above),
-- or nil when none does. uri is the normalized request path, values the
-- client's original request values for rules with a condition (built from
-- uri when absent).
function _M.chain(site, uri, authorized, values)
  local rules = site.cache_rules
  if not rules then
    return nil
  end
  local out
  for i = 1, #rules do
    local r = rules[i]
    local hit
    if r._condition then
      values = values or { ["http.request.uri.path"] = uri, ["http.request.uri.path.extension"] = expressions.path_extension(uri) }
      hit = r._condition(values)
    else
      hit = _M.request_matches(r, uri)
    end
    if hit then
      out = out or {}
      out[#out + 1] = r
      if (authorized and r._always_auth) or (not authorized and r._always) then
        break
      end
    end
  end
  return out
end

-- match returns the first rule of site whose request conditions match uri
-- (compatibility helper for callers that ignore response conditions).
function _M.match(site, uri)
  local c = _M.chain(site, uri)
  return c and c[1] or nil
end

-- may_cache reports whether any rule of the chain caches the request.
function _M.may_cache(chain, authorized)
  if not chain then
    return false
  end
  for i = 1, #chain do
    if _M.action(chain[i], authorized) == "cache" then
      return true
    end
  end
  return false
end

-- default_cacheable reports whether a rule TTL may apply to status when the
-- rule lists no status codes.
function _M.default_cacheable(status)
  return DEFAULT_CACHEABLE[status] == true
end

-- response_matches checks status and size. status 206 counts as 200 (Range
-- and slice responses); size is the full entity size when known. Without
-- status codes, a caching rule that overrides origin headers only applies to
-- the default cacheable statuses; bypass rules and rules that respect origin
-- headers apply to any status.
function _M.response_matches(rule, status, size, authorized)
  if rule._has_status then
    local s = status == 206 and 200 or status
    if not rule._status_set[s] then
      return false
    end
  elseif _M.action(rule, authorized) == "cache" and rule.mode ~= "respect" and not DEFAULT_CACHEABLE[status] then
    return false
  end
  if rule.min_size > 0 or rule.max_size > 0 then
    if not size then
      return false -- unknown size never satisfies a size bound
    end
    if rule.min_size > 0 and size < rule.min_size then
      return false
    end
    if rule.max_size > 0 and size > rule.max_size then
      return false
    end
  end
  return true
end

-- NOT_STORED are the Cache-Control directives that keep nginx from storing
-- a response when the rule respects origin headers.
local NOT_STORED = { "no-store", "no-cache", "private" }

-- browser_cache_control returns "max-age=N" for a response the chain's
-- deciding rule caches with a browser TTL N (status and size as in
-- decide), or nil to keep the response's Cache-Control (cc: its value
-- after the edge restored the origin's). A rule that respects origin
-- headers leaves responses the origin keeps out of shared caches alone.
function _M.browser_cache_control(chain, status, size, authorized, cc)
  local rule = _M.decide(chain, status, size, authorized)
  if not rule or rule.browser_ttl <= 0 or _M.action(rule, authorized) ~= "cache" then
    return nil
  end
  if rule.mode == "override" and rule.ttl <= 0 then
    return nil
  end
  if rule.mode == "respect" and cc then
    local value = lower(type(cc) == "table" and table.concat(cc, ", ") or cc)
    for i = 1, #NOT_STORED do
      if value:find(NOT_STORED[i], 1, true) then
        return nil
      end
    end
  end
  return "max-age=" .. rule.browser_ttl
end

-- decide returns the rule of chain that applies to the response, or nil.
function _M.decide(chain, status, size, authorized)
  if not chain then
    return nil
  end
  for i = 1, #chain do
    if _M.response_matches(chain[i], status, size, authorized) then
      return chain[i]
    end
  end
  return nil
end

return _M
