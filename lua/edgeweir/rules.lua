-- edgeweir.rules: cache rule evaluation.
--
-- Rules arrive sorted by (priority, id). Request conditions (exact paths,
-- path prefixes, extensions) are checked on the edge layer when the request
-- arrives; response conditions (status codes, size) on the origin layer when
-- the origin answers. Empty lists match everything; when several conditions
-- are set, all of them must match (see CacheRuleMatch in edgeweir/proto).
--
-- chain() returns the rules whose request conditions match, in order, up to
-- and including the first rule that matches every response (later rules can
-- never apply). decide() picks the first rule of the chain whose response
-- conditions match.
local _M = {}

local sub = string.sub
local lower = string.lower

-- Statuses a rule without explicit status codes may cache. Error responses
-- are only cached when a rule lists them (or the origin asks for it and the
-- rule respects origin headers).
local DEFAULT_CACHEABLE = { [200] = true, [203] = true, [206] = true, [300] = true, [301] = true, [308] = true }

-- extension returns the lowercase extension of the last path segment of
-- uri ("/a/b.PNG" -> "png"), or nil.
function _M.extension(uri)
  local last = uri:match("([^/]*)$")
  if not last then
    return nil
  end
  local ext = last:match("%.([^.]+)$")
  if not ext then
    return nil
  end
  return lower(ext)
end

local function set_of(list)
  local set = {}
  for _, v in ipairs(list or {}) do
    set[v] = true
  end
  return set, next(set) ~= nil
end

-- prepare precomputes lookup tables on a decoded rule.
function _M.prepare(rule)
  rule._ext_set, rule._has_ext = set_of(rule.extensions)
  rule._path_set, rule._has_path = set_of(rule.paths)
  rule._status_set, rule._has_status = set_of(rule.status_codes)
  rule._prefixes = rule.path_prefixes or {}
  rule.ttl = tonumber(rule.ttl) or 0
  rule.min_size = tonumber(rule.min_size) or 0
  rule.max_size = tonumber(rule.max_size) or 0
  rule.swr = tonumber(rule.swr) or 0
  rule.sie = tonumber(rule.sie) or 0
  -- A rule without response conditions that bypasses or respects origin
  -- headers matches every response: rules after it can never apply.
  rule._always = not rule._has_status and rule.min_size == 0 and rule.max_size == 0
    and (rule.action ~= "cache" or rule.mode == "respect")
  return rule
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
-- or nil when none does.
function _M.chain(site, uri)
  local rules = site.cache_rules
  if not rules then
    return nil
  end
  local out
  for i = 1, #rules do
    local r = rules[i]
    if _M.request_matches(r, uri) then
      out = out or {}
      out[#out + 1] = r
      if r._always then
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

-- may_cache reports whether any rule of the chain caches.
function _M.may_cache(chain)
  if not chain then
    return false
  end
  for i = 1, #chain do
    if chain[i].action == "cache" then
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
function _M.response_matches(rule, status, size)
  if rule._has_status then
    local s = status == 206 and 200 or status
    if not rule._status_set[s] then
      return false
    end
  elseif rule.action == "cache" and rule.mode ~= "respect" and not DEFAULT_CACHEABLE[status] then
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

-- decide returns the rule of chain that applies to the response, or nil.
function _M.decide(chain, status, size)
  if not chain then
    return nil
  end
  for i = 1, #chain do
    if _M.response_matches(chain[i], status, size) then
      return chain[i]
    end
  end
  return nil
end

return _M
