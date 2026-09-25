-- edgeweir.rules: cache rule evaluation.
--
-- Rules arrive sorted by (priority, id); the first matching rule wins.
-- Empty condition lists match everything; when several lists are set all
-- of them must match (see CacheRuleMatch in edgeweir/proto).
local _M = {}

local sub = string.sub
local lower = string.lower

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

-- prepare precomputes lookup tables on a decoded rule.
function _M.prepare(rule)
  local set = {}
  for _, e in ipairs(rule.extensions or {}) do
    set[e] = true
  end
  rule._ext_set = set
  rule._has_ext = next(set) ~= nil
  rule._prefixes = rule.path_prefixes or {}
  rule.ttl = tonumber(rule.ttl) or 0
  return rule
end

local function matches(rule, uri)
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
  if rule._has_ext then
    local ext = _M.extension(uri)
    if not ext or not rule._ext_set[ext] then
      return false
    end
  end
  return true
end

-- match returns the first rule of site matching the normalized request
-- path uri, or nil.
function _M.match(site, uri)
  local rules = site.cache_rules
  if not rules then
    return nil
  end
  for i = 1, #rules do
    local r = rules[i]
    if matches(r, uri) then
      return r
    end
  end
  return nil
end

return _M
