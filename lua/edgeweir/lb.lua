-- edgeweir.lb: origin selection.
--
-- order() returns the origins to try for a request, best first, at most
-- MAX_TRIES of them:
--   1. the healthy primaries, ordered by the pool policy; retries stay
--      among them, backups never take traffic while a primary is up;
--   2. only when every primary is down: the healthy backups;
--   3. when every origin is down, all of them anyway, primaries first
--      (fail open: an attempt may still succeed and ends the down period
--      early).
--
-- Policies:
--   weighted_random  weighted random choice (then weighted order for retries)
--   round_robin      smooth weighted round robin (nginx's algorithm), per
--                    worker and site table version
--   consistent_hash  ketama-style ring (40 points per weight unit) keyed by
--                    the request URI; a down origin only moves its own keys
--
-- "Down" combines the passive check and, for sites whose pool has active
-- checks (site._active), the agent's active check (edgeweir.health).
--
-- Session affinity (edgeweir.affinity): a pinned origin that is eligible in
-- the tier taking traffic (a healthy primary; a healthy backup while every
-- primary is down) goes first and the policy orders the others behind it
-- (round robin keeps its state for unpinned requests: the others follow
-- in weighted order). When every origin is down there is no pin.
--
-- Origin groups (proto v0.13.0): a site's origins form groups (site._pools,
-- "" the default group); origin rules choose the group of a request and
-- order() works on that group's origins alone, with round-robin and ring
-- state of its own.
local health = require("edgeweir.health")

local _M = {}

_M.MAX_TRIES = 3

local crc32 = ngx.crc32_long
local random = math.random
local remove, sort = table.remove, table.sort

local POINTS_PER_WEIGHT = 40
local MAX_WEIGHT_POINTS = 100

local function healthy(site, list, now)
  local out = {}
  local active = site._active == true
  for i = 1, #list do
    if not health.is_down(site.id, list[i].id, now, active) then
      out[#out + 1] = list[i]
    end
  end
  return out
end

-- weighted_order samples without replacement, proportionally to weight.
function _M.weighted_order(list)
  local rest, out = {}, {}
  for i = 1, #list do
    rest[i] = list[i]
  end
  while #rest > 0 do
    local total = 0
    for i = 1, #rest do
      total = total + rest[i].weight
    end
    local r = random() * total
    local idx = #rest
    for i = 1, #rest do
      r = r - rest[i].weight
      if r < 0 then
        idx = i
        break
      end
    end
    out[#out + 1] = remove(rest, idx)
  end
  return out
end

-- rr_order picks with smooth weighted round robin; retries follow the list.
function _M.rr_order(site, list, group)
  local states = site._rr
  if not states then
    states = {}
    site._rr = states
  end
  local state = states[group]
  if not state then
    state = {}
    states[group] = state
  end
  local total, best, best_i = 0, nil, nil
  for i = 1, #list do
    local o = list[i]
    local cw = (state[o.id] or 0) + o.weight
    state[o.id] = cw
    total = total + o.weight
    if not best or cw > state[best.id] then
      best, best_i = o, i
    end
  end
  if not best then
    return {}
  end
  state[best.id] = state[best.id] - total
  local out = { best }
  for k = 1, #list - 1 do
    out[#out + 1] = list[(best_i + k - 1) % #list + 1]
  end
  return out
end

local function ring(site, all, group)
  local rings = site._rings
  if not rings then
    rings = {}
    site._rings = rings
  end
  local points = rings[group]
  if points then
    return points
  end
  points = {}
  for _, o in ipairs(all) do
    local n = math.min(o.weight, MAX_WEIGHT_POINTS) * POINTS_PER_WEIGHT
    for i = 1, n do
      points[#points + 1] = { crc32(o.id .. "-" .. i), o }
    end
  end
  sort(points, function(a, b)
    return a[1] < b[1]
  end)
  rings[group] = points
  return points
end

-- chash_order walks the ring of all origins of the group from the key's
-- position and returns the distinct eligible origins in ring order.
function _M.chash_order(site, all, eligible, group, key)
  local points = ring(site, all, group)
  local n = #points
  if n == 0 then
    return {}
  end
  local want = {}
  for i = 1, #eligible do
    want[eligible[i].id] = true
  end
  local h = crc32(key or "")
  local lo, hi = 1, n
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    if points[mid][1] < h then
      lo = mid + 1
    else
      hi = mid
    end
  end
  if points[lo][1] < h then
    lo = 1 -- wrap around
  end
  local out, seen = {}, {}
  for k = 0, n - 1 do
    local o = points[(lo + k - 1) % n + 1][2]
    if want[o.id] and not seen[o.id] then
      seen[o.id] = true
      out[#out + 1] = o
      if #out == #eligible then
        break
      end
    end
  end
  return out
end

local function policy_order(site, all, eligible, group, key)
  if #eligible == 0 then
    return {}
  end
  local policy = site.load_balance
  if policy == "round_robin" then
    return _M.rr_order(site, eligible, group)
  elseif policy == "consistent_hash" then
    return _M.chash_order(site, all, eligible, group, key)
  end
  return _M.weighted_order(eligible)
end

-- pinned returns the order of a tier with the pinned origin first, or nil
-- when the pin is not among the tier's eligible origins.
local function pinned(site, all, eligible, group, key, pin)
  local first, rest = nil, {}
  for i = 1, #eligible do
    if eligible[i].id == pin then
      first = eligible[i]
    else
      rest[#rest + 1] = eligible[i]
    end
  end
  if not first then
    return nil
  end
  local others
  if #rest == 0 then
    others = rest
  elseif site.load_balance == "consistent_hash" then
    others = _M.chash_order(site, all, rest, group, key)
  else
    others = _M.weighted_order(rest)
  end
  local out = { first }
  for i = 1, #others do
    out[#out + 1] = others[i]
  end
  return out
end

-- order returns the origins to try for a request (see above). key is the
-- consistent-hash key (the request URI), pin the origin id of a valid
-- affinity cookie (or nil), group the origin group (nil or "": the default
-- group; a group without origins gives none).
function _M.order(site, key, now, pin, group)
  local prim, back, p, b = site._primaries or {}, site._backups or {}, "p", "b"
  if group and group ~= "" then
    local pool = site._pools and site._pools[group]
    if not pool then
      return {}
    end
    prim, back, p, b = pool.primaries, pool.backups, group .. "|p", group .. "|b"
  end
  local hp = healthy(site, prim, now)
  local hb = #hp == 0 and healthy(site, back, now) or nil
  local out
  if #hp > 0 then
    out = pin and pinned(site, prim, hp, p, key, pin) or policy_order(site, prim, hp, p, key)
  elseif #hb > 0 then
    out = pin and pinned(site, back, hb, b, key, pin) or policy_order(site, back, hb, b, key)
  else
    out = policy_order(site, prim, prim, p, key)
    local rest = policy_order(site, back, back, b, key)
    for i = 1, #rest do
      out[#out + 1] = rest[i]
    end
  end
  for i = #out, _M.MAX_TRIES + 1, -1 do
    out[i] = nil
  end
  return out
end

return _M
