-- edgeweir.tap: the node's live view of requests (ADR-0041 §6,
-- `edgeweir-node accesslog`).
--
-- A viewer polls GET /v1/logs/tap?after=<seq>[&site=<id>] on the control
-- socket. Each call marks "on|*" (every request, unknown hosts included)
-- or "on|<site>" in lua_shared_dict edgeweir_tap for ON_TTL seconds. Only
-- while such a mark exists does the log phase record requests, at most
-- MAX_PER_SECOND a second on this node ("rate|<second>", counted before a
-- number is taken): a request's entry is encoded first, then it takes the
-- next sequence number and is kept under "e|<seq>" for ENTRY_TTL seconds,
-- so numbers stay dense. Requests over the rate take no number: "dropped"
-- counts them on this node, and every answer carries that total (the
-- viewer reports its growth between two answers as missed requests,
-- whatever site it watches). Without viewers a request costs two dict
-- reads.
--
-- Viewers read by sequence number, each on its own. A number without an
-- entry is missed (it expired, or the worker that took it failed to store
-- it) unless it is one of the last HEAD_GAP numbers and was taken in about
-- the last second: another worker may be between taking it and storing
-- its entry, so the read stops before it and the next call reads it.
-- Sampling does not apply, and the sampled access log queue is never
-- touched.
local cjson = require("cjson.safe")

local _M = {}

local ceil, floor, min = math.ceil, math.floor, math.min

_M.ON_TTL = 5
_M.ENTRY_TTL = 10
_M.MAX_PER_SECOND = 2000
-- Entries one call returns, and sequence numbers it reads, at most.
_M.MAX_ENTRIES = 1000
_M.MAX_SCAN = 5000
-- Entries never outlive this many numbers (ENTRY_TTL at the full rate):
-- a viewer further behind skips the rest as missed.
_M.WINDOW = _M.ENTRY_TTL * _M.MAX_PER_SECOND
-- A missing number this close to the head may still be being written.
_M.HEAD_GAP = 64

local function dict()
  return ngx.shared.edgeweir_tap
end

-- watching reports whether a viewer watches requests of site_id ("" for
-- requests of no site: only viewers of every request see them).
function _M.watching(site_id)
  local d = dict()
  if not d then return false end
  if d:get("on|*") then return true end
  return site_id ~= nil and site_id ~= "" and d:get("on|" .. site_id) ~= nil
end

-- record numbers entry (a table with site_id) and keeps it, unless this
-- second's records are over the rate (then it counts as dropped).
function _M.record(entry)
  local d = dict()
  if not d then return end
  local n = d:incr("rate|" .. floor(ngx.now()), 1, 0, 2)
  local raw = n and n <= _M.MAX_PER_SECOND and cjson.encode(entry)
  local seq = raw and d:incr("seq", 1, 1)
  if not seq then
    d:incr("dropped", 1, 0)
    return
  end
  d:set("e|" .. seq, raw, _M.ENTRY_TTL)
end

-- recent returns about how many numbers were taken in the last second at
-- now: this second's and the previous second's share of it.
local function recent(d, now)
  local sec = floor(now)
  local cur = min(d:get("rate|" .. sec) or 0, _M.MAX_PER_SECOND)
  local prev = min(d:get("rate|" .. (sec - 1)) or 0, _M.MAX_PER_SECOND)
  return cur + ceil(prev * (1 - (now - sec)))
end

-- read renews the viewer's mark and returns {seq, entries, missed,
-- dropped}: the entries after after (of site only, when given), up to the
-- last number read, which the viewer passes next time; the numbers missed
-- among them; the node's total of requests dropped over the rate. A first
-- call (after 0) and a viewer ahead of this node (nginx restarted) get
-- only the current number. Numbers start at 1, so that a first answer is
-- never 0.
function _M.read(after, site)
  local d = dict()
  d:set("on|" .. (site or "*"), true, _M.ON_TTL)
  local seq = d:get("seq")
  if not seq then
    d:add("seq", 1)
    seq = d:get("seq") or 1
  end
  local dropped = d:get("dropped") or 0
  local entries, missed = {}, 0
  if after <= 0 or after > seq then
    return { seq = seq, entries = setmetatable(entries, cjson.array_mt), missed = 0, dropped = dropped }
  end
  if seq - after > _M.WINDOW then
    missed = seq - _M.WINDOW - after
    after = seq - _M.WINDOW
  end
  local young = min(recent(d, ngx.now()), _M.HEAD_GAP)
  local last = after
  for s = after + 1, min(seq, after + _M.MAX_SCAN) do
    if #entries >= _M.MAX_ENTRIES then break end
    local raw = d:get("e|" .. s)
    if raw then
      if not site or raw:find('"site_id":"' .. site .. '"', 1, true) then
        local e = cjson.decode(raw)
        if e and (not site or e.site_id == site) then entries[#entries + 1] = e end
      end
    elseif seq - s < young then
      -- Taken, maybe not stored yet: the next call reads it.
      break
    else
      missed = missed + 1
    end
    last = s
  end
  return { seq = last, entries = setmetatable(entries, cjson.array_mt), missed = missed, dropped = dropped }
end

return _M
