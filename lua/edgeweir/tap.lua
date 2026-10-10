-- edgeweir.tap: the node's live view of requests (ADR-0041 §6,
-- `edgeweir-node accesslog`).
--
-- A viewer polls GET /v1/logs/tap?after=<seq>[&site=<id>] on the control
-- socket. Each call marks "on|*" (every request, unknown hosts included)
-- or "on|<site>" in lua_shared_dict edgeweir_tap for ON_TTL seconds. Only
-- while such a mark exists does the log phase record requests: under
-- "e|<seq>" for ENTRY_TTL seconds, at most MAX_PER_SECOND sequence numbers
-- per second on this node. Without viewers a request costs two dict reads.
-- Viewers read by sequence number, each on its own; numbers whose entry
-- expired or was over the rate count as missed. Sampling does not apply,
-- and the sampled access log queue is never touched.
local cjson = require("cjson.safe")

local _M = {}

local floor = math.floor

_M.ON_TTL = 5
_M.ENTRY_TTL = 10
_M.MAX_PER_SECOND = 2000
-- Entries one call returns, and sequence numbers it reads, at most.
_M.MAX_ENTRIES = 1000
_M.MAX_SCAN = 5000
-- Entries never outlive this many numbers (ENTRY_TTL at the full rate):
-- a viewer further behind skips the rest as missed.
_M.WINDOW = _M.ENTRY_TTL * _M.MAX_PER_SECOND

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
-- second's numbers are over the rate (the number is missed then).
function _M.record(entry)
  local d = dict()
  if not d then return end
  local seq = d:incr("seq", 1, 1)
  if not seq then return end
  local n = d:incr("rate|" .. floor(ngx.now()), 1, 0, 2)
  if not n or n > _M.MAX_PER_SECOND then return end
  local raw = cjson.encode(entry)
  if raw then d:set("e|" .. seq, raw, _M.ENTRY_TTL) end
end

-- read renews the viewer's mark and returns {seq, entries, missed}: the
-- entries after after (of site only, when given), up to the last number
-- read, which the viewer passes next time. A first call (after 0) and a
-- viewer ahead of this node (nginx restarted) get only the current number.
-- Numbers start at 1, so that a first answer is never 0.
function _M.read(after, site)
  local d = dict()
  d:set("on|" .. (site or "*"), true, _M.ON_TTL)
  local seq = d:get("seq")
  if not seq then
    d:add("seq", 1)
    seq = d:get("seq") or 1
  end
  local entries, missed = {}, 0
  if after <= 0 or after > seq then
    return { seq = seq, entries = setmetatable(entries, cjson.array_mt), missed = 0 }
  end
  if seq - after > _M.WINDOW then
    missed = seq - _M.WINDOW - after
    after = seq - _M.WINDOW
  end
  local last = after
  for s = after + 1, math.min(seq, after + _M.MAX_SCAN) do
    if #entries >= _M.MAX_ENTRIES then break end
    last = s
    local raw = d:get("e|" .. s)
    if raw then
      if not site or raw:find('"site_id":"' .. site .. '"', 1, true) then
        local e = cjson.decode(raw)
        if e and (not site or e.site_id == site) then entries[#entries + 1] = e end
      end
    else
      missed = missed + 1
    end
  end
  return { seq = last, entries = setmetatable(entries, cjson.array_mt), missed = missed }
end

return _M
