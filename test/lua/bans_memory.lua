-- edgeweir.bans when shared memory, not the capacity, runs out (see
-- `make lua-test`; the dict is deliberately tiny):
--
--   resty -I lua --shdict 'edgeweir_bans 64k' test/lua/bans_memory.lua
local bans = require("edgeweir.bans")

local function check(cond, msg)
  if not cond then
    print("FAIL " .. msg)
    os.exit(1)
  end
end

bans.capacity = 1000000
for i = 1, 3000 do
  local ok, err = bans.add_auto("site-memory", string.format("10.%d.%d.1", math.floor(i / 256), i % 256), 600)
  check(ok, "own ban " .. i .. ": " .. tostring(err))
end
local st = bans.status()
check(st.entries > 10 and st.entries < 3000, "own bans held in 64k: " .. st.entries)
check(st.auto_evicted == 3000 - st.entries, "evicted " .. st.auto_evicted .. " of 3000, held " .. st.entries)
check(bans.match("site-memory", "10.11.184.1") == "a", "the newest own ban is missing")
check(bans.match("site-memory", "10.0.1.1") == nil, "the oldest own ban survived")
print("ok   new own bans replace the oldest ones when memory runs out (" .. st.entries .. " held)")

-- Console bans evict own bans (oldest first) when memory runs out.
local list = {}
for i = 1, 40 do
  list[i] = { id = "m" .. i, cidr = string.format("198.51.%d.0/24", i), scope = "platform", kind = "m", expires_at = ngx.now() + 3600 }
end
st = assert(bans.replace({ sequence = "1", bans = list }))
check(st.unapplied == 0, "manual bans unapplied: " .. st.unapplied)
check(st.auto_evicted > 3000 - st.entries, "no own ban was evicted")
for i = 1, 40 do
  check(bans.match("x", string.format("198.51.%d.9", i)) == "m", "manual ban " .. i .. " missing")
end
print("ok   console bans took the memory of the oldest own bans (" .. st.auto_evicted .. " evicted)")

-- Once only console bans are left, a manual ban that does not fit is
-- reported and nothing is evicted silently.
for i = 41, 2000 do
  list[i] = { id = "m" .. i, cidr = string.format("203.%d.%d.0/24", math.floor(i / 256), i % 256), scope = "platform", kind = "m", expires_at = ngx.now() + 3600 }
end
st = assert(bans.replace({ sequence = "2", bans = list }))
check(st.unapplied > 0, "every manual ban fit into 64k")
-- The ids are listed as far as memory allows; the count is always exact.
check(#st.unapplied_ids <= 100 and #st.unapplied_ids <= st.unapplied, "unapplied ids")
check(st.entries + st.unapplied == 2000, "held " .. st.entries .. " + unapplied " .. st.unapplied .. " ~= 2000")
for i = 1, 40 do
  check(bans.match("x", string.format("198.51.%d.9", i)) == "m", "earlier manual ban " .. i .. " was evicted")
end
print("ok   manual bans that do not fit are reported (" .. st.unapplied .. ")")
print("\n3 passed, 0 failed")
