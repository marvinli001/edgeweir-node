local rate = require("edgeweir.ratelimit")
local store = require("edgeweir.store")
local a = { id = "a", origins = {}, domains = {} }
local b = { id = "b", origins = {}, domains = {} }
store.prepare(a)
store.prepare(b)
assert(rate.dict_name("a") == "edgeweir_rate_61")
assert(a._rate_limit_dict and b._rate_limit_dict and a._rate_limit_dict ~= b._rate_limit_dict)
assert(a._rate_limit_dict:capacity() == 262144 and b._rate_limit_dict:capacity() == 262144)

local action = { window_seconds = 60, limit = 2, status_code = 429 }
assert(rate.check(a._rate_limit_dict, "a", "site", "requests", action, "client") == nil)
assert(rate.check(a._rate_limit_dict, "a", "site", "requests", action, "client") == nil)
local limited = assert(rate.check(a._rate_limit_dict, "a", "site", "requests", action, "client"))
assert(limited.status == 429 and limited.retry_after == 60)
assert(rate.check(b._rate_limit_dict, "b", "site", "requests", action, "client") == nil)
assert(rate.check(a._rate_limit_dict, "a", "platform", "requests", action, "client") == nil)

-- Re-decoding a site after a hot update keeps its shared counter state.
local refreshed = { id = "a", origins = {}, domains = {} }
store.prepare(refreshed)
assert(rate.check(refreshed._rate_limit_dict, "a", "site", "requests", action, "client").status == 429)
local missing = { id = "unallocated", origins = {}, domains = {} }
store.prepare(missing)
local unavailable = rate.check(missing._rate_limit_dict, "unallocated", "site", "requests", action, "client")
assert(unavailable.status == 503 and unavailable.code == "rate-limit-unavailable")

-- Audit 2026-10-01 P0-7: once the partition is full, new clients pass
-- uncounted (logged), and clients already counted stay limited.
local dict = b._rate_limit_dict
local logs = ngx.shared.edgeweir_policy_logs
local clients = 0
repeat
  clients = clients + 1
  assert(rate.check(dict, "b", "site", "requests", action, "client-" .. clients) == nil)
until logs:get("rate-full-n:b") or clients > 100000
-- Short keys: one counter per 128-byte slab chunk.
assert(clients > 1800 and clients < 100000, "partition holds " .. clients .. " counters")
for _ = 1, 10 do
  assert(rate.check(dict, "b", "site", "requests", action, "newcomer") == nil)
end
assert(rate.check(dict, "b", "site", "requests", action, "client") == nil)
assert(rate.check(dict, "b", "site", "requests", action, "client").status == 429)
assert(logs:get("rate-full-n:b") == 11 and logs:get("rate-full:b"))

print(clients .. " counters per 256 KiB partition; full partitions pass new clients; independent counters, hot updates and missing-partition handling passed")
