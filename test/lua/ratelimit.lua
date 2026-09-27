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
assert(rate.check(a._rate_limit_dict, "site", "requests", action, "client") == nil)
assert(rate.check(a._rate_limit_dict, "site", "requests", action, "client") == nil)
local limited = assert(rate.check(a._rate_limit_dict, "site", "requests", action, "client"))
assert(limited.status == 429 and limited.retry_after == 60)
assert(rate.check(b._rate_limit_dict, "site", "requests", action, "client") == nil)
assert(rate.check(a._rate_limit_dict, "platform", "requests", action, "client") == nil)

-- Re-decoding a site after a hot update keeps its shared counter state.
local refreshed = { id = "a", origins = {}, domains = {} }
store.prepare(refreshed)
assert(rate.check(refreshed._rate_limit_dict, "site", "requests", action, "client").status == 429)
local missing = { id = "unallocated", origins = {}, domains = {} }
store.prepare(missing)
assert(rate.check(missing._rate_limit_dict, "site", "requests", action, "client").status == 503)

print("256 KiB site partitions, independent counters, hot updates and missing-partition handling passed")
