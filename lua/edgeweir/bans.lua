-- edgeweir.bans: dynamic IP bans.
--
-- Console bans arrive from the agent through the control API (PUT replaces
-- the whole set, POST applies a delta); the node's own automatic bans are
-- added with add_auto() and queued for the agent to report, and deleted
-- with release() when the console lifts them. When a site's automatic ban
-- goes (own or console automatic), CC counts its client afresh
-- (edgeweir.cc.lifted). Nothing here reloads nginx.
--
-- lua_shared_dict "edgeweir_bans" (size: the agent's --ban-dict-mb):
--
--   e|<scope>|<family>/<len>|<bytes>  one ban, "<kind>|<id>|<expires>|<cidr>"
--        scope "*" (platform) or a site id; bytes are the first ceil(len/8)
--        bytes of the masked address; kind m (console, manual), c (console,
--        automatic) or a (this node's own); the TTL is the remaining
--        lifetime, so expired bans disappear by themselves
--   #len|<scope>  prefix lengths of the scope's console bans ("4/32,6/48")
--   #loc|<scope>  the scope has (had) own bans (always /32 and /64)
--   #ver          bumped when a length list changes; workers cache the
--                 lists per version
--   #seq          console sequence of the set (decimal, zero-padded to 20
--                 digits so that updates never need new memory)
--   #live         bans held; #x|<minute> counts the bans expiring in that
--                 minute and is subtracted from #live once it has passed
--                 (#swept is the last minute done)
--   #q            own bans in write order: eviction queue
--   #r            own bans waiting to be reported (JSON)
--   #unapplied    JSON {id: expires} of manual bans that do not fit (at
--                 most 1000; #unapplied_more counts the others)
--   #evicted      automatic bans dropped to make room
--   #aid          id counter of own bans
--   #lock         held while the agent writes
--
-- Every write uses safe_set / safe_add, so shared memory never evicts a
-- ban on its own. When a ban needs room (capacity or memory), the oldest
-- own ban goes first; console bans are never evicted here. A manual ban
-- that still does not fit is recorded in #unapplied and reported; an
-- automatic one is dropped and counted.
--
-- Lookup (match): one read of #ver per request; the prefix lengths of the
-- platform and the site scope come from the worker's cache, and without
-- any length nothing else is read. Otherwise the client address is masked
-- to each length and looked up (usually one or two reads).
local cjson = require("cjson.safe")
local bit = require("bit")
local ipaddr = require("edgeweir.ipaddr")

local _M = {}

-- Maximum number of bans held (the agent's --ban-capacity).
_M.capacity = 100000

-- clock returns the current time (replaced in tests).
_M.clock = function()
  return ngx.now()
end

local PLATFORM = "*"
local MAX_TTL = 7 * 86400
local REPORT_MAX = 10000
local UNAPPLIED_IDS = 100
local LIST_MAX = 1000

local band, lshift = bit.band, bit.lshift
local floor, char, concat = math.floor, string.char, table.concat
local find, sub, match = string.find, string.sub, string.match
local tonumber, tostring, type, pairs = tonumber, tostring, type, pairs
local unpack = unpack

local function shdict()
  return ngx.shared.edgeweir_bans
end

local function valid_id(s)
  return type(s) == "string" and #s > 0 and #s <= 128 and match(s, "^[A-Za-z0-9_-]+$") ~= nil
end

local scratch = {}

-- key_for returns the dict key of prefix bytes/len in scope.
local function key_for(scope, bytes, len)
  local n = floor((len + 7) / 8)
  for i = 1, n do
    scratch[i] = bytes[i]
  end
  local rem = len % 8
  if rem > 0 then
    scratch[n] = band(scratch[n], band(lshift(0xff, 8 - rem), 0xff))
  end
  local fam = (#bytes == 4) and "4/" or "6/"
  return "e|" .. scope .. "|" .. fam .. len .. "|" .. char(unpack(scratch, 1, n))
end
_M.key_for = key_for

-- parse_value splits "<kind>|<id>|<expires>|<cidr>" (nil for nil).
local function parse_value(v)
  if not v then
    return nil
  end
  local p2 = find(v, "|", 3, true)
  local p3 = p2 and find(v, "|", p2 + 1, true)
  if not p3 then
    return nil
  end
  return sub(v, 1, 1), sub(v, 3, p2 - 1), tonumber(sub(v, p2 + 1, p3 - 1)), sub(v, p3 + 1)
end

-- lifted tells CC that an automatic ban of scope went: ip is its IPv4
-- address or the first address of its IPv6 /64 (the text of a CIDR is
-- cut at the "/").
local function lifted(scope, ip)
  if scope ~= PLATFORM then
    require("edgeweir.cc").lifted(scope, match(ip, "^[^/]+"))
  end
end

-- ---------------------------------------------------------------------
-- Accounting: #live and the per-minute expiry buckets.

local SEQ_ZERO = string.rep("0", 20)

local function ensure(dict)
  dict:safe_add("#seq", SEQ_ZERO)
  dict:safe_add("#unapplied_more", 0)
  dict:safe_add("#live", 0)
  dict:safe_add("#evicted", 0)
  dict:safe_add("#aid", 0)
  dict:safe_add("#ver", 0)
end

local function account(dict, expires, n)
  local k = "#x|" .. floor(expires / 60)
  if n > 0 then
    local ok, err = dict:safe_add(k, 0)
    if not ok and err ~= "exists" then
      return nil, err
    end
  end
  if dict:incr(k, n) then
    dict:incr("#live", n)
  end
  return true
end

-- recount rebuilds #live and the buckets from the bans held.
local function recount(dict, now)
  local keys = dict:get_keys(0)
  local buckets, total = {}, 0
  for i = 1, #keys do
    local k = keys[i]
    if sub(k, 1, 3) == "#x|" then
      dict:delete(k)
    elseif sub(k, 1, 2) == "e|" then
      local v = dict:get(k)
      local kind, _, expires = parse_value(v)
      if kind and expires then
        local m = floor(expires / 60)
        buckets[m] = (buckets[m] or 0) + 1
        total = total + 1
      end
    end
  end
  for m, n in pairs(buckets) do
    dict:safe_set("#x|" .. m, n)
  end
  dict:safe_set("#live", total)
  dict:safe_set("#swept", floor(now / 60) - 1)
end

-- sweep subtracts the buckets of the minutes that are over. Without a
-- previous sweep (or after a long pause) it counts the bans instead.
local function sweep(dict, now)
  local cur = floor(now / 60) - 1
  local swept = dict:get("#swept")
  if swept and swept >= cur then
    return
  end
  if not dict:safe_add("#sweeping", true, 10) then
    return
  end
  -- Buckets are at most 7 days ahead of the write that created them.
  if not swept or cur - swept > 20160 then
    recount(dict, now)
  else
    for m = swept + 1, cur do
      local k = "#x|" .. m
      local n = dict:get(k)
      if n then
        dict:delete(k)
        if n ~= 0 then
          dict:incr("#live", -n)
        end
      end
    end
    dict:safe_set("#swept", cur)
  end
  dict:delete("#sweeping")
end

local function live(dict, now)
  sweep(dict, now)
  return dict:get("#live") or 0
end

-- evict_one drops the oldest own ban that is still held. Queue items of
-- bans that expired or were overwritten are skipped.
local function evict_one(dict, now)
  while true do
    local item = dict:lpop("#q")
    if not item then
      return false
    end
    local p1 = find(item, "|", 1, true)
    local p2 = p1 and find(item, "|", p1 + 1, true)
    if p2 and (tonumber(sub(item, 1, p1 - 1)) or 0) > now then
      local id, key = sub(item, p1 + 1, p2 - 1), sub(item, p2 + 1)
      local v = dict:get(key)
      if v then
        local kind, vid, vexp = parse_value(v)
        if kind == "a" and vid == id then
          dict:delete(key)
          if vexp then
            account(dict, vexp, -1)
          end
          dict:incr("#evicted", 1)
          return true
        end
      end
    end
  end
end

-- trim drops a few queue items at the head whose ban has expired or was
-- replaced, so the queue does not outgrow the own bans it tracks.
local function trim(dict, now)
  for _ = 1, 4 do
    local item = dict:lpop("#q")
    if not item then
      return
    end
    local p1 = find(item, "|", 1, true)
    local p2 = p1 and find(item, "|", p1 + 1, true)
    if p2 and (tonumber(sub(item, 1, p1 - 1)) or 0) > now then
      local kind, id = parse_value(dict:get(sub(item, p2 + 1)))
      if kind == "a" and id == sub(item, p1 + 1, p2 - 1) then
        dict:lpush("#q", item) -- still held: it stays the oldest
        return
      end
    end
  end
end

-- with_room runs f until it does not fail for lack of memory, evicting an
-- own ban before every retry.
local function with_room(dict, now, f)
  while true do
    local ok, err = f()
    if ok then
      return true
    end
    if err ~= "no memory" then
      return nil, err
    end
    if not evict_one(dict, now) then
      return nil, "full"
    end
  end
end

-- store writes one ban. A new key needs room below the capacity; either
-- way own bans are evicted, oldest first, when room or memory runs out.
-- Returns true, or nil and "full" / "expired" / an error.
local function store(dict, key, value, expires, now)
  local ttl = expires - now
  if ttl <= 0 then
    return nil, "expired"
  end
  local old = dict:get(key)
  if not old then
    while live(dict, now) >= _M.capacity do
      if not evict_one(dict, now) then
        return nil, "full"
      end
    end
  end
  local ok, err = with_room(dict, now, function()
    return account(dict, expires, 1)
  end)
  if not ok then
    return nil, err
  end
  ok, err = with_room(dict, now, function()
    return dict:safe_set(key, value, ttl)
  end)
  if not ok then
    account(dict, expires, -1)
    return nil, err
  end
  if old then
    local _, _, oexp = parse_value(old)
    if oexp then
      account(dict, oexp, -1)
    end
  end
  return true
end

-- ---------------------------------------------------------------------
-- Console bans.

-- entry validates a ban of the control API:
-- {id, cidr, scope = "platform" | "site", site_id, kind = "m" | "c", expires_at}
-- (kind and expires_at are not needed to remove a ban).
local function entry(b, removal)
  if type(b) ~= "table" then
    return nil, "ban must be an object"
  end
  if not valid_id(b.id) then
    return nil, "invalid id"
  end
  local scope
  if b.scope == "platform" then
    scope = PLATFORM
  elseif b.scope == "site" then
    if not valid_id(b.site_id) then
      return nil, "invalid site_id"
    end
    scope = b.site_id
  else
    return nil, "invalid scope"
  end
  local p = ipaddr.parse_prefix(b.cidr)
  if not p then
    return nil, "invalid cidr"
  end
  if p.len < ((#p.bytes == 4) and 16 or 48) then
    return nil, "prefix too short"
  end
  local e = { id = b.id, scope = scope, key = key_for(scope, p.bytes, p.len),
    length = ((#p.bytes == 4) and "4/" or "6/") .. p.len }
  if removal then
    return e
  end
  if b.kind ~= "m" and b.kind ~= "c" then
    return nil, "invalid kind"
  end
  local expires = tonumber(b.expires_at)
  if not expires then
    return nil, "invalid expires_at"
  end
  e.kind, e.expires = b.kind, expires
  e.value = b.kind .. "|" .. b.id .. "|" .. tostring(expires) .. "|" .. b.cidr
  return e
end

local function entries(list, removal)
  if list == nil or list == cjson.null then
    return {}
  end
  if type(list) ~= "table" then
    return nil, "must be an array"
  end
  local out = {}
  for i = 1, #list do
    local e, err = entry(list[i], removal)
    if not e then
      return nil, "#" .. i .. ": " .. err
    end
    out[i] = e
  end
  return out
end

local function sequence(v)
  if type(v) == "number" and v >= 0 and v == floor(v) then
    v = string.format("%d", v)
  end
  if type(v) ~= "string" or not match(v, "^%d+$") or #v > 20 then
    return nil
  end
  return (v:gsub("^0+(%d)", "%1"))
end

local function lock(dict)
  local ok, err = with_room(dict, _M.clock(), function()
    return dict:safe_add("#lock", true, 30)
  end)
  if not ok then
    if err == "exists" then
      return nil, "another ban update is in progress", 409
    end
    return nil, "lock: " .. tostring(err), 500
  end
  return true
end

local function unapplied(dict)
  local m = cjson.decode(dict:get("#unapplied") or "{}")
  return type(m) == "table" and m or {}, dict:get("#unapplied_more") or 0
end

-- save_unapplied stores the unapplied manual bans: by id as far as memory
-- allows (at most 1000), the rest only counted. The agent replaces the
-- whole set when not every unapplied ban is listed, which starts the
-- count over.
local function save_unapplied(dict, m, more, now)
  local ids = {}
  for id, expires in pairs(m) do
    if type(expires) == "number" and expires > now then
      ids[#ids + 1] = id
    else
      m[id] = nil
    end
  end
  table.sort(ids)
  for _, limit in ipairs({ 1000, UNAPPLIED_IDS, 0 }) do
    for i = #ids, limit + 1, -1 do
      m[ids[i]] = nil
      ids[i] = nil
      more = more + 1
    end
    if #ids == 0 then
      dict:delete("#unapplied")
      break
    end
    local raw = cjson.encode(m)
    if with_room(dict, now, function()
      return dict:safe_set("#unapplied", raw)
    end) then
      break
    end
  end
  dict:safe_set("#unapplied_more", math.max(more, 0))
  return true
end

local function padded(seq)
  return string.rep("0", 20 - #seq) .. seq
end

local function current_sequence(dict)
  return sequence(dict:get("#seq") or "0") or "0"
end

-- add_length records a console prefix length of scope (under the lock).
local function add_length(dict, now, scope, length)
  local k = "#len|" .. scope
  local cur = dict:get(k)
  if cur and find("," .. cur .. ",", "," .. length .. ",", 1, true) then
    return true
  end
  local ok, err = with_room(dict, now, function()
    return dict:safe_set(k, cur and (cur .. "," .. length) or length)
  end)
  if ok then
    dict:incr("#ver", 1)
  end
  return ok, err
end

-- write stores console bans in order; bans that do not fit are recorded
-- (manual) or counted (automatic). lengths collects the stored lengths per
-- scope when given.
local function write(dict, list, now, un, lengths)
  for i = 1, #list do
    local e = list[i]
    local ok, err = store(dict, e.key, e.value, e.expires, now)
    if ok then
      un[e.id] = nil
      if lengths then
        local set = lengths[e.scope] or {}
        lengths[e.scope] = set
        set[e.length] = true
      else
        ok, err = add_length(dict, now, e.scope, e.length)
      end
    end
    if not ok and err ~= "expired" then
      if err ~= "full" then
        return nil, err
      end
      if e.kind == "m" then
        un[e.id] = e.expires
      else
        dict:incr("#evicted", 1)
      end
    end
  end
  return true
end

-- status reports the set (never walks the dict unless list is set).
function _M.status(list)
  local dict = shdict()
  local now = _M.clock()
  local held = live(dict, now)
  local ids, n = {}, 0
  local un, more = unapplied(dict)
  for id, expires in pairs(un) do
    if type(expires) == "number" and expires > now then
      n = n + 1
      ids[#ids + 1] = id
    end
  end
  table.sort(ids)
  for i = #ids, UNAPPLIED_IDS + 1, -1 do
    ids[i] = nil
  end
  local st = {
    sequence = current_sequence(dict),
    entries = math.max(held, 0),
    capacity = _M.capacity,
    unapplied = n + more,
    unapplied_ids = setmetatable(ids, cjson.array_mt),
    auto_evicted = dict:get("#evicted") or 0,
    pending_reports = dict:llen("#r") or 0,
  }
  if list then
    local out = {}
    local keys = dict:get_keys(0)
    for i = 1, #keys do
      local k = keys[i]
      if sub(k, 1, 2) == "e|" then
        local v = dict:get(k)
        local kind, id, expires, cidr = parse_value(v)
        if kind then
          local scope = sub(k, 3, find(k, "|", 3, true) - 1)
          out[#out + 1] = {
            id = id, kind = kind, cidr = cidr, expires_at = expires,
            scope = scope == PLATFORM and "platform" or "site",
            site_id = scope ~= PLATFORM and scope or nil,
          }
          if #out >= LIST_MAX then
            break
          end
        end
      end
    end
    st.bans = setmetatable(out, cjson.array_mt)
  end
  return st
end

-- replace installs exactly the given console set (own bans stay):
-- doc = {sequence, bans = [...]} with the bans in priority order (manual
-- first, then automatic from the newest). Returns the status, or nil, an
-- error and an HTTP status.
function _M.replace(doc)
  if type(doc) ~= "table" then
    return nil, "document must be an object", 400
  end
  local seq = sequence(doc.sequence)
  if not seq then
    return nil, "invalid sequence", 400
  end
  local list, err = entries(doc.bans, false)
  if not list then
    return nil, "bans " .. err, 400
  end
  local dict = shdict()
  local ok, lerr, code = lock(dict)
  if not ok then
    return nil, lerr, code
  end
  ensure(dict)
  local now = _M.clock()
  local wanted, keep = {}, {}
  for i = 1, #list do
    local e = list[i]
    if not wanted[e.key] and e.expires > now then
      wanted[e.key] = true
      keep[#keep + 1] = e
    end
  end
  -- Console bans that are not in the new set go first (they make room);
  -- bans in both sets are overwritten in place and never missing.
  local all = dict:get_keys(0)
  local old_lengths = {}
  for i = 1, #all do
    local k = all[i]
    local prefix = sub(k, 1, 2)
    if prefix == "e|" and not wanted[k] then
      local v = dict:get(k)
      local kind, _, expires, cidr = parse_value(v)
      if kind and kind ~= "a" then
        dict:delete(k)
        if expires then
          account(dict, expires, -1)
        end
        if kind == "c" then
          lifted(sub(k, 3, find(k, "|", 3, true) - 1), cidr)
        end
      end
    elseif sub(k, 1, 5) == "#len|" then
      old_lengths[#old_lengths + 1] = k
    end
  end
  local un, lengths = {}, {}
  local wok, werr = write(dict, keep, now, un, lengths)
  if wok then
    local seen = {}
    for scope, set in pairs(lengths) do
      local items = {}
      for length in pairs(set) do
        items[#items + 1] = length
      end
      table.sort(items)
      local k = "#len|" .. scope
      seen[k] = true
      wok, werr = with_room(dict, now, function()
        return dict:safe_set(k, concat(items, ","))
      end)
      if not wok then
        break
      end
    end
    for i = 1, #old_lengths do
      if not seen[old_lengths[i]] then
        dict:delete(old_lengths[i])
      end
    end
    dict:incr("#ver", 1)
  end
  if wok then
    wok, werr = save_unapplied(dict, un, 0, now)
  end
  if wok then
    wok, werr = with_room(dict, now, function()
      return dict:safe_set("#seq", padded(seq))
    end)
  end
  -- A full replacement also corrects the counters.
  if dict:safe_add("#sweeping", true, 10) then
    recount(dict, now)
    dict:delete("#sweeping")
  end
  dict:delete("#lock")
  if not wok then
    return nil, "shared dict edgeweir_bans: " .. tostring(werr), 500
  end
  return _M.status()
end

-- add applies a delta on top of sequence base:
-- doc = {base, sequence, remove = [...], upsert = [...]}. A data plane at
-- another sequence answers 409 (the agent then replaces the whole set).
-- Removals only delete a console ban held under the same id.
function _M.add(doc)
  if type(doc) ~= "table" then
    return nil, "document must be an object", 400
  end
  local base, seq = sequence(doc.base), sequence(doc.sequence)
  if not base or not seq then
    return nil, "invalid base or sequence", 400
  end
  local upsert, err = entries(doc.upsert, false)
  if not upsert then
    return nil, "upsert " .. err, 400
  end
  local remove
  remove, err = entries(doc.remove, true)
  if not remove then
    return nil, "remove " .. err, 400
  end
  local dict = shdict()
  local ok, lerr, code = lock(dict)
  if not ok then
    return nil, lerr, code
  end
  local current = current_sequence(dict)
  if current ~= base then
    dict:delete("#lock")
    return nil, "sequence mismatch: the data plane holds " .. current, 409
  end
  ensure(dict)
  local now = _M.clock()
  local un, more = unapplied(dict)
  for i = 1, #remove do
    local e = remove[i]
    un[e.id] = nil
    local v = dict:get(e.key)
    local kind, id, expires, cidr = parse_value(v)
    if kind and kind ~= "a" and id == e.id then
      dict:delete(e.key)
      if expires then
        account(dict, expires, -1)
      end
      if kind == "c" then
        lifted(e.scope, cidr)
      end
    end
  end
  local wok, werr = write(dict, upsert, now, un, nil)
  if wok then
    wok, werr = save_unapplied(dict, un, more, now)
  end
  if wok then
    wok, werr = with_room(dict, now, function()
      return dict:safe_set("#seq", padded(seq))
    end)
  end
  dict:delete("#lock")
  if not wok then
    return nil, "shared dict edgeweir_bans: " .. tostring(werr), 500
  end
  return _M.status()
end

-- ---------------------------------------------------------------------
-- The node's own bans.

-- own_network returns the text, masked bytes and length of what an own ban
-- of client holds: an IPv4 address (/32) or an IPv6 /64. client is an
-- address (an IPv6 one stands for its /64) or such a prefix
-- ("2001:db8:1:2::/64"; "/128" from older reports is taken as given).
local function own_network(client)
  if not find(client or "", "/", 1, true) then
    local text, bytes, len = ipaddr.client_network(client)
    if not text then
      return nil
    end
    return match(text, "^[^/]+"), bytes, len
  end
  local p = ipaddr.parse_prefix(client)
  if not p or not (p.len == 32 and #p.bytes == 4) and not (#p.bytes == 16 and (p.len == 64 or p.len == 128)) then
    return nil
  end
  if p.len == 64 then
    for i = 9, 16 do
      p.bytes[i] = 0
    end
  end
  return ipaddr.format(p.bytes), p.bytes, p.len
end

-- protected reports networks the node never bans on its own: loopback and
-- unspecified IPv4 addresses and ::/64 (::1, ::), the node's own traffic.
local function protected(bytes)
  if #bytes == 4 then
    return bytes[1] == 127 or (bytes[1] == 0 and bytes[2] == 0 and bytes[3] == 0 and bytes[4] == 0)
  end
  for i = 1, 8 do
    if bytes[i] ~= 0 then
      return false
    end
  end
  return true
end

-- add_auto bans a client on a site (site_id "*": every site, the
-- platform scope of scan protection) for ttl seconds and queues it for
-- reporting: an IPv4 address or an IPv6 /64 (see own_network). trigger =
-- {reason, metric, observed, threshold, window_seconds}. A network a
-- console ban already holds is only reported; loopback and unspecified
-- ones are refused. Returns true, or nil and an error ("full" when no room
-- is left without evicting a console ban).
function _M.add_auto(site_id, client, ttl, trigger)
  if site_id ~= PLATFORM and not valid_id(site_id) then
    return nil, "invalid site id"
  end
  local ip, bytes, len = own_network(client)
  if not ip then
    return nil, "invalid address"
  end
  if protected(bytes) then
    return nil, "protected address"
  end
  ttl = tonumber(ttl)
  if not ttl or ttl < 1 or ttl > MAX_TTL then
    return nil, "invalid ttl"
  end
  if type(trigger) ~= "table" then
    trigger = {}
  end
  local dict = shdict()
  ensure(dict)
  local now = _M.clock()
  local key = key_for(site_id, bytes, len)
  local expires = now + ttl
  local rec = cjson.encode({
    site_id = site_id, ip = ip, prefix_len = len, created_at = now, expires_at = expires,
    reason = type(trigger.reason) == "string" and sub(trigger.reason, 1, 64) or "cc_ip_rate",
    metric = type(trigger.metric) == "string" and sub(trigger.metric, 1, 64) or "",
    observed = tonumber(trigger.observed) or 0, threshold = tonumber(trigger.threshold) or 0,
    window_seconds = floor(tonumber(trigger.window_seconds) or 0),
  })
  local result, err = true, nil
  local old = dict:get(key)
  local kind, _, oexp = parse_value(old)
  if not kind or kind == "a" then
    if oexp and oexp > expires then
      expires = oexp
    end
    if dict:safe_add("#loc|" .. site_id, true) then
      dict:incr("#ver", 1)
    end
    trim(dict, now)
    local id = "local-" .. tostring(dict:incr("#aid", 1))
    local value = "a|" .. id .. "|" .. tostring(expires) .. "|" .. ip .. "/" .. len
    result, err = store(dict, key, value, expires, now)
    if result then
      with_room(dict, now, function()
        return dict:rpush("#q", tostring(expires) .. "|" .. id .. "|" .. key)
      end)
    else
      dict:incr("#evicted", 1)
    end
  end
  if rec then
    if (dict:llen("#r") or 0) >= REPORT_MAX then
      dict:lpop("#r")
    end
    dict:rpush("#r", rec)
  end
  return result, err
end

-- release deletes own bans the console lifted:
-- list = [{site_id ("*" for a platform one), cidr, expires_at}], IPv4
-- addresses or IPv6 /64 (or
-- /128 of older own bans). An own ban there
-- is deleted only if it expires no later than expires_at (one second of
-- slack for rounding): an own ban of the address made after the lift
-- lasts longer and stays. Console bans are not touched. CC counts the
-- address of a deleted ban afresh. Returns how many were deleted, or nil,
-- an error and a status.
function _M.release(list)
  if type(list) ~= "table" then
    return nil, "bans must be an array", 400
  end
  local items = {}
  for i = 1, #list do
    local b = list[i]
    if type(b) ~= "table" or (b.site_id ~= PLATFORM and not valid_id(b.site_id)) then
      return nil, "#" .. i .. ": invalid site_id", 400
    end
    local ip, bytes, len = own_network(type(b.cidr) == "string" and find(b.cidr, "/", 1, true) and b.cidr or "")
    if not ip then
      return nil, "#" .. i .. ": invalid cidr", 400
    end
    local expires = tonumber(b.expires_at)
    if not expires then
      return nil, "#" .. i .. ": invalid expires_at", 400
    end
    items[i] = { key = key_for(b.site_id, bytes, len), expires = expires, scope = b.site_id, ip = ip }
  end
  local dict = shdict()
  local ok, lerr, code = lock(dict)
  if not ok then
    return nil, lerr, code
  end
  local n = 0
  for i = 1, #items do
    local kind, _, expires = parse_value(dict:get(items[i].key))
    if kind == "a" and expires and expires <= items[i].expires + 1 then
      dict:delete(items[i].key)
      account(dict, expires, -1)
      n = n + 1
      lifted(items[i].scope, items[i].ip)
    end
  end
  dict:delete("#lock")
  return n
end

-- drain returns and removes up to max (default 1000) queued own bans.
function _M.drain(max)
  local dict = shdict()
  local out = {}
  for _ = 1, max or 1000 do
    local raw = dict:lpop("#r")
    if not raw then
      break
    end
    local rec = cjson.decode(raw)
    if type(rec) == "table" then
      out[#out + 1] = rec
    end
  end
  return setmetatable(out, cjson.array_mt)
end

-- ---------------------------------------------------------------------
-- Lookup.

local cache_ver, cache = nil, {}

local function add_len(lens, fam, len)
  local l = lens[fam]
  if not l then
    l = {}
    lens[fam] = l
  end
  for i = 1, #l do
    if l[i] == len then
      return
    end
  end
  l[#l + 1] = len
end

-- lengths returns {["4"] = {...}, ["6"] = {...}} for scope, or false.
local function lengths(dict, scope)
  local c = cache[scope]
  if c ~= nil then
    return c
  end
  local s = dict:get("#len|" .. scope)
  local own = dict:get("#loc|" .. scope)
  c = false
  if s or own then
    c = {}
    for fam, len in string.gmatch(s or "", "([46])/(%d+)") do
      add_len(c, fam, tonumber(len))
    end
    if own then
      add_len(c, "4", 32)
      add_len(c, "6", 64)
    end
  end
  cache[scope] = c
  return c
end

local function lookup(dict, scope, lens, bytes)
  local list = lens[(#bytes == 4) and "4" or "6"]
  if not list then
    return nil
  end
  for i = 1, #list do
    local v = dict:get(key_for(scope, bytes, list[i]))
    if v then
      return v
    end
  end
  return nil
end

-- forget drops the worker's cached prefix lengths (tests flush the dict,
-- which nginx itself never does).
function _M.forget()
  cache, cache_ver = {}, nil
end

-- mapped returns the IPv4 address of an IPv4-mapped IPv6 address.
local function mapped(a)
  if #a ~= 16 or a[11] ~= 0xff or a[12] ~= 0xff then
    return nil
  end
  for i = 1, 10 do
    if a[i] ~= 0 then
      return nil
    end
  end
  return { a[13], a[14], a[15], a[16] }
end

-- match returns the kind and id of the ban holding addr on site_id
-- (platform bans first), or nil. addr may be a function returning the
-- address: it is only called when a scope has bans.
function _M.match(site_id, addr)
  local dict = shdict()
  local ver = dict and dict:get("#ver")
  if not ver then
    return nil
  end
  if ver ~= cache_ver then
    cache, cache_ver = {}, ver
  end
  local pl = lengths(dict, PLATFORM)
  local sl = site_id and lengths(dict, site_id)
  if not pl and not sl then
    return nil
  end
  if type(addr) == "function" then
    addr = addr()
  end
  local bytes = ipaddr.parse(addr)
  if not bytes then
    return nil
  end
  local v4 = mapped(bytes)
  local v
  if pl then
    v = lookup(dict, PLATFORM, pl, bytes) or (v4 and lookup(dict, PLATFORM, pl, v4))
  end
  if not v and sl then
    v = lookup(dict, site_id, sl, bytes) or (v4 and lookup(dict, site_id, sl, v4))
  end
  if not v then
    return nil
  end
  local kind, id = parse_value(v)
  return kind, id
end

return _M
