-- Session affinity cookies (edgeweir.affinity), the active health store
-- and its merge with the passive check (edgeweir.health), and origin
-- selection with both (edgeweir.lb).
--
--   resty -I lua --shdict 'edgeweir_challenge 1m' --shdict 'edgeweir_health 1m' test/lua/origins.lua
local affinity = require("edgeweir.affinity")
local challenge = require("edgeweir.challenge")
local health = require("edgeweir.health")
local lb = require("edgeweir.lb")

local passed, failed = 0, 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    print("ok   " .. name)
  else
    failed = failed + 1
    print("FAIL " .. name .. ": " .. tostring(err))
  end
end

local function eq(got, want, msg)
  if got ~= want then
    error((msg or "value") .. ": got " .. tostring(got) .. ", want " .. tostring(want), 2)
  end
end

local function install(current, ids)
  local keys = {}
  for _, id in ipairs(ids) do
    keys[#keys + 1] = { id = id, secret = ngx.encode_base64("secret of " .. id .. " (32 bytes ok)") }
  end
  assert(challenge.replace_keys({ id = table.concat(ids, "+"), current = current, keys = keys }))
  return challenge.keys()
end

local NOW = 1800000000

-- ---------------------------------------------------------------------
-- Affinity cookies

test("affinity: sign and verify", function()
  local keys = install("k2", { "k1", "k2", "k3" })
  local value = affinity.sign(keys.current, "site-a", "o-1", NOW + 3600)
  local origin, exp = value:match("^([^.]+)%.(%d+)%.")
  eq(origin, "o-1")
  eq(tonumber(exp), NOW + 3600)
  assert(value:match("^o%-1%.1800003600%.k2%.[A-Za-z0-9_-]+$"), value)
  assert(not value:find("=", 1, true), "base64url without padding")
  local o, e = affinity.verify(keys, "site-a", value, NOW)
  eq(o, "o-1")
  eq(e, NOW + 3600)
  -- The signature: HMAC-SHA256(secret, "affinity|<site>|<origin>|<exp>").
  local hmac = require("resty.openssl.hmac")
  local mac = assert(hmac.new(keys.by_id.k2.secret, "sha256")):final("affinity|site-a|o-1|1800003600")
  eq(value, "o-1.1800003600.k2." .. require("ngx.base64").encode_base64url(mac))
end)

test("affinity: tampered, other site, expired and malformed cookies are refused", function()
  local keys = install("k2", { "k1", "k2", "k3" })
  local value = affinity.sign(keys.current, "site-a", "o-1", NOW + 3600)
  local function refused(v, site, why)
    local o, reason = affinity.verify(keys, site or "site-a", v, NOW)
    eq(o, nil, why)
    return reason
  end
  eq(refused(value:gsub("^o%-1", "o-2"), nil, "other origin"), "bad signature")
  eq(refused(value:gsub("%.1800003600%.", ".1800009999."), nil, "longer lifetime"), "bad signature")
  local last = value:sub(-1)
  eq(refused(value:sub(1, -2) .. (last == "A" and "B" or "A"), nil, "signature"), "bad signature")
  eq(refused(value, "site-b", "another site"), "bad signature")
  eq(refused(affinity.sign(keys.current, "site-a", "o-1", NOW), nil, "expired now"), "expired")
  eq(refused(affinity.sign(keys.current, "site-a", "o-1", NOW - 1), nil, "expired"), "expired")
  for _, bad in ipairs({ "", "o-1", "o-1.123.k2", "o 1.1.k2.sig", "o-1.12x.k2.sig", "o-1.1.k2.sig.extra",
    "o-1.1234567890123.k2.sig", string.rep("a", 600), 42 }) do
    eq(refused(bad, nil, tostring(bad)), "malformed")
  end
  eq(select(2, affinity.verify(nil, "site-a", value, NOW)), "unknown key", "no keys")
end)

test("affinity: rotated keys still verify, removed ones do not", function()
  local keys = install("k2", { "k1", "k2", "k3" })
  local old = affinity.sign(keys.current, "site-a", "o-1", NOW + 3600)
  -- Daily rotation: k3 signs now, k2 is the previous key.
  keys = install("k3", { "k2", "k3", "k4" })
  eq(affinity.verify(keys, "site-a", old, NOW), "o-1", "signed with the previous key")
  local new = affinity.sign(keys.current, "site-a", "o-1", NOW + 3600)
  assert(new:find(".k3.", 1, true))
  -- Another rotation drops k2.
  keys = install("k4", { "k3", "k4", "k5" })
  local o, why = affinity.verify(keys, "site-a", old, NOW)
  eq(o, nil)
  eq(why, "unknown key")
  eq(affinity.verify(keys, "site-a", new, NOW), "o-1")
end)

test("affinity: when the origin layer announces a new cookie", function()
  eq(affinity.renew(nil, nil, "o1", 3600, NOW), true, "no valid pin")
  eq(affinity.renew("o1", NOW + 3000, "o2", 3600, NOW), true, "another origin answered")
  eq(affinity.renew("o1", NOW + 3000, "o1", 3600, NOW), false, "pinned origin answered, plenty left")
  eq(affinity.renew("o1", NOW + 1799, "o1", 3600, NOW), true, "less than half of the lifetime left")
  eq(affinity.renew("o1", NOW + 1800, "o1", 3600, NOW), false, "exactly half left")
end)

test("affinity: Set-Cookie value and appending to the origin's cookies", function()
  eq(affinity.cookie("o1.1.k.s", 3600, false), "__ew_affinity=o1.1.k.s; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax")
  eq(affinity.cookie("o1.1.k.s", 60, true), "__ew_affinity=o1.1.k.s; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; Secure")
  eq(affinity.valid_value("o-1.1800003600.k2.AbC_-9"), true)
  eq(affinity.valid_value("o1; Domain=evil.test"), false)
  eq(affinity.valid_value("o1\r\nX: y"), false)
  eq(affinity.valid_value(""), false)
  local h = {}
  affinity.append_cookie(h, "a=1")
  eq(h["Set-Cookie"], "a=1")
  affinity.append_cookie(h, "b=2")
  eq(table.concat(h["Set-Cookie"], "|"), "a=1|b=2")
  affinity.append_cookie(h, "c=3")
  eq(table.concat(h["Set-Cookie"], "|"), "a=1|b=2|c=3")
end)

-- ---------------------------------------------------------------------
-- Active health store

local d = ngx.shared.edgeweir_health

test("active marks: replace validates and installs the full set", function()
  local function refused(doc, code)
    local res, err, status = health.replace_active(doc)
    eq(res, nil)
    eq(status, code or 400, tostring(err))
  end
  refused("x")
  refused({ down = {} }, 400)
  refused({ ttl = 0, down = {} })
  refused({ ttl = 86401, down = {} })
  refused({ ttl = 1.5, down = {} })
  refused({ ttl = 90, down = "x" })
  refused({ ttl = 90, down = { { site_id = "s|x", origin_id = "o" } } })
  refused({ ttl = 90, down = { { site_id = "s", origin_id = "" } } })
  refused({ ttl = 90, down = { { site_id = "s", origin_id = string.rep("o", 129) } } })
  local res = assert(health.replace_active({ ttl = 90, down = {
    { site_id = "s1", origin_id = "o1" }, { site_id = "s1", origin_id = "o1" }, { site_id = "s2", origin_id = "o2" },
  } }))
  eq(res.down, 2, "duplicates count once")
  eq(d:get("a|s1|o1"), true)
  eq(d:get("a|s2|o2"), true)
  res = assert(health.replace_active({ ttl = 90, down = { { site_id = "s2", origin_id = "o2" }, { site_id = "s3", origin_id = "o3" } } }))
  eq(res.down, 2)
  eq(d:get("a|s1|o1"), nil, "an origin that recovered loses its mark")
  eq(d:get("a|s3|o3"), true)
  res = assert(health.replace_active({ ttl = 90, down = {} }))
  eq(res.down, 0)
  eq(d:get("a|s2|o2"), nil)
  eq(d:get("a|s3|o3"), nil)
  assert(health.replace_active({ ttl = 90 }), "no down list: none")
  -- Passive reporting never lists active marks.
  assert(health.replace_active({ ttl = 90, down = { { site_id = "s1", origin_id = "o1" } } }))
  eq(#health.report(NOW), 0)
  assert(health.replace_active({ ttl = 90, down = {} }))
end)

test("active marks expire after their ttl", function()
  assert(health.replace_active({ ttl = 1, down = { { site_id = "t", origin_id = "o" } } }))
  eq(health.is_down("t", "o", nil, true), true)
  ngx.sleep(1.1)
  eq(health.is_down("t", "o", nil, true), false, "an agent that stopped pushing leaves no marks behind")
end)

test("is_down merges the passive and the active check", function()
  local now = ngx.now()
  assert(health.replace_active({ ttl = 90, down = { { site_id = "m", origin_id = "a" } } }))
  eq(health.is_down("m", "a", now, true), true, "active mark, site with active checks")
  eq(health.is_down("m", "a", now, false), false, "active marks only count for sites with active checks")
  eq(health.is_down("m", "a", now), false)
  -- Passive down: down whatever the active check says.
  for _ = 1, 3 do health.failure("m", "p", "connect failed", 3, 30, now, "connect_failed") end
  eq(health.is_down("m", "p", now, true), true)
  eq(health.is_down("m", "p", now, false), true)
  eq(health.is_down("m", "p", now + 31, true), false, "passive marks last until their recovery time")
  health.success("m", "p")
  assert(health.replace_active({ ttl = 90, down = {} }))
end)

-- ---------------------------------------------------------------------
-- Selection

local function site(id, policy, active)
  local s = { id = id, load_balance = policy or "weighted_random", _active = active }
  s._primaries = {
    { id = "p1", weight = 1 }, { id = "p2", weight = 1 }, { id = "p3", weight = 1 },
  }
  s._backups = { { id = "b1", weight = 1 }, { id = "b2", weight = 1 } }
  return s
end

local function ids(list)
  local out = {}
  for i = 1, #list do out[i] = list[i].id end
  return table.concat(out, ",")
end

test("lb: actively down origins take no traffic on sites with active checks", function()
  local now = ngx.now()
  assert(health.replace_active({ ttl = 90, down = { { site_id = "lb1", origin_id = "p1" }, { site_id = "lb1", origin_id = "p2" } } }))
  for _ = 1, 20 do
    eq(ids(lb.order(site("lb1", nil, true), "/x", now)), "p3")
  end
  local out = lb.order(site("lb1", nil, false), "/x", now)
  eq(#out, 3, "without active checks the marks are ignored")
  -- Every primary down (active or passive): backups.
  for _ = 1, 3 do health.failure("lb1", "p3", "timeout", 3, 30, now, "timeout") end
  out = lb.order(site("lb1", nil, true), "/x", now)
  eq(#out, 2)
  assert(out[1].id:sub(1, 1) == "b" and out[2].id:sub(1, 1) == "b", ids(out))
  health.success("lb1", "p3")
  assert(health.replace_active({ ttl = 90, down = {} }))
end)

test("lb: a valid pin goes first while it is eligible", function()
  local now = ngx.now()
  for _, policy in ipairs({ "weighted_random", "round_robin", "consistent_hash" }) do
    local s = site("pin-" .. policy, policy, true)
    for _ = 1, 10 do
      local out = lb.order(s, "/path", now, "p2")
      eq(out[1].id, "p2", policy)
      eq(#out, 3, policy .. ": the others follow")
    end
    eq(#lb.order(s, "/path", now, "gone"), 3, policy .. ": unknown pin, normal order")
    eq(lb.order(s, "/path", now, "b1")[1].id:sub(1, 1), "p", policy .. ": a backup pin while primaries are up")
  end
  -- A pinned origin that went down is replaced.
  assert(health.replace_active({ ttl = 90, down = { { site_id = "pin-down", origin_id = "p2" } } }))
  local s = site("pin-down", nil, true)
  for _ = 1, 10 do
    local out = lb.order(s, "/path", now, "p2")
    assert(out[1].id ~= "p2" and #out == 2, ids(out))
  end
  -- Primaries down: a backup pin goes first among the backups.
  assert(health.replace_active({ ttl = 90, down = {
    { site_id = "pin-down", origin_id = "p1" }, { site_id = "pin-down", origin_id = "p2" }, { site_id = "pin-down", origin_id = "p3" },
  } }))
  for _ = 1, 10 do
    eq(ids(lb.order(s, "/path", now, "b2")), "b2,b1")
  end
  -- Everything down: no pin, primaries first (fail open).
  assert(health.replace_active({ ttl = 90, down = {
    { site_id = "pin-down", origin_id = "p1" }, { site_id = "pin-down", origin_id = "p2" }, { site_id = "pin-down", origin_id = "p3" },
    { site_id = "pin-down", origin_id = "b1" }, { site_id = "pin-down", origin_id = "b2" },
  } }))
  local out = lb.order(s, "/path", now, "b2")
  eq(out[1].id:sub(1, 1), "p", "fail open ignores the pin")
  assert(health.replace_active({ ttl = 90, down = {} }))
end)

test("lb: pinned requests leave the round-robin state to the others", function()
  local now = ngx.now()
  local s = site("rr", "round_robin", false)
  local first = {}
  for i = 1, 6 do first[i] = lb.order(s, "/", now)[1].id end
  local t = site("rr2", "round_robin", false)
  for i = 1, 6 do
    lb.order(t, "/", now, "p3")
    eq(lb.order(t, "/", now)[1].id, first[i], "pinned requests in between")
  end
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
