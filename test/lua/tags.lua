-- Tag purges: tag markers (edgeweir.purge), the Cache-Tag parser and the
-- key-epoch index (edgeweir.cachetags).
--
--   resty -I lua --shdict 'edgeweir_purge 4m' --shdict 'edgeweir_tags 1m' test/lua/tags.lua
local purge = require("edgeweir.purge")
local cachetags = require("edgeweir.cachetags")
local cachekey = require("edgeweir.cachekey")

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

local function list(t)
  return table.concat(t, ",")
end

local tags_dict = ngx.shared.edgeweir_tags
local purge_dict = ngx.shared.edgeweir_purge

local function reset()
  tags_dict:flush_all()
  tags_dict:flush_expired()
  assert(purge.replace({ id = "empty", markers = {} }))
end

-- ---------------------------------------------------------------------
-- Tag markers

test("tag markers: entries, counters and the site's highest tag epoch", function()
  reset()
  local st = assert(purge.replace({ id = "t1", markers = {
    { site_id = "s1", type = "tag", tag = "product-42", epoch = 100 },
    { site_id = "s1", type = "tag", tag = "Category|Shoes", epoch = 120 },
    { site_id = "s1", type = "url", host = "a.test", path = "/x", query = "", epoch = 90 },
    { site_id = "s2", type = "tag", tag = "product-42", epoch = 130 },
  } }))
  -- t|s1|product-42, t|s1|category|shoes, T|s1, u|s1|/x, t|s2|product-42, T|s2
  eq(st.entries, 6)
  eq(st.markers, 4, "T| indexes, it is no marker")
  eq(purge.tag_max("s1"), 120)
  eq(purge.tag_max("s2"), 130)
  eq(purge.tag_max("s3"), nil, "no tag marker: nil")
  eq(purge_dict:get("t|s1|category|shoes"), 120, "tags are kept in lowercase")
  eq(purge.tag_epoch("s1", { "product-42" }), 100)
  eq(purge.tag_epoch("s1", { "category|shoes", "product-42" }), 120)
  eq(purge.tag_epoch("s1", { "other" }), 0)
  eq(purge.tag_epoch("s1", {}), 0)
  eq(purge.tag_epoch("s3", { "product-42" }), 0, "other site")
end)

test("tag markers: add keeps the highest epoch and the counters follow", function()
  reset()
  assert(purge.add({ id = "a1", markers = { { site_id = "s1", type = "tag", tag = "a", epoch = 10 } } }))
  local st = assert(purge.add({ id = "a2", markers = {
    { site_id = "s1", type = "tag", tag = "a", epoch = 5 },
    { site_id = "s1", type = "tag", tag = "b", epoch = 20 },
  } }))
  eq(st.id, "a2")
  eq(st.entries, 3, "t|s1|a, t|s1|b, T|s1")
  eq(st.markers, 2)
  eq(purge.tag_epoch("s1", { "a" }), 10, "an older purge of a tag never lowers its epoch")
  eq(purge.tag_max("s1"), 20)
  st = assert(purge.add({ id = "a3", markers = { { site_id = "s1", type = "tag", tag = "a", epoch = 30 } } }))
  eq(st.entries, 3)
  eq(st.markers, 2, "re-purging a tag only raises its epoch")
  eq(purge.tag_epoch("s1", { "a" }), 30, "the worker cache follows the new version")
  eq(purge.tag_max("s1"), 30)
  -- replace drops what the new set lacks.
  st = assert(purge.replace({ id = "a4", markers = { { site_id = "s1", type = "tag", tag = "b", epoch = 20 } } }))
  eq(st.entries, 2)
  eq(st.markers, 1)
  eq(purge.tag_epoch("s1", { "a" }), 0, "expired marker is gone")
  eq(purge.tag_max("s1"), 20)
end)

test("tag markers: invalid tags are refused", function()
  reset()
  for _, tag in ipairs({ "", "a,b", " a", "a ", string.rep("x", 129), "tab\there", "nul\0", "caf\195\169", 7 }) do
    local _, err, code = purge.add({ id = "bad", markers = { { site_id = "s1", type = "tag", tag = tag, epoch = 1 } } })
    eq(code, 400, "tag " .. tostring(tag))
    assert(err:find("invalid marker"), err)
  end
  local ok = purge.add({ id = "edge", markers = { { site_id = "s1", type = "tag", tag = string.rep("x", 128), epoch = 1 },
    { site_id = "s1", type = "tag", tag = "a b|c~", epoch = 1 } } })
  assert(ok, "128 bytes and inner spaces are valid")
  eq(purge.valid_tag("x"), true)
  eq(purge.valid_tag(" "), false)
end)

test("tag markers collapse with the site when a full set does not fit", function()
  reset()
  local markers = {}
  local pad = string.rep("y", 2500)
  for i = 1, 2000 do
    markers[#markers + 1] = { site_id = "big", type = "url", host = "big.test", path = "/same", query = "q=" .. i .. pad, epoch = 1000 + i }
  end
  markers[#markers + 1] = { site_id = "big", type = "tag", tag = "late", epoch = 9000 }
  markers[#markers + 1] = { site_id = "small", type = "tag", tag = "keep", epoch = 77 }
  local st = assert(purge.replace({ id = "big-1", markers = markers }))
  eq(#st.collapsed, 1)
  eq(st.collapsed[1], "big")
  local key = cachekey.prepare({ query = "all" })
  eq(purge.epoch("big", key, "big.test", "/anything", ""), 9000, "site-level marker at the highest epoch, tag epochs included")
  eq(purge.tag_max("big"), nil, "the collapsed site has no tag index left")
  eq(purge_dict:get("t|big|late"), nil)
  eq(purge.tag_max("small"), 77, "other sites keep their tag markers")
  reset()
end)

-- ---------------------------------------------------------------------
-- Cache-Tag parser

test("parse splits, trims, lowercases and de-duplicates", function()
  eq(list(cachetags.parse("a,b, c ,\tD\t,a,,  ,b")), "a,b,c,d")
  eq(list(cachetags.parse({ "first-a,first-b", "second" })), "first-a,first-b,second", "several header lines")
  eq(list(cachetags.parse("Product 42, product 42")), "product 42", "inner spaces stay, case does not count")
  eq(list(cachetags.parse("x|y,~!")), "x|y,~!", "printable ASCII")
  eq(#cachetags.parse(nil), 0)
  eq(#cachetags.parse(""), 0)
  eq(#cachetags.parse(" , ,"), 0)
end)

test("parse drops long and non-printable elements", function()
  local long = string.rep("l", 129)
  eq(list(cachetags.parse("ok," .. long .. "," .. string.rep("m", 128))), "ok," .. string.rep("m", 128))
  eq(list(cachetags.parse("a\tb,c")), "c", "a tab inside an element")
  eq(list(cachetags.parse("caf\195\169,d")), "d", "UTF-8 bytes")
  eq(list(cachetags.parse("del\127,e")), "e")
end)

test("parse reads at most 4096 bytes and drops the element cut there", function()
  -- 682 distinct tags of 5 bytes, joined: 4091 bytes.
  local parts = {}
  for i = 1, 682 do parts[i] = string.format("a%04d", i) end
  local head = table.concat(parts, ",")
  eq(#head, 4091)
  -- Byte 4097 falls inside "xyzxyzxyz": that element is cut and dropped.
  local tags = cachetags.parse(head .. ",xyzxyzxyz")
  eq(#tags, 682)
  eq(tags[682], "a0682")
  -- Byte 4097 is ",": the element ending at byte 4096 is whole.
  tags = cachetags.parse(head .. ",abcd,next")
  eq(#tags, 683)
  eq(tags[683], "abcd")
  -- Exactly 4096 bytes are read as they are.
  eq(cachetags.parse(head .. ",abcd")[683], "abcd")
  -- One element longer than 4096 bytes: nothing.
  eq(#cachetags.parse(string.rep("q", 5000)), 0)
end)

-- ---------------------------------------------------------------------
-- Index entries

test("entries encode, decode and merge", function()
  eq(cachetags.encode(1790000000123, { "a", "b" }), "1790000000123|a,b")
  eq(cachetags.encode(5, {}), "5|")
  eq(cachetags.encode(7, true), "7*")
  local e, tags = cachetags.decode("1790000000123|a,b")
  eq(e, 1790000000123)
  eq(list(tags), "a,b")
  e, tags = cachetags.decode("0|")
  eq(e, 0)
  eq(#tags, 0)
  e, tags = cachetags.decode("9*")
  eq(e, 9)
  eq(tags, true)
  eq(cachetags.decode("junk"), nil)
  eq(cachetags.decode(nil), nil)
  -- A higher epoch replaces, a lower one changes nothing.
  eq(cachetags.merge("10|a,b", 20, { "c" }), "20|c")
  eq(cachetags.merge("10|a,b", 5, { "c" }), nil)
  eq(cachetags.merge(nil, 0, { "c" }), "0|c")
  -- The same epoch adds the new tags (slices fetched at different times).
  eq(cachetags.merge("10|a,b", 10, { "b", "c" }), "10|a,b,c")
  eq(cachetags.merge("10|a,b", 10, { "a" }), nil, "nothing new")
  eq(cachetags.merge("10|a", 10, {}), nil)
  eq(cachetags.merge("10*", 10, { "z" }), nil, "every tag already")
  eq(cachetags.merge("10*", 11, { "z" }), "11|z")
  -- Beyond 4096 bytes of tags the entry stands for every tag of the site.
  local big = {}
  for i = 1, 400 do big[i] = string.format("tag-%05d", i) end
  local more = {}
  for i = 401, 800 do more[#more + 1] = string.format("tag-%05d", i) end
  eq(cachetags.merge(cachetags.encode(3, big), 3, more), "3*")
end)

test("split_key separates the base key and the key epoch", function()
  local base, e = cachetags.split_key("s1:1:http://a.test/x?q=%23|h:x=%23#1790000000123")
  eq(base, "s1:1:http://a.test/x?q=%23|h:x=%23")
  eq(e, 1790000000123)
  base, e = cachetags.split_key("s1:1:http://a.test/x")
  eq(base, "s1:1:http://a.test/x")
  eq(e, 0)
  eq(cachekey.with_epoch("b", 0), "b")
  eq(cachekey.with_epoch("b", 1790000000123), "b#1790000000123")
end)

-- ---------------------------------------------------------------------
-- Key epoch decisions

local TTL = 60

-- fetch simulates a request: the key epoch the edge computes, and, when
-- the response is fetched for the cache (the key is not cached yet), the
-- index write of the header filter. cached[key] = tags of the stored
-- object. Returns key epoch, "HIT" or "MISS".
local function fetch(cached, site, base, e_url, header)
  local tmax = purge.tag_max(site)
  local e = tmax and cachetags.key_epoch(site, base, e_url, tmax) or e_url
  local key = cachekey.with_epoch(base, e)
  if cached[key] then
    return e, "HIT"
  end
  cachetags.record(site, key, header, TTL)
  cached[key] = header or ""
  return e, "MISS"
end

test("key epoch: objects with a purged tag move, others stay", function()
  reset()
  local cached = {}
  local tagged, plain = "s1:1:http://a.test/tagged", "s1:1:http://a.test/plain"
  eq(select(2, fetch(cached, "s1", tagged, 0, "Product-42, all")), "MISS")
  eq(select(2, fetch(cached, "s1", plain, 0, nil)), "MISS")
  eq(select(2, fetch(cached, "s1", tagged, 0, "product-42")), "HIT")
  eq(select(2, fetch(cached, "s1", plain, 0, nil)), "HIT")
  eq(tags_dict:get("s:s1"), 1, "site flag after a tagged response")
  assert(tags_dict:get(ngx.md5_bin(plain)), "untagged object of a site with tags is indexed")
  -- Purge the tag.
  assert(purge.add({ id = "p1", markers = { { site_id = "s1", type = "tag", tag = "product-42", epoch = 500 } } }))
  local e, r = fetch(cached, "s1", tagged, 0, "product-42, all")
  eq(r, "MISS", "tagged object after the purge")
  eq(e, 500)
  eq(select(2, fetch(cached, "s1", tagged, 0, "product-42, all")), "HIT", "the new object is stable")
  eq(select(2, fetch(cached, "s1", plain, 0, nil)), "HIT", "untagged object keeps its key")
  -- Another tag's purge leaves the object alone; "all" moves it again.
  assert(purge.add({ id = "p2", markers = { { site_id = "s1", type = "tag", tag = "unrelated", epoch = 600 } } }))
  eq(select(2, fetch(cached, "s1", tagged, 0, nil)), "HIT")
  assert(purge.add({ id = "p3", markers = { { site_id = "s1", type = "tag", tag = "all", epoch = 700 } } }))
  e, r = fetch(cached, "s1", tagged, 0, "product-42, all")
  eq(r, "MISS")
  eq(e, 700)
  -- A URL purge still wins when it is newer.
  e, r = fetch(cached, "s1", tagged, 800, "product-42")
  eq(r, "MISS")
  eq(e, 800)
end)

test("key epoch: an evicted entry or a restart refetches once, then stays", function()
  reset()
  local cached = {}
  local base = "s1:1:http://a.test/e"
  fetch(cached, "s1", base, 0, "x")
  assert(purge.add({ id = "q1", markers = { { site_id = "s1", type = "tag", tag = "other", epoch = 300 } } }))
  eq(select(2, fetch(cached, "s1", base, 0, "x")), "HIT", "indexed object, unrelated tag")
  tags_dict:delete(ngx.md5_bin(base)) -- evicted
  local e, r = fetch(cached, "s1", base, 0, "x")
  eq(r, "MISS", "unknown object: fetched once more")
  eq(e, 300, "under the site's highest tag epoch")
  eq(select(2, fetch(cached, "s1", base, 0, "x")), "HIT", "indexed again")
end)

test("key epoch: an expired tag marker keeps the stored epoch", function()
  reset()
  local cached = {}
  local base = "s1:1:http://a.test/x"
  fetch(cached, "s1", base, 0, "t")
  assert(purge.add({ id = "r1", markers = { { site_id = "s1", type = "tag", tag = "t", epoch = 400 } } }))
  eq(select(2, fetch(cached, "s1", base, 0, "t")), "MISS")
  assert(purge.add({ id = "r2", markers = { { site_id = "s1", type = "tag", tag = "u", epoch = 450 } } }))
  -- The marker of t expires; u keeps the site's tag index alive.
  assert(purge.replace({ id = "r3", markers = { { site_id = "s1", type = "tag", tag = "u", epoch = 450 } } }))
  local e, r = fetch(cached, "s1", base, 0, "t")
  eq(r, "HIT", "entry epoch is the floor")
  eq(e, 400)
  -- Every tag marker gone: E_url decides again (one refetch, unindexed).
  -- Markers outlive the objects cached before them (retention: longest
  -- inactive time + 1 h), so the pre-purge object is gone by then.
  cached[base] = nil
  assert(purge.replace({ id = "r4", markers = {} }))
  e, r = fetch(cached, "s1", base, 0, "t")
  eq(e, 0)
  eq(r, "MISS")
end)

test("key epoch: tags of slices fetched at different times add up", function()
  reset()
  local base = "s1:1:http://a.test/big.bin"
  -- Slice 0 and slice 1 of one object, recorded under the same key epoch.
  cachetags.record("s1", base, "slice-0, file", TTL)
  cachetags.record("s1", base, "slice-1, file", TTL)
  local e, tags = cachetags.decode(tags_dict:get(ngx.md5_bin(base)))
  eq(e, 0)
  eq(list(tags), "slice-0,file,slice-1")
  assert(purge.add({ id = "s1", markers = { { site_id = "s1", type = "tag", tag = "slice-1", epoch = 900 } } }))
  eq(cachetags.key_epoch("s1", base, 0, purge.tag_max("s1")), 900, "a tag only one slice carried moves the object")
  -- A response that raced a newer one (lower epoch) changes nothing.
  cachetags.record("s1", base .. "#900", "new", TTL)
  cachetags.record("s1", base, "stale-race", TTL)
  e, tags = cachetags.decode(tags_dict:get(ngx.md5_bin(base)))
  eq(e, 900)
  eq(list(tags), "new")
end)

test("record: sites without tags and tag markers write nothing", function()
  reset()
  cachetags.record("plain", "plain:1:http://p.test/x", nil, TTL)
  cachetags.record("plain", "plain:1:http://p.test/y", "", TTL)
  eq(tags_dict:get(ngx.md5_bin("plain:1:http://p.test/x")), nil)
  eq(tags_dict:get("s:plain"), nil)
  -- With tag markers, untagged objects are indexed (they keep their key).
  assert(purge.add({ id = "w1", markers = { { site_id = "plain", type = "tag", tag = "t", epoch = 50 } } }))
  cachetags.record("plain", "plain:1:http://p.test/x#50", nil, TTL)
  eq(tags_dict:get(ngx.md5_bin("plain:1:http://p.test/x")), "50|")
  eq(tags_dict:get("s:plain"), nil, "no flag without a tagged response")
  eq(cachetags.key_epoch("plain", "plain:1:http://p.test/x", 0, 50), 50)
  -- Missing site or key: nothing.
  cachetags.record("", "k", "t", TTL)
  cachetags.record("s", "", "t", TTL)
  eq(tags_dict:get("s:s"), nil)
end)

test("record: entries expire with the tag index lifetime", function()
  reset()
  cachetags.record("ttl", "ttl:1:http://t.test/x", "a", 1)
  assert(tags_dict:get(ngx.md5_bin("ttl:1:http://t.test/x")))
  ngx.sleep(1.1)
  eq(tags_dict:get(ngx.md5_bin("ttl:1:http://t.test/x")), nil)
  eq(tags_dict:get("s:ttl"), nil)
end)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
