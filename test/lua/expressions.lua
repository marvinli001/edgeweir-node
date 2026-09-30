local cjson = require("cjson.safe")
local engine = require("edgeweir.expressions")
local vectors = assert(cjson.decode(assert(io.open("/t/expression-vectors.json")):read("*a")))
local challenge_levels = require("edgeweir.challenge").LEVELS
local accepted, actions = 0, 0
for i, vector in ipairs(vectors) do
  -- Rejected patterns never reach the data plane: the console and configir refuse them.
  if not vector.rejected then
    local lists = {}; for id, entries in pairs(vector.lists) do lists[id] = engine.ip_set(entries) end
    local match = engine.compile(vector.ir, lists)
    assert(match(vector.request) == vector.expected, "vector " .. i .. ": " .. vector.source)
    accepted = accepted + 1
    -- Challenge actions the console compiles name a level the edge knows.
    local action = vector.action
    if type(action) == "table" and action.kind == "challenge" and not vector.actionRejected then
      assert(challenge_levels[action.challenge], "vector " .. i .. ": unknown challenge " .. tostring(action.challenge))
      actions = actions + 1
    end
  end
end
-- `$` outside a class becomes \z; escaped and bracketed `$` stay literal.
local prefix = "(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(*LF)"
for pattern, want in pairs({
  [""] = "",
  ["^/a$"] = "^/a\\z",
  ["(a$|b)$"] = "(a\\z|b)\\z",
  ["\\$[$]\\\\$"] = "\\$[$]\\\\\\z",
  ["[\\]$]$"] = "[\\]$]\\z",
}) do
  assert(engine.pcre_pattern(pattern) == prefix .. want, "pcre_pattern " .. pattern)
end
assert(actions > 0, "no challenge action vectors")
print(tostring(accepted) .. " shared TS/Lua expression vectors passed (" .. actions .. " challenge actions)")
