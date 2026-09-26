local cjson = require("cjson.safe")
local engine = require("edgeweir.expressions")
local vectors = assert(cjson.decode(assert(io.open("/t/expression-vectors.json")):read("*a")))
for i, vector in ipairs(vectors) do
  local lists = {}; for id, entries in pairs(vector.lists) do lists[id] = engine.ip_set(entries) end
  local match = engine.compile(vector.ir, lists)
  assert(match(vector.request) == vector.expected, "vector " .. i .. ": " .. vector.source)
end
print(tostring(#vectors) .. " shared TS/Lua expression vectors passed")
