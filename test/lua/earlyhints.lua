local hints = require("edgeweir.earlyhints")
local passed = 0
local function test(name, fn)
  fn()
  passed = passed + 1
  print("ok   " .. name)
end

local function request(opts, fn)
  local runtime = ngx
  _G.ngx = { is_subrequest = opts.subrequest, var = { edgeweir_tier_in = opts.internal and "1" or "" },
    req = { http_version = function() return opts.protocol or 1.1 end } }
  local ok, err = pcall(fn)
  _G.ngx = runtime
  assert(ok, err)
end

test("Link validation rejects malformed, sparse and oversized input before runtime checks", function()
  local many = {}
  for i = 1, 33 do many[i] = "</a>" end
  for _, links in ipairs({ false, "</a>", {}, { 1 }, { "no-angle" }, { "</a>\rX: y" },
    { "</a>\nX: y" }, { "</a>\0" }, { "<" .. string.rep("a", 8192) }, many,
    { [1] = "</a>", [3] = "</b>" }, { [0] = "</a>" }, { x = "</a>" } }) do
    assert(not pcall(hints.send, links))
  end
end)

test("32 values and 8192 bytes are accepted without sending on HTTP/1.1", function()
  local links = {}
  for i = 1, 32 do links[i] = "<" .. string.rep("a", 255) end
  request({}, function()
    local ok, reason = hints.send(links)
    assert(ok == false and reason == "protocol")
  end)
end)

test("HTTP/1.0, HTTP/1.1, subrequests and upper-tier requests do not send", function()
  for _, vector in ipairs({ { protocol = 1, reason = "protocol" }, { reason = "protocol" },
    { protocol = 2, subrequest = true, reason = "subrequest" },
    { protocol = 3, internal = true, reason = "internal" } }) do
    request(vector, function()
      local ok, reason = hints.send({ "</a>" })
      assert(ok == false and reason == vector.reason)
    end)
  end
end)

test("an unavailable native request returns unsupported without throwing", function()
  request({ protocol = 2 }, function()
    local ok, reason = hints.send({ "</a>" })
    assert(ok == false and reason == "unsupported")
  end)
end)

print(passed .. " early hints tests passed")
