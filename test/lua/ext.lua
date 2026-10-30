-- Node extensions (edgeweir.ext): loading and isolation, hooks and
-- verdicts, faults and trips, CSP and HTML injection, helpers.
--
--   resty -I lua --shdict 'edgeweir_meta 1m' --shdict 'ewx_68656c6c6f2d686561646572_state 64k' \
--     test/lua/ext.lua examples/extensions/hello-header
local cjson = require("cjson.safe")

local example_dir = arg and arg[1] or "examples/extensions/hello-header"

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

-- The extensions' settings come from a stub of edgeweir.store.
local settings = { disabled = false, by_id = {} }
package.loaded["edgeweir.store"] = { config = function() return { extensions = settings } end }
-- The challenge module's levels and the request's pass level.
local pass_level = 0
package.loaded["edgeweir.challenge"] = {
  LEVELS = { cookie302 = 1, js = 2, pow = 3, captcha = 4 },
  pass_level = function() return pass_level end,
}
local ext = require("edgeweir.ext")
local reasons = require("edgeweir.reasons")

local tmp = "/tmp/ewx-test-" .. ngx.worker.pid()

local function write(path, data)
  os.execute("mkdir -p '" .. path:match("^(.*)/[^/]+$") .. "'")
  local f = assert(io.open(path, "wb"))
  f:write(data)
  f:close()
end

-- package writes an unpacked extension: manifest fields and lua files.
local function package(id, manifest, files)
  local dir = tmp .. "/" .. id
  local m = { format = "edgeweir-node-extension-v1", id = id, version = "1.0.0", publisher = "example.org",
    name = { en = id }, requires = { lua_api = 1 }, hooks = { "access" } }
  for k, v in pairs(manifest or {}) do m[k] = v end
  write(dir .. "/manifest.json", cjson.encode(m))
  for name, src in pairs(files) do write(dir .. "/" .. name, src) end
  return { id = id, dir = dir, sha256 = string.rep("a", 64) }
end

local function reset_ctx()
  for k in pairs(ngx.ctx) do ngx.ctx[k] = nil end
end

local VERDICTS = package("t-verdict", {
  hooks = { "access", "access_late", "log" }, capabilities = { "verdicts" },
  fields = { { name = "score", type = "number" }, { name = "tag", type = "string" } },
  counters = { "hits" }, log_fields = { "note" },
}, { ["lua/main.lua"] = [[
local util = require("util")
local M = {}
function M.access(ew)
  ew.field("score", util.seven())
  ew.count("hits")
  ew.log_field("note", "hi")
  local mode = ew.site_config.mode
  if mode == "deny" then return ew.deny(451) end
  if mode == "error" then error("boom") end
  if mode == "allow" then return ew.allow() end
  if mode == "challenge" then return ew.challenge("js") end
  if mode == "bad_field" then ew.field("score", "seven") end
  if mode == "undeclared" then ew.field("other", 1) end
  if mode == "slow" then local t = os.clock() while os.clock() - t < 0.03 do end end
  if mode == "headers" then
    ew.ctx.hdr = { (pcall(ew.respond, 403, "x", { ["X-Edgeweir-Challenge"] = "session" })),
      (pcall(ew.respond, 403, "x", { ["X-Edgeweir-Error"] = "x" })),
      (pcall(ew.respond, 200, "x", { ["X-Edgeweir-Ext-Note"] = "x" })) }
  end
  ew.ctx.seen = (ew.ctx.seen or 0) + 1
end
function M.access_late(ew)
  if ew.site_config.mode == "late_allow" then return ew.allow() end
  if ew.site_config.mode == "late_deny" then return ew.deny() end
  if ew.ctx.seen ~= 1 then error("ew.ctx not kept across hooks") end
end
function M.log(ew)
  ew.count("hits", 2)
  ew.log_field("note", 12345)
end
return M
]], ["lua/util.lua"] = "return { seven = function() return 7 end }" })

local NOCAP = package("t-nocap", { hooks = { "access" } }, { ["lua/main.lua"] = [[
return { access = function(ew) return ew.deny() end }
]] })

local PROBE = package("t-probe", { hooks = { "access" } }, { ["lua/main.lua"] = [[
local M = {}
function M.probe()
  local ok_os = pcall(require, "os")
  local ok_ffi = pcall(require, "ffi")
  local ok_up = pcall(require, "../../etc/passwd")
  local fn = load("return 1 + 1")
  local bc = load(string.char(27) .. "LJ")
  return { ngx = ngx, io = io, execute = os.execute, debug = debug, dump = string.dump, package = package,
    jit = jit, setfenv = setfenv, getfenv = getfenv, collectgarbage = collectgarbage, loadstring = loadstring,
    require_os = ok_os, require_ffi = ok_ffi, require_up = ok_up, load = fn and fn(), bytecode = bc,
    cjson = require("cjson.safe") ~= nil, strmeta = getmetatable("") }
end
return M
]] })

local BROKEN = package("t-broken", {}, { ["lua/main.lua"] = "return {" })

local API2 = package("t-api2", { requires = { lua_api = 2 }, hooks = { "access", "log" } }, { ["lua/main.lua"] = [[
local M = {}
function M.access(ew)
  ew.ctx.site_name = ew.site_name
  ew.ctx.reason = { ew.resp.reason() }
  ew.ctx.node = { ew.node.id(), ew.node.name(), ew.node.cluster_id(), ew.node.version() }
  ew.ctx.status = ew.node.status()
  ew.ctx.equal = { ew.equal("abc", "abc"), ew.equal("abc", "abd"), ew.equal("abc", "ab"), ew.equal("", "") }
  ew.ctx.log_only = pcall(ew.resp.bytes_sent)
end
return M
]] })
local SIDE = package("t-side", { requires = { lua_api = 2 }, hooks = { "access", "access_late" }, capabilities = { "sidecar" },
  secret = true }, { ["lua/main.lua"] = [[
local M = {}
function M.access(ew)
  local s = ew.secrets()
  ew.ctx.secret = { #ew.secret(), s.current == ew.secret(), s.previous }
  ew.ctx.ready = ew.sidecar.ready()
  ew.ctx.bad_header = pcall(ew.sidecar.proxy, { headers = { ["X-Other"] = "1" } })
  ew.ctx.in_access = pcall(ew.sidecar.proxy, {})
end
function M.access_late(ew)
  return ew.sidecar.proxy({ headers = { ["X-Edgeweir-Ext-Route"] = "r1" }, fail = ew.site_config.fail })
end
return M
]] })
local FUTURE = package("t-future", { requires = { lua_api = 3 } }, { ["lua/main.lua"] = "return {}" })

ext.init({
  { id = "hello-header", dir = example_dir, sha256 = string.rep("b", 64) },
  VERDICTS, NOCAP, PROBE, BROKEN, API2, SIDE, FUTURE,
})
ext.init_worker()

local function enable(id, opts)
  opts = opts or {}
  settings.by_id[id] = { enabled = true, closed = opts.closed == true, sha256 = ext.EXT[id].sha256, config = opts.config or {} }
end

local function site(list)
  local s = { id = "s1", extensions = list }
  ext.prepare(s)
  return s
end

local denied
local function deny(status, code)
  denied = { status = status, code = code }
  return "denied"
end
local challenged
local function run_challenge(_, kind, level, rule)
  challenged = { kind = kind, level = level, rule = rule }
  return "challenged"
end

local function access(s, hook)
  reset_ctx()
  denied, challenged = nil, nil
  return ext[hook or "access"](s, run_challenge, deny)
end

test("the example loads and its init runs on first use", function()
  local e = ext.EXT["hello-header"]
  eq(e.err, nil, "load error")
  eq(e.version, "1.0.0")
  eq(e.caps.verdicts, true)
  enable("hello-header", { config = { greeting = "hi" } })
  local s = site({ { id = "hello-header", config = {} } })
  ext.log(s)
  eq(e.inited, true, "inited")
  eq(ngx.shared["ewx_68656c6c6f2d686561646572_state"]:get("started") ~= nil, true, "init set started")
end)

test("a broken package reports its load error", function()
  local e = ext.EXT["t-broken"]
  eq(e.mod, nil)
  eq(type(e.err), "string")
  local status = ext.status()
  eq(status["t-broken"].error ~= "", true, "status error")
  eq(status["t-verdict"].error, "")
  eq(status["t-verdict"].sha256, string.rep("a", 64))
end)

test("the environment has no ngx, io, os.execute, debug, bytecode or package", function()
  local p = ext.EXT["t-probe"].mod.probe()
  for _, k in ipairs({ "ngx", "io", "execute", "debug", "dump", "package", "jit", "setfenv", "getfenv", "collectgarbage", "loadstring", "bytecode", "strmeta" }) do
    eq(p[k], nil, k)
  end
  eq(p.require_os, false, "require os")
  eq(p.require_ffi, false, "require ffi")
  eq(p.require_up, false, "require outside lua/")
  eq(p.load, 2, "source text loads")
  eq(p.cjson, true, "cjson.safe")
  eq(rawget(_G, "seven"), nil, "no global leak")
end)

test("access sets fields, counters and log fields; ew.ctx lasts the request", function()
  enable("t-verdict", { config = {} })
  local s = site({ { id = "t-verdict", config = { mode = "" } } })
  eq(access(s), nil)
  eq(ngx.ctx.edgeweir_ext_fields["ext.t-verdict.score"], 7)
  eq(ngx.ctx.edgeweir_ext_counts["t-verdict.hits"], 1)
  eq(ngx.ctx.edgeweir_ext_log["ext.t-verdict.note"], "hi")
  eq(ext.access_late(s, run_challenge, deny), nil, "access_late sees ew.ctx")
  ext.log(s)
  eq(ngx.ctx.edgeweir_ext_counts["t-verdict.hits"], 3)
  eq(ngx.ctx.edgeweir_ext_log["ext.t-verdict.note"], "12345")
end)

test("deny verdict: reason extension, rule ext:<id>, verdict logged", function()
  local s = site({ { id = "t-verdict", config = { mode = "deny" } } })
  local r = access(s)
  eq(r, true)
  eq(denied.status, 451)
  eq(denied.code, "extension-denied")
  local reason, rule = reasons.get()
  eq(reason, "extension")
  eq(rule, "ext:t-verdict")
  eq(ngx.ctx.edgeweir_ext_log["ext.t-verdict.verdict"], "deny")
end)

test("challenge and allow verdicts", function()
  local s = site({ { id = "t-verdict", config = { mode = "challenge" } } })
  pass_level = 0
  eq(access(s), true)
  eq(challenged.kind, "js")
  eq(challenged.level, 2)
  eq(challenged.rule, "ext:t-verdict")
  pass_level = 2
  eq(access(s), nil, "a pass of the level continues")
  pass_level = 0
  s = site({ { id = "t-verdict", config = { mode = "allow" } } })
  eq(access(s), "allow")
  s = site({ { id = "t-verdict", config = { mode = "late_allow" } } })
  eq(access(s, "access_late"), nil, "allow is not an access_late verdict")
  s = site({ { id = "t-verdict", config = { mode = "late_deny" } } })
  eq(access(s, "access_late"), true)
  eq(denied.status, 403)
  s = site({ { id = "t-verdict", config = { mode = "headers" } } })
  eq(access(s), nil)
  local hdr = ngx.ctx.edgeweir_ext["t-verdict"].ctx.hdr
  eq(hdr[1], true, "ew.respond may mark its page X-Edgeweir-Challenge")
  eq(hdr[2], false, "other X-Edgeweir- headers are the node's")
  eq(hdr[3], true, "X-Edgeweir-Ext- headers are the extensions'")
end)

test("verdicts need the capability; fields are type-checked and declared", function()
  enable("t-nocap")
  local before = ngx.shared.edgeweir_meta:get("ext|t-nocap|" .. string.rep("a", 64) .. "|faults") or 0
  eq(access(site({ { id = "t-nocap", config = {} } })), nil, "fails open")
  eq(ngx.shared.edgeweir_meta:get("ext|t-nocap|" .. string.rep("a", 64) .. "|faults"), before + 1, "fault counted")
  eq(ngx.ctx.edgeweir_ext_counts["t-nocap.faults"], 1, "site fault counter")
  eq(access(site({ { id = "t-verdict", config = { mode = "bad_field" } } })), nil)
  eq(ngx.ctx.edgeweir_ext_counts["t-verdict.faults"], 1)
  eq(access(site({ { id = "t-verdict", config = { mode = "undeclared" } } })), nil)
  eq(ngx.ctx.edgeweir_ext_counts["t-verdict.faults"], 1)
end)

test("failure modes: open skips, closed answers 503; disabled and the kill switch skip", function()
  local s = site({ { id = "t-verdict", config = { mode = "error" } } })
  eq(access(s), nil, "open")
  enable("t-verdict", { closed = true })
  eq(access(s), true, "closed")
  eq(denied.status, 503)
  eq(denied.code, "extension")
  eq(access(site({ { id = "t-verdict", config = { mode = "slow" } } })), true, "over the budget fails")
  settings.by_id["t-verdict"].enabled = false
  eq(access(site({ { id = "t-verdict", config = { mode = "deny" } } })), nil, "disabled")
  enable("t-verdict")
  settings.disabled = true
  eq(access(site({ { id = "t-verdict", config = { mode = "deny" } } })), nil, "kill switch")
  settings.disabled = false
  -- A package that is not the delivered one (reload pending) fails closed.
  settings.by_id["t-verdict"].sha256 = string.rep("c", 64)
  settings.by_id["t-verdict"].closed = true
  eq(access(site({ { id = "t-verdict", config = {} } })), true, "other package, closed")
  enable("t-verdict")
end)

test("faults trip an extension in the worker", function()
  local e = ext.EXT["t-verdict"]
  e.window, e.faults, e.tripped = 0, 0, 0
  local s = site({ { id = "t-verdict", config = { mode = "error" } } })
  for _ = 1, ext.MAX_FAULTS do access(s) end
  eq(e.tripped > ngx.now(), true, "tripped")
  eq(access(site({ { id = "t-verdict", config = { mode = "deny" } } })), nil, "tripped and open: skipped")
  eq(ext.status()["t-verdict"].trips >= 1, true, "trips reported")
  e.tripped = 0
  eq(access(site({ { id = "t-verdict", config = { mode = "deny" } } })), true, "back after the trip")
end)

test("compile and prepare", function()
  local c = ext.compile({ disabled = true, list = { { id = "a-b", enabled = true, failure_mode = "closed", sha256 = "x", config = { k = 1 } } } })
  eq(c.disabled, true)
  eq(c.by_id["a-b"].closed, true)
  eq(c.by_id["a-b"].config.k, 1)
  eq(ext.compile(nil), nil)
  local s = { extensions = { { id = "a-b", config = { x = 1 } }, { id = "c-d" } } }
  ext.prepare(s)
  eq(#s._ext, 2)
  eq(s._ext[2].id, "c-d")
  s = { extensions = {} }
  ext.prepare(s)
  eq(s._ext, nil)
end)

test("CSP decides how scripts are injected", function()
  eq(ext.csp_script(nil, true), true, "no CSP")
  eq(ext.csp_script("default-src 'self'", true), true, "self, same origin")
  eq(ext.csp_script("default-src 'self'", false), false, "self, other origin")
  eq(ext.csp_script("script-src 'nonce-abc123' 'strict-dynamic'; default-src 'none'", true), "abc123", "nonce")
  eq(ext.csp_script("script-src 'self' 'strict-dynamic'", true), false, "strict-dynamic without nonce")
  eq(ext.csp_script({ "script-src 'nonce-a'", "script-src 'nonce-b'" }, true), false, "two nonces")
  eq(ext.csp_script("img-src *", false), true, "no script directive")
end)

test("injectable responses", function()
  eq(ext.injectable("GET", 200, { ["Content-Type"] = "text/html; charset=utf-8" }), true)
  eq(ext.injectable("POST", 200, { ["Content-Type"] = "text/html" }), false)
  eq(ext.injectable("GET", 404, { ["Content-Type"] = "text/html" }), false)
  eq(ext.injectable("GET", 200, { ["Content-Type"] = "application/json" }), false)
  eq(ext.injectable("GET", 200, { ["Content-Type"] = "text/html", ["Content-Encoding"] = "gzip" }), false)
  eq(ext.injectable("GET", 200, { ["Content-Type"] = "text/html", ["Content-Range"] = "bytes 0-1/2" }), false)
  eq(ext.injectable("GET", 200, { ["Content-Type"] = "text/html", ["Cache-Control"] = "public, no-transform" }), false)
end)

local function stream(head, tail, chunks)
  local st = { head = head, tail = tail, scanned = head == "", buf = {}, size = 0, held = "" }
  local out = {}
  for i, c in ipairs(chunks) do out[#out + 1] = ext.inject(st, c, i == #chunks) end
  return table.concat(out)
end

test("HTML injection across chunks", function()
  eq(stream("<s>", "", { "<html><HEAD><title>x</ti", "tle></he", "ad><body>b</body></html>" }),
    "<html><HEAD><title>x</title><s></head><body>b</body></html>", "head_end split")
  eq(stream("", "<t>", { "<body>", string.rep("x", 2000), "</BODY></html>" }),
    "<body>" .. string.rep("x", 2000) .. "<t></BODY></html>", "body_end")
  eq(stream("<s>", "<t>", { "<p>no head", "</body>" }), "<p>no head<s><t></body>", "head falls back to body_end")
  eq(stream("", "<t>", { "plain" }), "plain<t>", "appended")
  eq(stream("<s>", "", { "</body>" }), "<s></body>", "no head, before body")
  local big = string.rep("y", ext.HEAD_SCAN + 10)
  eq(stream("<s>", "", { big, "</head></body>" }), big .. "</head><s></body>", "head beyond the scan")
end)

test("helpers", function()
  local hex = require("resty.string").to_hex
  eq(hex(ext.hmac_sha256("Jefe", "what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "RFC 4231 case 2")
  local e = ext.EXT["t-verdict"]
  local a = e.api
  eq(a.b64url_decode(a.b64url_encode("\255\254x")), "\255\254x")
  eq(a.b64url_encode("\255\254"), "__4")
  eq(a.json_decode(a.json_encode({ a = 1 })).a, 1)
  eq(#a.random_bytes(16), 16)
end)

test("Lua API 2: site name, reason, node, status, equal", function()
  eq(ext.EXT["t-future"].err, "unsupported Lua API")
  settings.node = { id = "n1", name = "edge-1", cluster_id = "c1", version = "1.7.0" }
  ngx.shared.edgeweir_meta:set("ext_node_status", '{"at":1,"cpu_percent":12.5}')
  enable("t-api2")
  local s = { id = "s1", domains = { { name = "shop.example" }, { name = "www.shop.example" } },
    extensions = { { id = "t-api2", config = {} } } }
  ext.prepare(s)
  reset_ctx()
  reasons.set("rate_limit", "r7")
  ext.access(s, run_challenge, deny)
  local c = ngx.ctx.edgeweir_ext["t-api2"].ctx
  eq(c.site_name, "shop.example")
  eq(c.reason[1], "rate_limit"); eq(c.reason[2], "r7")
  eq(table.concat(c.node, ","), "n1,edge-1,c1,1.7.0")
  eq(c.status.cpu_percent, 12.5)
  eq(c.equal[1], true); eq(c.equal[2], false); eq(c.equal[3], false); eq(c.equal[4], true)
  eq(c.log_only, false, "bytes_sent outside log")
  eq(ext.EXT["t-api2"].api.api, 2)
  eq(ext.EXT["t-verdict"].api.api, 1)
  eq(ext.EXT["t-verdict"].api.node, nil, "API 1 has no ew.node")
  settings.node = nil
end)

test("Lua API 2: secrets and sidecar verdicts", function()
  local key = string.rep("k", 32)
  eq(ext.put_runtime({ secrets = { ["t-side"] = { current = ngx.encode_base64(key) } }, sidecars = { ["t-side"] = false } }), true)
  enable("t-side")
  local function run(fail)
    local s = { id = "s1", domains = { { name = "a.example" } }, extensions = { { id = "t-side", config = { fail = fail } } } }
    ext.prepare(s)
    reset_ctx()
    denied = nil
    local r = ext.access(s, run_challenge, deny)
    local c = ngx.ctx.edgeweir_ext["t-side"].ctx
    return s, r, c
  end
  local s, r, c = run("open")
  eq(r, nil)
  eq(c.secret[1], 32); eq(c.secret[2], true); eq(c.secret[3], nil)
  eq(c.ready, false)
  eq(c.bad_header, false, "non X-Edgeweir-Ext- header refused")
  eq(c.in_access, false, "proxy outside access_late refused")
  -- Not ready: open continues, closed answers 502.
  eq(ext.access_late(s, run_challenge, deny), nil)
  s = run("closed")
  eq(ext.access_late(s, run_challenge, deny), true)
  eq(denied.status, 502)
  -- Ready: the request goes to the sidecar location with the headers.
  ext.put_runtime({ secrets = { ["t-side"] = { current = ngx.encode_base64(key), previous = ngx.encode_base64("p") } }, sidecars = { ["t-side"] = true } })
  local entered
  local real = ext.sidecar_enter
  ext.sidecar_enter = function(_, v) entered = v; return "entered" end
  s = run("open")
  eq(ext.access_late(s, run_challenge, deny), true)
  ext.sidecar_enter = real
  eq(entered.fail, "open")
  eq(entered.headers["X-Edgeweir-Ext-Route"], "r1")
  eq(ngx.ctx.edgeweir_ext_counts["t-side.sidecar"], 1)
  -- Extensions the agent leaves out lose their secret.
  ext.put_runtime({ secrets = {}, sidecars = {} })
  eq(ngx.shared.edgeweir_meta:get("ext_secret|t-side"), nil)
end)

os.execute("rm -r '" .. tmp .. "'")
print(string.format("%d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
