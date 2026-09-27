local router = require("edgeweir.router")

for _, case in ipairs({
  { "cdn.example.test", "443", 443 },
  { "cdn.example.test:443", "443", 443 },
  { "cdn.example.test:8443", "8443", 8443 },
  { "cdn.example.test:10443", "443", 10443 },
  { "cdn.example.test", "8443", 443 },
  { "[2001:db8::1]:8443", "443", 8443 },
  { "[2001:db8::1]", "8443", 443 },
  { "", "8443", 8443 },
  { "cdn.example.test:0", "443", false },
  { "cdn.example.test:65536", "443", false },
  { "cdn.example.test:unknown", "443", false },
}) do
  local actual = router.http3_port(case[1], case[2])
  assert(actual == (case[3] or nil), "unexpected HTTP/3 public port for " .. case[1])
  local runtime = ngx
  local response = {}
  _G.ngx = {
    var = { scheme = "https", http_host = case[1], server_port = case[2] },
    ctx = { edgeweir_site = { tls = { http3 = true, hsts_max_age = 0 } } },
    header = response,
  }
  local ok, err = pcall(router.header_filter)
  _G.ngx = runtime
  assert(ok, err)
  local expected = case[3] and ('h3=":' .. tostring(case[3]) .. '"; ma=86400') or nil
  assert(response["Alt-Svc"] == expected, "unexpected Alt-Svc for " .. case[1])
end

print("HTTP/3 public authority port cases passed")
