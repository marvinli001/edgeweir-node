local ffi = require("ffi")
local base = require("resty.core.base")

ffi.cdef[[
  typedef struct { size_t len; const unsigned char *data; } ew_hint_t;
  int ngx_http_ffi_send_early_hints(ngx_http_request_t *r, ew_hint_t *links, size_t count);
]]

local available, send = pcall(function() return ffi.C.ngx_http_ffi_send_early_hints end)
local reasons = { "protocol", "sent", "subrequest", "internal", "unsupported" }
local _M = {}

function _M.send(links)
  if type(links) ~= "table" then error("early_hints needs a list of Link values", 2) end
  local n, bytes = 0, 0
  for k, value in pairs(links) do
    if type(k) ~= "number" or k % 1 ~= 0 or k < 1 or k > 32
      or type(value) ~= "string" or value:sub(1, 1) ~= "<" or value:find("[\r\n%z]") then
      error("invalid early_hints Link value", 2)
    end
    n, bytes = n + 1, bytes + #value
  end
  if n < 1 or n > 32 or n ~= #links or bytes > 8192 then
    error("early_hints needs 1-32 Link values totaling at most 8192 bytes", 2)
  end
  for i = 1, n do
    if links[i] == nil then error("early_hints needs a dense list", 2) end
  end
  if ngx.is_subrequest then return false, "subrequest" end
  if ngx.var.edgeweir_tier_in == "1" then return false, "internal" end
  local protocol = ngx.req.http_version()
  if protocol ~= 2 and protocol ~= 3 then return false, "protocol" end
  if not available then return false, "unsupported" end
  local values = ffi.new("ew_hint_t[?]", n)
  for i = 1, n do
    values[i - 1].data = links[i]
    values[i - 1].len = #links[i]
  end
  local result = send(base.get_request(), values, n)
  if result == 0 then return true end
  return false, reasons[result] or "unsupported"
end

return _M
