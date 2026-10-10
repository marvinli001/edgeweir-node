-- Sampled request diagnostics and the live view's records (edge layer, log
-- phase). Never bodies; query strings, request headers and the connection's
-- peer only for sites that record them.
--
-- The site's log_sample_rate (basis points) applies unless a config rule set
-- one for the request. Log rules with access_log (proto v0.29.0, feature
-- waf-v2) ask for a line whatever the rate: the line names them (rule_ids,
-- at most 8), and a line written only because of them says sample_rate
-- 10000; sites with log_blocked (proto v0.30.0, feature access-logs-v2,
-- ADR-0041) do the same for every request with a block reason
-- (edgeweir.reasons). Both share MAX_FORCED such lines per site and second
-- on this node (counted in edgeweir_logs); the others only as sampled.
--
-- Every line carries (ADR-0041 §1) the User-Agent, the Referer without
-- query and fragment, the HTTP and TLS versions, the scheme, the client's
-- country and network (the access phase's GeoIP record, else the worker's
-- cache: no sockets here), the origin's address, status and time when the
-- request went to the origin (not for cache hits), the request's size, the
-- response's media type and the block reason with its rule. Sites add the
-- query string (log_query), request headers (log_headers) and the
-- connection's peer address (log_peer) when they record them.
--
-- The live view (edgeweir.tap) gets the same record, without the optional
-- fields, for every request while someone watches it, sampled or not.
local json = require("cjson.safe")
local reasons = require("edgeweir.reasons")
local tap = require("edgeweir.tap")
local M = {}
-- Lines the queue holds for the agent (edgeweir_logs is sized for them).
local MAX_PENDING = 2000
M.MAX_PENDING = MAX_PENDING
M.MAX_FORCED = 100

local byte, find, floor, lower, match, sub = string.byte, string.find, math.floor, string.lower, string.match, string.sub
local tonumber, type = tonumber, type

local function clean(value, limit)
  return string.sub(tostring(value or ""):gsub("[%z\1-\31\127]", ""), 1, limit)
end

-- cut shortens s to at most limit bytes without splitting a UTF-8 sequence.
local function cut(s, limit)
  if #s <= limit then return s end
  local n = limit
  for _ = 1, 3 do
    local b = byte(s, n + 1)
    if not b or b < 0x80 or b >= 0xC0 then break end
    n = n - 1
  end
  return sub(s, 1, n)
end
M.cut = cut

-- text strips control characters from value (the first of several lines)
-- and cuts it to limit bytes.
local function text(value, limit)
  if type(value) == "table" then value = value[1] end
  if type(value) ~= "string" or value == "" then return "" end
  return cut((value:gsub("[%z\1-\31\127]", "")), limit)
end
M.text = text

local HTTP_VERSIONS = { ["HTTP/1.0"] = "1.0", ["HTTP/1.1"] = "1.1", ["HTTP/2.0"] = "2", ["HTTP/3.0"] = "3" }
local TLS_VERSIONS = { ["TLSv1.2"] = "1.2", ["TLSv1.3"] = "1.3" }
M.HTTP_VERSIONS, M.TLS_VERSIONS = HTTP_VERSIONS, TLS_VERSIONS
-- Responses from the cache: their upstream variables describe the stored
-- response, not this request.
local FROM_CACHE = { HIT = true, STALE = true, UPDATING = true }

-- media_type returns a Content-Type's media type, lowercase, without
-- parameters ("" when it is no type/subtype of at most 128 bytes).
function M.media_type(value)
  if type(value) == "table" then value = value[1] end
  if type(value) ~= "string" then return "" end
  local t = lower(match(value, "^%s*([^;]*)") or ""):gsub("%s+$", "")
  if #t > 128 or not match(t, "^[%w!#%$&%^_%.%+%-]+/[%w!#%$&%^_%.%+%-]+$") then return "" end
  return t
end

-- referer returns a Referer without its query and fragment.
function M.referer(value)
  if type(value) == "table" then value = value[1] end
  if type(value) ~= "string" then return "" end
  return text(match(value, "^[^?#]*"), 1024)
end

-- last_number returns the last number of an upstream variable ("200, 502 :
-- 200"; "-" for none): nil when there is none.
local function last_number(value)
  if type(value) ~= "string" then return nil end
  return tonumber(match(value, "([%d%.]+)[^%d%.]*$"))
end

-- upstream returns the origin's address, status and time in milliseconds
-- of a request the edge passed to the origin layer: its response's
-- X-Edgeweir-Upstream (set only by the origin layer, hidden from clients)
-- and the edge's last $upstream_status and $upstream_response_time
-- (including the origin layer's own retries); "", 0, 0 for responses from
-- the cache and the node's own answers.
function M.upstream(var)
  local status = var.upstream_status
  if not status or status == "" or FROM_CACHE[var.upstream_cache_status or ""] then return "", 0, 0 end
  local code = last_number(status)
  if not code or code < 100 or code > 599 or code ~= floor(code) then code = 0 end
  local seconds = last_number(var.upstream_response_time)
  local ms = seconds and math.min(86400000, floor(seconds * 1000 + 0.5)) or 0
  return text(var.upstream_http_x_edgeweir_upstream, 128), code, ms
end

-- geo_fields returns the country (uppercase alpha-2 or ""), network (0
-- unknown) and its name from a GeoIP record.
function M.geo_fields(geo)
  if type(geo) ~= "table" then return "", 0, "" end
  local country = type(geo.country) == "string" and match(geo.country, "^%u%u$") or ""
  local asn = tonumber(geo.asnum)
  if not asn or asn < 1 or asn > 4294967295 or asn ~= floor(asn) then return country, 0, "" end
  return country, asn, text(geo.as_name, 128)
end

-- request_headers picks the recorded headers from a request header table
-- (lowercase names): several lines joined with ", ", each value at most
-- 512 bytes; nil when the request has none of them.
function M.request_headers(headers, names)
  if type(names) ~= "table" or #names == 0 or type(headers) ~= "table" then return nil end
  local out, any = {}, false
  for i = 1, #names do
    local name = names[i]
    local v = headers[name]
    if type(v) == "table" then v = table.concat(v, ", ") end
    if type(v) == "string" then
      out[name] = text(v, 512)
      any = true
    end
  end
  return any and out or nil
end

-- record builds the fields every line and live view record carries.
local function record(var, site_id, geo, status)
  local country, asn, as_name = M.geo_fields(geo)
  local upstream_addr, upstream_status, upstream_ms = M.upstream(var)
  local reason, rule = reasons.get()
  local scheme = var.scheme
  return {
    time = ngx.now(), site_id = site_id, client_ip = clean(var.remote_addr, 64),
    method = clean(var.request_method, 32), host = clean(var.host, 253),
    path = clean((ngx.ctx.edgeweir_original_path or var.uri or ""):match("^[^?#]*"), 2048),
    status = status, bytes_sent = tonumber(var.bytes_sent) or 0,
    duration_ms = math.min(86400000, floor((tonumber(var.request_time) or 0) * 1000)),
    cache_status = clean(var.upstream_cache_status, 32),
    -- The X-Request-Id the node answered with (also on error pages).
    request_id = clean(var.edgeweir_request_id, 128),
    user_agent = text(var.http_user_agent, 512), referer = M.referer(var.http_referer),
    http_version = HTTP_VERSIONS[var.server_protocol] or "",
    scheme = (scheme == "http" or scheme == "https") and scheme or "",
    country = country, asn = asn, as_name = as_name,
    upstream_addr = upstream_addr, upstream_status = upstream_status, upstream_ms = upstream_ms,
    request_bytes = tonumber(var.request_length) or 0,
    content_type = M.media_type(var.sent_http_content_type),
    tls_version = TLS_VERSIONS[var.ssl_protocol or ""] or "",
    block_reason = reason or "", block_rule_id = rule or "",
  }
end

-- decide returns whether the request of site gets a line and its sample
-- rate, and the log rules that asked for it.
local function decide(site, dict)
  local ctx = ngx.ctx
  -- Config rules may set the rate for a request (basis points).
  local policy = ctx.edgeweir_policy
  local rate = policy and policy.log_sample_rate or tonumber(site.log_sample_rate) or 0
  local rules = policy and policy.log_rules
  if rules and #rules == 0 then rules = nil end
  if rate and rate > 0 then
    local id = ngx.var.request_id or tostring(ngx.now()) .. tostring(ngx.worker.pid())
    if ngx.crc32_short(id) % 10000 < rate then return true, rate, rules end
  end
  if not rules and not (site.log_blocked and ctx.edgeweir_reason) then return false end
  local forced = dict:incr("forced|" .. site.id .. "|" .. floor(ngx.now()), 1, 0, 2)
  if not forced or forced > M.MAX_FORCED then return false end
  return true, 10000, rules
end

-- log(waf_ids, waf_blocked, site_id, geo, tap_only): the CRS rules that
-- matched (at most 16) and whether CRS blocked the request, for requests
-- of CRS sites; site_id is the request's site ("" for none), geo the
-- client's GeoIP record (nil: unknown); tap_only: a request no site counts
-- (the live view only).
function M.log(waf_ids, waf_blocked, site_id, geo, tap_only)
  if ngx.is_subrequest then return end
  local ctx = ngx.ctx
  local site = ctx.edgeweir_site
  if not site_id then site_id = site and site.id or "" end
  if tap_only or (site and site.id ~= site_id) then site = nil end
  local dict = ngx.shared.edgeweir_logs
  local write, rate, rules = false, nil, nil
  if site then write, rate, rules = decide(site, dict) end
  local watched = tap.watching(site_id)
  if not write and not watched then return end
  local var = ngx.var
  local entry = record(var, site_id, geo, ngx.status)
  if watched then tap.record(entry) end
  if not write then return end
  local n = dict:llen("pending") or 0
  if n >= MAX_PENDING then dict:incr("dropped", 1, 0); return end
  entry.sample_rate = rate
  entry.ja4 = site.protection and site.protection.log_ja4 and clean(require("edgeweir.ja4").value(), 64) or nil
  entry.waf_rule_ids = waf_ids and #waf_ids > 0 and setmetatable(waf_ids, json.array_mt) or nil
  entry.waf_blocked = waf_blocked or nil
  entry.rule_ids = rules and setmetatable({ unpack(rules, 1, math.min(#rules, 8)) }, json.array_mt) or nil
  -- The site's optional fields (access-logs-v2).
  if site.log_query then entry.query = text(ctx.edgeweir_original_args or var.args, 2048) end
  if site.log_headers then
    entry.headers = ctx.edgeweir_log_headers or M.request_headers(ngx.req.get_headers(0), site.log_headers)
  end
  if site.log_peer then
    local peer = var.realip_remote_addr
    if peer and peer ~= "unix:" and peer ~= var.remote_addr then entry.peer_ip = clean(peer, 64) end
  end
  local raw = json.encode(entry)
  if not raw or not dict:rpush("pending", raw) then dict:incr("dropped", 1, 0) end
end

function M.drain()
  local dict, entries = ngx.shared.edgeweir_logs, {}
  for _ = 1, 1000 do
    local raw = dict:lpop("pending")
    if not raw then break end
    local record = json.decode(raw)
    if record then entries[#entries+1] = record end
  end
  if json.array_mt then setmetatable(entries, json.array_mt) end
  return entries
end
return M
