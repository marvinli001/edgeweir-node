-- edgeweir.reasons: why the node refused or challenged a request (ADR-0041).
--
-- The edge layer records the reason where it refuses, never from the
-- error code (policy-denied and ip-banned each stand for several reasons;
-- a 503 of Force HTTPS without a certificate, a closed WebSocket or a body
-- over the limit are no blocks). The first reason of a request wins. The
-- access logs (AccessLog.block_reason, block_rule_id), the live view and
-- the statistics (MinuteStats.block_reasons) read it in the log phase; it
-- lives in ngx.ctx, which the CRS and gRPC hand-overs carry along
-- (edgeweir.waf.stash_ctx).
local _M = {}

-- REASONS are the reasons the console knows (packages/contract
-- BLOCK_REASONS); set() ignores anything else.
_M.REASONS = {
  ip_banned = true, ip_blocked = true, rule = true, rate_limit = true, crs = true, cc = true,
  challenge = true, auth = true, referer = true, user_agent = true, region = true, cors = true,
  websocket_origin = true, client_cert = true, maintenance = true,
}

-- set records reason and, for reasons a rule caused, the rule's id (custom
-- WAF, rate limit and access authentication rules; a rule's challenge).
-- A request keeps its first reason.
function _M.set(reason, rule_id)
  local ctx = ngx.ctx
  if ctx.edgeweir_reason or not _M.REASONS[reason] then return end
  ctx.edgeweir_reason = reason
  if type(rule_id) == "string" and rule_id ~= "" then ctx.edgeweir_reason_rule = rule_id end
end

-- get returns the request's reason and rule id (nil, nil without one).
function _M.get()
  local ctx = ngx.ctx
  return ctx.edgeweir_reason, ctx.edgeweir_reason_rule
end

return _M
