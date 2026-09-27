#!/usr/bin/env bash
# Container smoke test for edgeweir-node:
#   1. the node container serves 404 unknown-host before enrollment;
#   2. `docker compose exec node edgeweir-node enroll ...` while `run` is
#      running switches the node to mTLS and applies revision 1;
#   3. demo.test is proxied to the whoami origin: first MISS, then HIT;
#   4. origin address policy: special-purpose literals and DNS answers
#      outside the allow list get 502, CDN-Loop is appended and loops get
#      508;
#   5. origin HTTPS verification uses the origin's name (SNI): trusted CA +
#      matching name 200, wrong name 502;
#   6. a new site reserves its partition; later existing-site changes stay hot;
#   7. restarting the container serves the last-known-good config.
# Set E2E_KEEP=1 to keep the stack running afterwards.
set -euo pipefail
cd "$(dirname "$0")"

NODE="http://127.0.0.1:${E2E_NODE_PORT:-28080}"
HELPER="http://127.0.0.1:${E2E_HELPER_PORT:-28090}"
# COMPOSE_PROJECT_NAME (if set) takes precedence over the file's name.
compose() { docker compose -f compose.yml "$@"; }

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- node logs ---"
    compose logs --no-color --tail=200 node || true
    echo "--- console logs ---"
    compose logs --no-color --tail=50 console || true
  fi
  if [ "${E2E_KEEP:-0}" != "1" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

wait_for() { # description, command... (WAIT_SECS overrides the 90s timeout)
  local what=$1; shift
  for _ in $(seq 1 "${WAIT_SECS:-90}"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out waiting for $what"
}

x_cache() { # host -> value of X-Cache
  curl -s -o /dev/null -D - -H "Host: $1" "$NODE/" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-cache"{print $2}'
}
status_code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "$NODE/"; }
x_cache_path() { # host path -> value of X-Cache
  curl -s -o /dev/null -D - -H "Host: $1" "$NODE$2" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-cache"{print $2}'
}
applied_is() { [ "$(curl -fsS "$HELPER/applied")" = "$1" ]; }

compose up -d --build --quiet-pull
wait_for "fake console" curl -fsS "$HELPER/pin"
wait_for "node data plane" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' $NODE/)\" = 404 ]"

code=$(status_code demo.test)
[ "$code" = 404 ] || fail "before enrollment: demo.test returned $code, want 404"
hdr=$(curl -s -o /dev/null -D - -H 'Host: demo.test' "$NODE/" | tr -d '\r' | grep -i '^x-edgeweir-error:' || true)
[ "$hdr" = "X-Edgeweir-Error: unknown-host" ] || fail "missing X-Edgeweir-Error header: '$hdr'"
pass "404 unknown-host before enrollment"

PIN=$(curl -fsS "$HELPER/pin")
TOKEN=$(curl -fsS "$HELPER/token")
compose exec -T node edgeweir-node enroll --server https://console:8443 --token "$TOKEN" --ca-sha256 "$PIN"
pass "enrolled while run is running"

wait_for "revision 1 applied" applied_is "1 APPLY_STATE_APPLIED"
compose logs node | grep "switched to mTLS channel node_id=node-e2e" >/dev/null || fail "no 'switched to mTLS channel' log line"
pass "revision 1 applied and reported over mTLS"

# Probe a different path so that "/" is still uncached below.
wait_for "demo.test routed" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.test' $NODE/e2e-probe)\" = 200 ]"
first=$(x_cache demo.test)
second=$(x_cache demo.test)
[ "$first" = MISS ] || fail "first request X-Cache=$first, want MISS"
[ "$second" = HIT ] || fail "second request X-Cache=$second, want HIT"
curl -fsS -H 'Host: demo.test' "$NODE/" | grep "Hostname:" >/dev/null || fail "response is not from the whoami origin"
pass "demo.test: MISS then HIT, served by the origin"

# whoami echoes the request headers it received: no X-Edgeweir-* header
# may reach the origin, even behind 150 other headers.
pad=()
for i in $(seq 1 150); do pad+=(-H "X-Pad-$i: v"); done
echoed=$(curl -fsS -H 'Host: demo.test' "${pad[@]}" -H 'X-Edgeweir-Site: site-other' \
  -H 'X-Edgeweir-TTL: 99999' -H 'X-Edgeweir-Injected: evil' "$NODE/spoof")
echo "$echoed" | grep "X-Pad-150" >/dev/null || fail "origin did not receive the request"
if echo "$echoed" | grep -i "x-edgeweir" >/dev/null; then fail "internal headers reached the origin"; fi
pass "client-supplied X-Edgeweir-* headers never reach the origin"

# PROXY protocol listener: origins see the client address from the PROXY
# header, not the load balancer's.
pp_request() {
  exec 3<>"/dev/tcp/127.0.0.1/${E2E_PP_PORT:-28081}"
  printf 'PROXY TCP4 198.51.100.23 10.0.0.1 40000 8081\r\nGET /pp HTTP/1.1\r\nHost: demo.test\r\nConnection: close\r\n\r\n' >&3
  cat <&3
  exec 3<&-
}
echoed=$(pp_request | tr -d '\r')
echo "$echoed" | grep -qi "^X-Real-Ip: 198.51.100.23$" || fail "origin did not see the PROXY protocol client address: $(echo "$echoed" | grep -i -e x-real-ip -e x-forwarded-for)"
echo "$echoed" | grep -qi "^X-Forwarded-For: 198.51.100.23$" || fail "X-Forwarded-For is not the PROXY protocol client address"
pass "PROXY protocol client address reaches the origin"

# Origin address policy (special-purpose addresses) and CDN-Loop.
NODE_ID=$(curl -fsS "$HELPER/node-id")
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
CDN_ID="edgeweir-$(printf '%s' "$NODE_ID" | sha256 | cut -c1-16)"
echoed=$(curl -fsS -H 'Host: demo.test' -H 'CDN-Loop: other-cdn.example; v=1' "$NODE/cdn-loop")
echo "$echoed" | tr -d '\r' | grep -qi "^Cdn-Loop: other-cdn.example; v=1, $CDN_ID\$" ||
  fail "origin did not receive CDN-Loop with this node's cdn-id appended: $(echo "$echoed" | grep -i cdn-loop)"
pass "CDN-Loop forwarded with this node's cdn-id ($CDN_ID)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.test' -H "CDN-Loop: x, $CDN_ID" "$NODE/looped")
[ "$code" = 508 ] || fail "request carrying this node's cdn-id returned $code, want 508"
code=$(status_code loop.test)
[ "$code" = 508 ] || fail "origin pointing back at the node returned $code, want 508 (loop detected)"
pass "loops are rejected with 508"
code=$(status_code forbidden.test)
[ "$code" = 502 ] || fail "origin 127.0.0.1 returned $code, want 502"
code=$(status_code hidden.test)
[ "$code" = 502 ] || fail "origin resolving outside the allow list returned $code, want 502"
compose logs node | grep "special-purpose address" >/dev/null || fail "refused origin not reported as a warning"
origin_health_has() { curl -fsS "$HELPER/origin-health" | grep -q -- "$1"; }
WAIT_SECS=30 wait_for "DNS answer refusal in origin health" origin_health_has "^site-hidden o1 address_forbidden dns hidden: every address"
WAIT_SECS=30 wait_for "literal refusal in origin health" origin_health_has "^site-forbidden o1 address_forbidden address 127.0.0.1 is a special-purpose address"
pass "special-purpose origins refused (literal and DNS answer), allow-listed Docker network served"

# Origin HTTPS verifies the origin's configured name (SNI) against the
# trusted CA. tls-ok and tls-bad share the same address and port: a
# connection verified for origin.test must never be reused for wrong.test.
body=$(curl -s -H 'Host: tls-ok.test' "$NODE/tls-1")
echo "$body" | grep -q "tls origin ok sni=origin.test" || fail "trusted CA + matching name: got '$body'"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tls-bad.test' "$NODE/tls-2")
[ "$code" = 502 ] || fail "trusted CA + wrong name returned $code, want 502"
body=$(curl -s -H 'Host: tls-ok.test' "$NODE/tls-3")
echo "$body" | grep -q "tls origin ok sni=origin.test" || fail "matching name after a mismatch: got '$body'"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tls-bad.test' "$NODE/tls-4")
[ "$code" = 502 ] || fail "wrong name after a verified connection returned $code, want 502 (connection reused?)"
WAIT_SECS=30 wait_for "tls_failed in origin health" origin_health_has "^site-tls-bad o1 tls_failed "
pass "origin HTTPS: trusted CA + matching name 200, wrong name 502 (tls_failed)"

# The cache key sees every header (not only the first 100): a key header
# behind 150 others still splits the variants.
x_cache_keyed() { # accept-language
  curl -s -o /dev/null -D - -H 'Host: keyed.test' "${pad[@]}" -H "Accept-Language: $1" "$NODE/keyed" |
    tr -d '\r' | awk -F': ' 'tolower($1)=="x-cache"{print $2}'
}
[ "$(x_cache_keyed de)" = MISS ] || fail "keyed.test first request is not a MISS"
[ "$(x_cache_keyed de)" = HIT ] || fail "keyed.test second request is not a HIT"
[ "$(x_cache_keyed en)" = MISS ] || fail "another Accept-Language behind 150 headers shares the cached variant"
curl -fsS -H 'Host: keyed.test' "${pad[@]}" -H 'Accept-Language: en' "$NODE/keyed" | grep -q "Accept-Language: en" ||
  fail "keyed.test served the wrong variant"
pass "cache key reads every request header"

# RFC 9111 3.5: requests with Authorization bypass the cache unless the
# rule sets cache_authorized.
x_cache_auth() { # host path
  curl -s -o /dev/null -D - -H "Host: $1" -H 'Authorization: Bearer e2e' "$NODE$2" |
    tr -d '\r' | awk -F': ' 'tolower($1)=="x-cache"{print $2}'
}
[ "$(x_cache_auth demo.test /auth)" = BYPASS ] || fail "Authorization request was looked up in the cache"
[ "$(x_cache_auth demo.test /auth)" = BYPASS ] || fail "Authorization response was stored"
[ "$(x_cache_path demo.test /auth)" = MISS ] || fail "anonymous request after Authorization requests is not a MISS"
[ "$(x_cache_auth auth.test /auth)" = MISS ] || fail "cache_authorized rule: first request is not a MISS"
[ "$(x_cache_auth auth.test /auth)" = HIT ] || fail "cache_authorized rule: second request is not a HIT"
pass "Authorization bypasses the cache unless the rule allows it"

# Purges match nginx's normalized path: /%73tatic/ is /static/.
[ "$(x_cache_path demo.test /%73tatic/e2e.js)" = MISS ] || fail "/%73tatic/e2e.js first request is not a MISS"
[ "$(x_cache_path demo.test /static/e2e.js)" = HIT ] || fail "/static/e2e.js does not share the key of /%73tatic/e2e.js"
task=$(curl -fsS -X POST "$HELPER/purge-prefix?site=site-demo&host=demo.test&path=/static/")
wait_for "purge task $task" sh -c "curl -fsS $HELPER/task-results | grep -q '^$task TASK_STATE_SUCCEEDED'"
[ "$(x_cache_path demo.test /%73tatic/e2e.js)" = MISS ] || fail "prefix purge of /static/ did not cover /%73tatic/e2e.js"
pass "prefix purge covers percent-encoded variants"

reloads_before=$(compose logs node | grep -c "nginx configuration installed and reloaded" || true)
rev=$(curl -fsS -X POST "$HELPER/publish")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
[ "$(status_code demo2.test)" = 200 ] || fail "demo2.test not served after adding its partition"
reloads_after=$(compose logs node | grep -c "nginx configuration installed and reloaded" || true)
[ "$reloads_after" -eq "$((reloads_before + 1))" ] || fail "new site must add one structural reload ($reloads_before -> $reloads_after)"
pass "revision $rev added a dedicated site partition"

reloads_before=$reloads_after
rev=$(curl -fsS -X POST "$HELPER/update")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
[ "$(status_code alias.demo2.test)" = 200 ] || fail "existing-site alias not served after hot update"
reloads_after=$(compose logs node | grep -c "nginx configuration installed and reloaded" || true)
[ "$reloads_before" = "$reloads_after" ] || fail "existing-site change reloaded nginx ($reloads_before -> $reloads_after)"
pass "revision $rev hot-updated without nginx reload"

compose restart node >/dev/null
wait_for "node back after restart" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo2.test' $NODE/)\" = 200 ]"
compose logs node | grep "serving last-known-good configuration" >/dev/null || fail "LKG not restored on restart"
pass "last-known-good configuration served after restart"

if [ "${E2E_STATS:-0}" = "1" ]; then
  # Buckets are uploaded once their minute is complete (agent drains every 60s).
  WAIT_SECS=180 wait_for "stats uploaded" sh -c "[ \"\$(curl -fsS $HELPER/stats | cut -d' ' -f1)\" != 0 ]"
  pass "per-minute stats uploaded ($(curl -fsS "$HELPER/stats"))"
fi

echo "e2e smoke test passed"
