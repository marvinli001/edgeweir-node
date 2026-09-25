#!/usr/bin/env bash
# Container smoke test for edgeweir-node:
#   1. the node container serves 404 unknown-host before enrollment;
#   2. `docker compose exec node edgeweir-node enroll ...` while `run` is
#      running switches the node to mTLS and applies revision 1;
#   3. demo.test is proxied to the whoami origin: first MISS, then HIT;
#   4. a site-only revision is hot-updated (no reload) and reported;
#   5. restarting the container serves the last-known-good config.
# Set E2E_KEEP=1 to keep the stack running afterwards.
set -euo pipefail
cd "$(dirname "$0")"

NODE="http://127.0.0.1:${E2E_NODE_PORT:-28080}"
HELPER="http://127.0.0.1:${E2E_HELPER_PORT:-28090}"
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

reloads_before=$(compose logs node | grep -c "nginx configuration installed and reloaded" || true)
rev=$(curl -fsS -X POST "$HELPER/publish")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
[ "$(status_code demo2.test)" = 200 ] || fail "demo2.test not served after hot update"
reloads_after=$(compose logs node | grep -c "nginx configuration installed and reloaded" || true)
[ "$reloads_before" = "$reloads_after" ] || fail "site-only change reloaded nginx ($reloads_before -> $reloads_after)"
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
