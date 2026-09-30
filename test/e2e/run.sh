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
#   6. dynamic bans: a site ban answers 403 ip-banned on that site only, a
#      platform ban on every site, unbanning restores access (the node has
#      no NET_ADMIN here: bans stay at the edge layer);
#   7. challenges: Under Attack with cookie302 (302 + pass, bound to the
#      client), js and pow (token redeemed once at /.edgeweir/challenge/verify,
#      303 + pass), 403 for other methods without a pass, the reserved
#      prefix never reaches the origin;
#   8. CC: an address over its rate is banned and reported, the site level
#      rises under load (edgeweir-node security shows it), stays through a
#      threshold change and starts from normal after the policy was off;
#   9. a new site reserves its partition; later existing-site changes stay hot;
#  10. restarting the container serves the last-known-good config.
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
  [ -n "${TMPDIR_E2E:-}" ] && rm -rf "$TMPDIR_E2E"
  if [ "${E2E_KEEP:-0}" != "1" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT
TMPDIR_E2E=$(mktemp -d)

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
pp_request() { # [host [client address [path]]]
  exec 3<>"/dev/tcp/127.0.0.1/${E2E_PP_PORT:-28081}"
  printf 'PROXY TCP4 %s 10.0.0.1 40000 8081\r\nGET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "${2:-198.51.100.23}" "${3:-/pp}" "${1:-demo.test}" >&3
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

# Dynamic bans, with the client address taken from the PROXY protocol.
# (Responses are read completely first: with pipefail an early grep -q
# would fail the pipeline through SIGPIPE.)
pp_status() { local r; r=$(pp_request "$1" "$2" "/ban-$RANDOM" | tr -d '\r'); echo "$r" | sed -n '1s/^HTTP[^ ]* \([0-9]*\).*/\1/p'; }
pp_banned() { local r; r=$(pp_request "$1" "$2" /banned | tr -d '\r'); grep -qi '^X-Edgeweir-Error: ip-banned$' <<<"$r"; }
resp=$(curl -fsS -X POST "$HELPER/ban?site=site-demo&cidr=198.51.100.23/32") # "<id> <sequence>"
site_ban=${resp% *}
WAIT_SECS=10 wait_for "site ban $site_ban" pp_banned demo.test 198.51.100.23
[ "$(pp_status keyed.test 198.51.100.23)" = 200 ] || fail "a site ban of demo.test also blocked keyed.test"
[ "$(pp_status demo.test 198.51.100.24)" = 200 ] || fail "the site ban blocked a neighbouring address"
resp=$(curl -fsS -X POST "$HELPER/ban?cidr=198.51.100.0/24")
platform_ban=${resp% *} seq=${resp#* }
WAIT_SECS=10 wait_for "platform ban $platform_ban" pp_banned keyed.test 198.51.100.24
[ "$(pp_status demo.test 203.0.113.9)" = 200 ] || fail "the platform ban blocked an address outside it"
ban_status_is() { curl -fsS "$HELPER/ban-status" | grep -q "^$1 2 0 0 no$"; }
WAIT_SECS=30 wait_for "ban status reported" ban_status_is "$seq"
listed=$(compose exec -T node edgeweir-node bans --list)
grep -q '"cidr": "198.51.100.0/24"' <<<"$listed" || fail "edgeweir-node bans does not list the platform ban: $listed"
curl -fsS -X POST "$HELPER/unban?id=$platform_ban" >/dev/null
seq=$(curl -fsS -X POST "$HELPER/unban?id=$site_ban")
pp_allowed() { [ "$(pp_status "$1" "$2")" = 200 ]; }
WAIT_SECS=10 wait_for "unbanned" pp_allowed demo.test 198.51.100.23
pp_allowed keyed.test 198.51.100.24 || fail "the platform ban outlived its removal"
pass "site ban 403 on its site only, platform ban on every site, unban restores access"

# Challenges. The node fetched the cluster's keys with the configuration.
hdrs() { curl -s -o /dev/null -D - "$@" | tr -d '\r'; }
status_of() { sed -n '1s/^HTTP[^ ]* \([0-9]*\).*/\1/p'; }
header_of() { awk -v h="$1" -F': ' 'tolower($1)==tolower(h){print $2}'; }
cookie_of() { header_of set-cookie | cut -d';' -f1; }
state=$(compose exec -T node edgeweir-node security)
grep -q '"current": "e2e-key-2"' <<<"$state" || fail "challenge keys not installed: $state"
resp=$(hdrs -H 'Host: ua.test' -A 'e2e-browser' "$NODE/ua-page?x=1")
[ "$(status_of <<<"$resp")" = 302 ] || fail "Under Attack cookie302 answered $(status_of <<<"$resp"), want 302"
[ "$(header_of x-edgeweir-challenge <<<"$resp")" = cookie302 ] || fail "no X-Edgeweir-Challenge: cookie302"
[ "$(header_of location <<<"$resp")" = "http://ua.test/ua-page?x=1" ] || fail "cookie302 Location: $(header_of location <<<"$resp")"
pass_cookie=$(cookie_of <<<"$resp")
case "$pass_cookie" in __ew_pass=v1.e2e-key-2.*) ;; *) fail "pass cookie: $pass_cookie" ;; esac
header_of set-cookie <<<"$resp" | grep -q '; HttpOnly; SameSite=Lax' || fail "pass cookie attributes: $(header_of set-cookie <<<"$resp")"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: ua.test' -A 'e2e-browser' -H "Cookie: $pass_cookie" "$NODE/ua-page?x=1")
[ "$code" = 200 ] || fail "request with the pass returned $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: ua.test' -A 'another-agent' -H "Cookie: $pass_cookie" "$NODE/ua-page")
[ "$code" = 302 ] || fail "pass accepted for another User-Agent ($code)"
forged=${pass_cookie%?}
case "$pass_cookie" in *A) forged="${forged}B" ;; *) forged="${forged}A" ;; esac
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: ua.test' -A 'e2e-browser' -H "Cookie: $forged" "$NODE/ua-page")
[ "$code" = 302 ] || fail "forged pass accepted ($code)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: js.test' -A 'e2e-browser' -H "Cookie: $pass_cookie" "$NODE/")
[ "$code" = 403 ] || fail "pass of ua.test accepted on js.test ($code)"
code=$(curl -s -L -o /dev/null -w '%{http_code}' -b '' -c /dev/null -A 'e2e-browser' --connect-to "ua.test:80:127.0.0.1:${E2E_NODE_PORT:-28080}" "http://ua.test/followed")
[ "$code" = 200 ] || fail "a client with cookies following redirects got $code"
resp=$(hdrs -X POST -H 'Host: ua.test' -d 'x=1' "$NODE/form")
[ "$(status_of <<<"$resp")" = 403 ] && [ "$(header_of x-edgeweir-challenge <<<"$resp")" = required ] ||
  fail "POST without a pass: $(status_of <<<"$resp") $(header_of x-edgeweir-challenge <<<"$resp")"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: ua.test' -A 'e2e-browser' -H "Cookie: $pass_cookie" -d 'x=1' "$NODE/form")
[ "$code" = 200 ] || fail "POST with a pass returned $code"
pass "Under Attack cookie302: 302 with a pass bound to site and User-Agent, POST without a pass 403"

verify() { # host token answer -> response headers
  hdrs -X POST -H "Host: $1" -A 'e2e-browser' --data-urlencode "t=$2" --data-urlencode "a=$3" --data-urlencode "r=/after?q=1" "$NODE/.edgeweir/challenge/verify"
}
page=$(curl -s -D "$TMPDIR_E2E/js.h" -H 'Host: js.test' -A 'e2e-browser' "$NODE/js-page")
[ "$(tr -d '\r' <"$TMPDIR_E2E/js.h" | status_of)" = 403 ] || fail "js challenge page status"
csp=$(tr -d '\r' <"$TMPDIR_E2E/js.h" | header_of content-security-policy)
nonce=$(sed -n "s/.*script-src 'nonce-\([^']*\)'.*/\1/p" <<<"$csp")
[ -n "$nonce" ] && grep -q "<script nonce=\"$nonce\">" <<<"$page" || fail "challenge page without its CSP nonce: $csp"
grep -q "default-src 'none'" <<<"$csp" && grep -q "frame-ancestors 'none'" <<<"$csp" || fail "CSP: $csp"
token=$(sed -n 's/.*name="t" value="\([^"]*\)".*/\1/p' <<<"$page" | head -1)
answer=$(printf '%s' "$token" | sha256 | cut -d' ' -f1)
resp=$(verify js.test "$token" "$answer")
[ "$(status_of <<<"$resp")" = 303 ] && [ "$(header_of location <<<"$resp")" = "http://js.test/after?q=1" ] ||
  fail "js verify: $(status_of <<<"$resp") $(header_of location <<<"$resp")"
js_cookie=$(cookie_of <<<"$resp")
[ -n "$js_cookie" ] || fail "js verify set no pass"
resp=$(verify js.test "$token" "$answer")
[ "$(status_of <<<"$resp")" = 303 ] && [ -z "$(cookie_of <<<"$resp")" ] || fail "a redeemed token was accepted again"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: js.test' -A 'e2e-browser' -H "Cookie: $js_cookie" "$NODE/after?q=1")
[ "$code" = 200 ] || fail "js pass returned $code"
pass "js challenge: CSP nonce, token redeemed once, 303 with a pass"

page=$(curl -s -H 'Host: pow.test' -A 'e2e-browser' "$NODE/pow-page")
token=$(sed -n 's/.*name="t" value="\([^"]*\)".*/\1/p' <<<"$page" | head -1)
grep -q 'data-d="8"' <<<"$page" || fail "pow page without the site's difficulty"
n=0
until printf '%s:%d' "$token" "$n" | sha256 | grep -q '^00'; do n=$((n + 1)); done
resp=$(verify pow.test "$token" "$n")
[ "$(status_of <<<"$resp")" = 303 ] && [ -n "$(cookie_of <<<"$resp")" ] || fail "pow verify with n=$n: $(status_of <<<"$resp")"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: pow.test' -A 'e2e-browser' -H "Cookie: $(cookie_of <<<"$resp")" "$NODE/pow-page")
[ "$code" = 200 ] || fail "pow pass returned $code"
worker=$(hdrs -H 'Host: pow.test' "$NODE/.edgeweir/challenge/worker.js")
[ "$(status_of <<<"$worker")" = 200 ] && header_of content-type <<<"$worker" | grep -q javascript || fail "worker script: $worker"
resp=$(hdrs -H 'Host: demo.test' "$NODE/.edgeweir/other")
[ "$(status_of <<<"$resp")" = 404 ] && [ "$(header_of x-edgeweir-error <<<"$resp")" = not-found ] || fail "reserved prefix reached the origin: $resp"
pass "pow challenge (8 bits), worker script, reserved prefix answered at the edge"

token_of() { sed -n 's/.*name="t" value="\([^"]*\)".*/\1/p' | head -1; }
page=$(curl -s -H 'Host: captcha.test' -A 'e2e-browser' -H 'Accept-Language: zh-CN,zh;q=0.9' "$NODE/c")
grep -q 'src="data:image/png;base64,' <<<"$page" && grep -q 'name="alt" value="pow"' <<<"$page" && grep -q '<html lang="zh-CN">' <<<"$page" ||
  fail "captcha page without image, alternative or Chinese text"
token=$(token_of <<<"$page")
page=$(curl -s -X POST -H 'Host: captcha.test' -A 'e2e-browser' --data-urlencode "t=$token" --data-urlencode "a=ZZZZZ" --data-urlencode "r=/c" "$NODE/.edgeweir/challenge/verify")
grep -q 'role="alert"' <<<"$page" || fail "wrong captcha answer without an error message"
token=$(token_of <<<"$page")
page=$(curl -s -X POST -H 'Host: captcha.test' -A 'e2e-browser' --data-urlencode "t=$token" --data-urlencode "alt=pow" --data-urlencode "r=/c" "$NODE/.edgeweir/challenge/verify")
grep -q 'data-d="8"' <<<"$page" || fail "captcha alternative is not the high-difficulty proof of work"
token=$(token_of <<<"$page")
n=0
until printf '%s:%d' "$token" "$n" | sha256 | grep -q '^00'; do n=$((n + 1)); done
resp=$(verify captcha.test "$token" "$n")
[ "$(status_of <<<"$resp")" = 303 ] && [ -n "$(cookie_of <<<"$resp")" ] || fail "high-difficulty proof of work: $(status_of <<<"$resp")"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: captcha.test' -A 'e2e-browser' -H "Cookie: $(cookie_of <<<"$resp")" "$NODE/c")
[ "$code" = 200 ] || fail "captcha-level pass from the proof of work returned $code"
pass "captcha: image page in Chinese, wrong answer shown, accessible proof of work grants the captcha level"

# CC: one address over 2 requests per second is banned and reported.
cc_codes=""
for _ in $(seq 1 14); do cc_codes="$cc_codes $(pp_status cc.test 203.0.113.50)"; done
grep -q 403 <<<"$cc_codes" || fail "no CC ban after 14 requests: $cc_codes"
[ "$(pp_status cc.test 203.0.113.51)" = 200 ] || fail "the CC ban hit another address"
pp_banned cc.test 203.0.113.50 || fail "the banned address still reaches cc.test"
security_event() { curl -fsS "$HELPER/security-events" | grep -q "^$1"; }
WAIT_SECS=30 wait_for "ip_banned event" security_event "ip_banned site-cc [a-z]* 203.0.113.50 ip_qps"
pass "CC: an address over its rate is banned once and reported"

# CC: sustained load on the site raises its level to cookie302.
end=$((SECONDS + 9))
i=0
while [ "$SECONDS" -lt "$end" ]; do
  i=$((i + 1))
  pp_status cc.test "198.18.$((i / 200)).$((i % 200 + 1))" >/dev/null &
  [ $((i % 10)) -eq 0 ] && { wait; sleep 0.1; }
done
wait
level_is() { compose exec -T node edgeweir-node security | grep -A2 '"site_id": "site-cc"' | grep -q "\"level\": \"$1\""; }
WAIT_SECS=15 wait_for "site-cc at cookie302" level_is cookie302
resp=$(pp_request cc.test 192.0.2.77 /under-load | tr -d '\r')
[ "$(status_of <<<"$resp")" = 302 ] && grep -qi '^X-Edgeweir-Challenge: cookie302$' <<<"$resp" || fail "CC level not applied: $(head -1 <<<"$resp")"
WAIT_SECS=30 wait_for "site_level event" security_event "site_level site-cc cookie302"
pass "CC: sustained load raised site-cc to cookie302 ($i requests)"

# CC: other thresholds keep the level; off and on again starts from normal.
rev=$(curl -fsS -X POST "$HELPER/cc?site_qps=40")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
level_is cookie302 || fail "a threshold change reset the CC level"
rev=$(curl -fsS -X POST "$HELPER/cc?enabled=false")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
state=$(compose exec -T node edgeweir-node security)
! grep -q '"site_id": "site-cc"' <<<"$state" || fail "site-cc listed with CC off"
[ "$(pp_status cc.test 192.0.2.78)" = 200 ] || fail "site-cc challenged with CC off"
sleep 2 # the next evaluation (every second) clears the state
rev=$(curl -fsS -X POST "$HELPER/cc?site_qps=40")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
level_is normal || fail "CC turned off and on again kept its level: $(compose exec -T node edgeweir-node security)"
[ "$(pp_status cc.test 192.0.2.79)" = 200 ] || fail "site-cc challenged after CC was turned off and on again"
pass "CC: a threshold change keeps the level, off and on again starts from normal"

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
compose exec -T node edgeweir-node security | grep -q '"current": "e2e-key-2"' || fail "challenge keys not restored on restart"
pass "last-known-good configuration served after restart"

if [ "${E2E_STATS:-0}" = "1" ]; then
  # Buckets are uploaded once their minute is complete (agent drains every 60s).
  WAIT_SECS=180 wait_for "stats uploaded" sh -c "[ \"\$(curl -fsS $HELPER/stats | cut -d' ' -f1)\" != 0 ]"
  pass "per-minute stats uploaded ($(curl -fsS "$HELPER/stats"))"
fi

echo "e2e smoke test passed"
