#!/usr/bin/env bash
# Container smoke test for edgeweir-node:
#   1. the node container serves 404 unknown-host before enrollment;
#   2. `docker compose exec node edgeweir-node enroll ...` while `run` is
#      running switches the node to mTLS and applies revision 1; OpenResty
#      runs under the supervisor and keeps running when the agent restarts;
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
#   9. compression: one coding per response by q-value (zstd > br > gzip)
#      from one cached identity object, curl --compressed decodes each;
#  10. OWASP CRS: detect logs without blocking, block answers 403 for the
#      CRS test payloads (cache hits included), excluded rules stay quiet,
#      sites without CRS are unaffected, matched rules reach the logs;
#  11. Cache-Tag: hidden unless the site keeps it (cache hits included), a
#      tag purge through the control socket moves tagged objects only, also
#      when only a slice subrequest or a background update saw the tag;
#      stale-if-error after one origin attempt; request ids; error pages
#      (built-in, site and platform pages, offline and unknown hosts,
#      origin failures, intercepted origin errors, CRS blocks, bans,
#      requests nginx refuses, CRS 400s, HEAD); session affinity;
#  12. tasks from the console: purges by Cache-Tag and by host, a sitemap
#      prefetch (gzipped index, both device variants); an active health
#      check takes a failing origin out of rotation and brings it back;
#  13. rules-v2: a dynamic redirect with query edits, bulk redirects, a
#      rewrite to another origin group with its own Host, a port override,
#      config rules (read timeout, sampled log, WebSocket, Under Attack),
#      a cache rule condition with a browser TTL, compression rules and
#      config gzip=false on a cached object;
#  14. HTTP/2 to origins (h2c, h2 over TLS, request bodies, WebSocket
#      still HTTP/1.1, no fallback, health probes over HTTP/2) and gRPC end
#      to end (unary, bidirectional streaming, error trailers, past the CRS,
#      421 for h2c to a site without gRPC);
#  15. a new site reserves its partition; later existing-site changes stay hot;
#  16. probes: GET /.edgeweir/health answers 200 ok for any Host on HTTP,
#      PROXY protocol and HTTPS (the health certificate for SNI
#      health.edgeweir.invalid and without SNI, nothing but the health path
#      on such connections), ahead of loops, bans and challenges; the node
#      probes its peer (never itself) while the console lets it, and
#      `edgeweir-node probe` enrolls and reports; heartbeats carry host
#      metrics;
#  17. layer-4 applications: TCP and UDP echo through the node's stream
#      servers, PROXY protocol v1 and v2 headers seen by the origin
#      (nginx's own, and the relay passing on the client's address from
#      the header it received), a block list and a connection limit
#      refuse, a dead origin is retried past and held down, a long TCP
#      connection survives the reload that adds a port, an origin change
#      applies without a reload (E2E_STATS=1: their minute statistics);
#  18. restarting the container serves the last-known-good config.
# Set E2E_KEEP=1 to keep the stack running afterwards; E2E_NODE_IMAGE names
# the node image (default edgeweir-node:e2e-smoke).
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
# control METHOD PATH [BODY]: the node's control API (unix socket), through
# perl in the node container (the image has no curl).
control() {
  compose exec -T node perl -MIO::Socket::UNIX -e '
    my ($m, $p, $b) = @ARGV; $b = "" unless defined $b;
    my $s = IO::Socket::UNIX->new(Peer => "/run/edgeweir-node/control.sock") or die "control socket: $!";
    print $s "$m $p HTTP/1.0\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: " . length($b) . "\r\n\r\n$b";
    local $/; my $r = <$s>; $r =~ s/^.*?\r\n\r\n//s; print $r;' "$@"
}

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

# OpenResty runs under the supervisor (PID 1), not the agent: an agent that
# stops (an upgrade, a crash) leaves it serving.
proc_pid() { # cmdline regex -> pid and parent pid of the first match
  compose exec -T node perl -e 'for my $d (glob "/proc/[0-9]*") { open my $f, "<", "$d/cmdline" or next; my $c = <$f> // "";
    next unless $c =~ /$ARGV[0]/; open my $s, "<", "$d/status" or next; my ($pp) = map { /^PPid:\s+(\d+)/ ? $1 : () } <$s>;
    $d =~ s{.*/}{}; print "$d $pp\n"; last }' "$1"
}
compose logs node | grep "OpenResty runs under the supervisor" >/dev/null || fail "the agent runs OpenResty itself"
read -r master master_parent <<<"$(proc_pid '^nginx: master')"
[ "$master_parent" = 1 ] || fail "nginx master $master has parent $master_parent, want the supervisor (1)"
read -r agent _ <<<"$(proc_pid '^\S*edgeweir-node\0run')"
compose exec -T node perl -e 'kill "TERM", $ARGV[0] or die "kill: $!"' "$agent"
agent_back() { [ "$(compose logs node | grep -c 'supervisor started node')" -ge 2 ] && applied_is "1 APPLY_STATE_APPLIED"; }
WAIT_SECS=30 wait_for "agent restarted by the supervisor" agent_back
read -r master_after _ <<<"$(proc_pid '^nginx: master')"
[ "$master_after" = "$master" ] || fail "nginx master changed from $master to $master_after when the agent restarted"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.test' "$NODE/e2e-agent-restart")
[ "$code" = 200 ] || fail "demo.test after the agent restarted: $code"
pass "OpenResty runs under the supervisor and keeps serving while the agent restarts"

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

# Bans answer with the site's error page (or the built-in one).
resp=$(curl -fsS -X POST "$HELPER/ban?site=site-pages&cidr=198.51.100.77/32")
page_ban=${resp% *}
WAIT_SECS=10 wait_for "site ban $page_ban" pp_banned pages.test 198.51.100.77
r=$(pp_request pages.test 198.51.100.77 /banned-page | tr -d '\r')
grep -q '^Content-Type: text/html; charset=utf-8$' <<<"$r" && grep -q '^Cache-Control: no-store$' <<<"$r" ||
  fail "ban page headers: $(head -12 <<<"$r")"
rid=$(sed -n 's/^X-Request-Id: //p' <<<"$r")
grep -q "<h1>pages.test 403 198.51.100.77 $rid</h1>" <<<"$r" || fail "ban without the site's page: $(tail -1 <<<"$r")"
curl -fsS -X POST "$HELPER/unban?id=$page_ban" >/dev/null
WAIT_SECS=10 wait_for "unbanned pages.test" pp_allowed pages.test 198.51.100.77
pass "a ban answers with the site's 403 page (status, client address, request id)"

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
[ "$(status_of <<<"$resp")" = 403 ] && [ "$(header_of x-edgeweir-challenge <<<"$resp")" = required ] &&
  [ "$(header_of content-type <<<"$resp")" = "text/plain; charset=utf-8" ] && [ -z "$(header_of x-edgeweir-error <<<"$resp")" ] ||
  fail "POST without a pass: $(status_of <<<"$resp") $(header_of x-edgeweir-challenge <<<"$resp") $(header_of content-type <<<"$resp")"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: ua.test' -A 'e2e-browser' -H "Cookie: $pass_cookie" -d 'x=1' "$NODE/form")
[ "$code" = 200 ] || fail "POST with a pass returned $code"
pass "Under Attack cookie302: 302 with a pass bound to site and User-Agent, POST without a pass 403"

# HTTP-01 tokens that are not the node's go to the origin, uncached and
# unchallenged (the origin's own certificates).
for host in demo.test ua.test; do
  resp=$(curl -s -D - -H "Host: $host" "$NODE/.well-known/acme-challenge/origin-token_1" | tr -d '\r')
  [ "$(status_of <<<"$resp")" = 200 ] && grep -q "^Hostname:" <<<"$resp" && [ "$(header_of x-cache <<<"$resp")" = BYPASS ] ||
    fail "foreign HTTP-01 token on $host: $(head -1 <<<"$resp") X-Cache $(header_of x-cache <<<"$resp")"
done
pass "HTTP-01 tokens of the origin reach the origin, uncached, also under Under Attack"

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

# The probes' health endpoint (probe-health-v1): any Host, ahead of loops,
# challenges and bans, never cached.
health_ok() { # response headers and body
  [ "$(status_of <<<"$1")" = 200 ] && [ "$(header_of content-type <<<"$1")" = text/plain ] &&
    [ "$(header_of cache-control <<<"$1")" = no-store ] && [ "$(header_of content-length <<<"$1")" = 2 ] &&
    [ -z "$(header_of x-cache <<<"$1")" ] && [ "$(tail -1 <<<"$1")" = ok ]
}
for h in unknown.test demo.test ua.test health.edgeweir.invalid; do
  r=$(curl -s -D - -H "Host: $h" -A e2e-browser "$NODE/.edgeweir/health?x=1" | tr -d '\r')
  health_ok "$r" || fail "health endpoint for Host $h: $r"
done
r=$(curl -s -D - -H 'Host: demo.test' -H "CDN-Loop: $CDN_ID" "$NODE/.edgeweir/health" | tr -d '\r')
health_ok "$r" || fail "health endpoint with this node's CDN-Loop: $(status_of <<<"$r")"
[ "$(curl -s -o /dev/null -w '%{http_code}' -I -H 'Host: unknown.test' "$NODE/.edgeweir/health")" = 200 ] || fail "HEAD /.edgeweir/health"
r=$(pp_request unknown.test 198.51.100.99 /.edgeweir/health | tr -d '\r')
health_ok "$r" || fail "health endpoint on the PROXY protocol listener: $r"
resp=$(curl -fsS -X POST "$HELPER/ban?cidr=198.51.100.66/32")
health_ban=${resp% *}
WAIT_SECS=10 wait_for "platform ban $health_ban" pp_banned demo.test 198.51.100.66
r=$(pp_request demo.test 198.51.100.66 /.edgeweir/health | tr -d '\r')
health_ok "$r" || fail "health endpoint for a banned address: $(status_of <<<"$r")"
curl -fsS -X POST "$HELPER/unban?id=$health_ban" >/dev/null
pass "health endpoint: 200 ok for any Host, HEAD, PROXY protocol, loops, challenges and bans do not apply"

tls_health() { curl -fsS "$HELPER/tls-health?$1"; }
[ "$(tls_health 'sni=health.edgeweir.invalid')" = "health.edgeweir.invalid 200 ok" ] ||
  fail "HTTPS health with SNI health.edgeweir.invalid: $(tls_health 'sni=health.edgeweir.invalid')"
[ "$(tls_health 'sni=HEALTH.edgeweir.INVALID&host=demo.test')" = "health.edgeweir.invalid 200 ok" ] ||
  fail "HTTPS health, SNI in another case, Host of a site"
[ "$(tls_health 'sni=')" = "health.edgeweir.invalid 200 ok" ] || fail "HTTPS health without SNI: $(tls_health 'sni=')"
case "$(tls_health 'sni=health.edgeweir.invalid&path=/')" in "health.edgeweir.invalid 421 "*) ;;
  *) fail "health SNI reached another path: $(tls_health 'sni=health.edgeweir.invalid&path=/')" ;; esac
case "$(tls_health 'sni=&host=demo.test&path=/.well-known/acme-challenge/x')" in "health.edgeweir.invalid 421 "*) ;;
  *) fail "no-SNI connection reached a site: $(tls_health 'sni=&host=demo.test&path=/.well-known/acme-challenge/x')" ;; esac
case "$(tls_health 'sni=unknown.test')" in handshake-failed*) ;; *) fail "unknown SNI completed a handshake" ;; esac
case "$(tls_health 'sni=old.test')" in handshake-failed*) ;; *) fail "SNI of a disabled site completed a handshake" ;; esac
key_mode=$(compose exec -T node stat -c '%a' /var/lib/edgeweir-node/health.key)
[ "$key_mode" = 600 ] || fail "health.key mode $key_mode"
pass "HTTPS health: self-signed health certificate for SNI health.edgeweir.invalid and no SNI, 421 for anything else"

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

# The node's OpenResty has Brotli, Zstandard and ModSecurity with the CRS.
features=$(curl -fsS "$HELPER/features")
for f in brotli-v1 zstd-v1 modsecurity-v1; do
  grep -qx "$f" <<<"$features" || fail "feature $f not reported: $features"
done
pass "brotli-v1, zstd-v1 and modsecurity-v1 reported"

# Compression, seen by a client inside the compose network (curl with
# Brotli and Zstandard). The origin gets no Accept-Encoding; the cached
# identity object serves every coding.
client() { compose run --rm --no-deps -T client "$@" 2>/dev/null; }
encoding() { # accept-encoding path -> "<x-cache> <content-encoding or -> <vary>"
  client -s -o /dev/null -D - -H 'Host: compress.test' ${1:+-H "Accept-Encoding: $1"} "http://node$2" |
    tr -d '\r' | awk -F': ' '
      tolower($1)=="x-cache" { c=$2 } tolower($1)=="content-encoding" { e=$2 } tolower($1)=="vary" { v=v $2 }
      END { print c, (e==""?"-":e), (v==""?"-":v) }'
}
[ "$(encoding 'gzip, deflate, br, zstd' /packed)" = "MISS zstd Accept-Encoding" ] || fail "zstd client (MISS): $(encoding 'gzip, deflate, br, zstd' /packed2)"
[ "$(encoding 'gzip, deflate, br' /packed)" = "HIT br Accept-Encoding" ] || fail "br client on the cached object: $(encoding 'gzip, deflate, br' /packed)"
[ "$(encoding 'gzip' /packed)" = "HIT gzip Accept-Encoding" ] || fail "gzip client on the cached object: $(encoding gzip /packed)"
[ "$(encoding '' /packed)" = "HIT - Accept-Encoding" ] || fail "identity client on the cached object: $(encoding '' /packed)"
[ "$(encoding 'zstd;q=0, br;q=0.5, gzip' /packed)" = "HIT gzip Accept-Encoding" ] || fail "q-values ignored: $(encoding 'zstd;q=0, br;q=0.5, gzip' /packed)"
[ "$(encoding 'br;q=1, zstd;q=1' /packed)" = "HIT zstd Accept-Encoding" ] || fail "equal q-values must prefer zstd"
plain=$(client -s -H 'Host: compress.test' http://node/packed)
grep -q "Hostname:" <<<"$plain" || fail "compress.test not served by the origin: $plain"
if grep -qi "^Accept-Encoding:" <<<"$plain"; then fail "the origin received Accept-Encoding for a site the edge compresses"; fi
for enc in zstd br gzip; do
  decoded=$(client -s --compressed -H 'Host: compress.test' -H "Accept-Encoding: $enc" http://node/packed)
  [ "$decoded" = "$plain" ] || fail "$enc response does not decode to the cached object"
done
hdr=$(client -s -o /dev/null -D - --compressed -H 'Host: compress.test' http://node/packed | tr -d '\r' | grep -i '^content-encoding:')
[ "$hdr" = "content-encoding: zstd" ] || [ "$hdr" = "Content-Encoding: zstd" ] || fail "curl --compressed got '$hdr', want zstd"
pass "compression: zstd, br, gzip and identity from one cached object, by q-value, curl --compressed decodes"

# Compression rules: a rule's codings win over the default preference, an
# empty list sends identity; config gzip=false leaves the cache alone.
coded() { encoding "$1" "$2" | cut -d' ' -f1,2; }
[ "$(coded 'zstd, br, gzip' /gz-only)" = "MISS gzip" ] || fail "compression rule [gzip]: $(encoding 'zstd, br, gzip' /gz-only)"
[ "$(coded 'zstd, br, gzip' /no-compress)" = "MISS -" ] || fail "compression rule []: $(encoding 'zstd, br, gzip' /no-compress)"
[ "$(coded 'gzip' /no-gzip)" = "MISS -" ] || fail "config gzip=false (MISS): $(encoding gzip /no-gzip)"
[ "$(coded 'gzip' /no-gzip)" = "HIT -" ] || fail "config gzip=false on the cached object: $(encoding gzip /no-gzip)"
[ "$(coded 'gzip, br' /no-gzip)" = "HIT br" ] || fail "config gzip=false keeps br: $(encoding 'gzip, br' /no-gzip)"
pass "compression rules and config gzip=false without a cache bypass"

# OWASP CRS: the detect site logs, the block site answers 403, both on
# cache hits too; demo.test has no CRS.
crs() { # host [curl args...] -> "<status> <x-cache> <x-edgeweir-error>"
  local host=$1; shift
  curl -s -o /dev/null -D - -H "Host: $host" "$@" | tr -d '\r' | awk -F': ' '
    NR==1 { split($0, a, " "); s=a[2] } tolower($1)=="x-cache" { c=$2 } tolower($1)=="x-edgeweir-error" { e=$2 }
    END { print s, (c==""?"-":c), (e==""?"-":e) }'
}
XSS_REFERER='Referer: <script>alert(1)</script>'
[ "$(crs crs-detect.test "$NODE/crs-page")" = "200 MISS -" ] || fail "crs-detect first request: $(crs crs-detect.test "$NODE/crs-page")"
[ "$(crs crs-detect.test -H "$XSS_REFERER" "$NODE/crs-page")" = "200 HIT -" ] || fail "detect mode blocked a cache hit"
[ "$(crs crs-block.test "$NODE/crs-page")" = "200 MISS -" ] || fail "crs-block clean request"
[ "$(crs crs-block.test "$NODE/crs-page")" = "200 HIT -" ] || fail "crs-block clean cache hit"
[ "$(crs crs-block.test -H "$XSS_REFERER" "$NODE/crs-page")" = "403 - waf-blocked" ] || fail "XSS on a cached object: $(crs crs-block.test -H "$XSS_REFERER" "$NODE/crs-page")"
[ "$(crs crs-block.test "$NODE/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")" = "403 - waf-blocked" ] || fail "XSS in the query not blocked"
[ "$(crs crs-block.test -X POST --data-urlencode 'comment=<script>alert(1)</script>' "$NODE/comments")" = "403 - waf-blocked" ] || fail "XSS in the body not blocked"
curl -s -D "$TMPDIR_E2E/crs.h" -o "$TMPDIR_E2E/crs.b" -H 'Host: crs-block.test' -H 'Accept-Language: zh-CN' "$NODE/search?q=%3Cscript%3Ealert(5)%3C%2Fscript%3E"
grep -q '<html lang="zh-CN">' "$TMPDIR_E2E/crs.b" && grep -q '<h1>访问被拒绝</h1>' "$TMPDIR_E2E/crs.b" &&
  grep -qi '^content-type: text/html; charset=utf-8' "$TMPDIR_E2E/crs.h" || fail "CRS block without the built-in 403 page: $(cat "$TMPDIR_E2E/crs.b")"
[ "$(tr -d '\r' <"$TMPDIR_E2E/crs.h" | header_of content-length)" = "$(wc -c <"$TMPDIR_E2E/crs.b" | tr -d ' ')" ] ||
  fail "CRS page Content-Length $(tr -d '\r' <"$TMPDIR_E2E/crs.h" | header_of content-length) for $(wc -c <"$TMPDIR_E2E/crs.b") bytes"
[ "$(crs crs-block.test "$NODE/item?id=1%27%20OR%20%271%27%3D%271")" = "200 MISS -" ] || fail "excluded rule 942100 still blocks: $(crs crs-block.test "$NODE/item?id=1%27%20OR%20%271%27%3D%271")"
[ "$(crs crs-detect.test "$NODE/item?id=1%27%20OR%20%271%27%3D%271")" = "200 MISS -" ] || fail "detect mode blocked SQLi"
[ "$(crs demo.test "$NODE/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")" = "200 MISS -" ] || fail "a site without CRS answered the payload with $(crs demo.test "$NODE/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
echoed=$(curl -fsS -H 'Host: crs-detect.test' "$NODE/crs-echo")
if grep -qi "x-edgeweir" <<<"$echoed"; then fail "X-Edgeweir-Waf reached the origin"; fi
logs_have() { curl -fsS "$HELPER/logs" | grep -Eq "$1"; }
WAIT_SECS=30 wait_for "blocked request in the access logs" logs_have '^site-crs-block 403 /search true [0-9,]*949110'
WAIT_SECS=30 wait_for "detected SQLi in the access logs" logs_have '^site-crs-detect 200 /item false [0-9,]*942100'
logs_have '^site-crs-block 200 /item false -$' || fail "excluded rule 942100 logged for crs-block: $(curl -fsS "$HELPER/logs" | grep /item)"
logs_have '^site-crs-detect 200 /crs-page false -$' || fail "a clean request matched CRS rules: $(curl -fsS "$HELPER/logs" | grep crs-page)"
pass "CRS: detect logs without blocking, block answers 403 (cache hits too), exclusions, no effect on other sites"

# Without CRS sites nginx.conf does not load ModSecurity at all.
conf_loads_modsecurity() { compose exec -T node grep -q '^load_module ' /var/lib/edgeweir-node/nginx/conf/nginx.conf; }
rev=$(curl -fsS -X POST "$HELPER/crs?enabled=false")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
if conf_loads_modsecurity; then fail "nginx.conf loads ModSecurity without CRS sites"; fi
[ "$(crs crs-block.test "$NODE/search?q=%3Cscript%3Ealert(2)%3C%2Fscript%3E")" = "200 MISS -" ] || fail "CRS still active after it was turned off"
rev=$(curl -fsS -X POST "$HELPER/crs?enabled=true")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
conf_loads_modsecurity || fail "nginx.conf does not load ModSecurity for CRS sites"
[ "$(crs crs-block.test "$NODE/search?q=%3Cscript%3Ealert(3)%3C%2Fscript%3E")" = "403 - waf-blocked" ] || fail "CRS not active again"
pass "CRS off: ModSecurity not loaded; on again: blocking"

# Cache-Tag never reaches clients unless the site keeps it, cache hits
# included (the edge reads $upstream_http_cache_tag of cached objects).
hv() { # host path [curl args...] -> response headers
  local host=$1 path=$2
  shift 2
  curl -s -o /dev/null -D - -H "Host: $host" "$@" "$NODE$path" | tr -d '\r'
}
cache_is() { [ "$(hv "$@" | header_of x-cache)" = "$CACHE" ]; }
r=$(hv tags.test '/tagged?tags=Product-42,All')
[ "$(header_of x-cache <<<"$r")" = MISS ] && [ -z "$(header_of cache-tag <<<"$r")" ] || fail "tags.test MISS: $r"
r=$(hv tags.test '/tagged?tags=Product-42,All')
[ "$(header_of x-cache <<<"$r")" = HIT ] && [ -z "$(header_of cache-tag <<<"$r")" ] || fail "tags.test HIT: $r"
r=$(hv keep.test '/tagged?tags=a,b')
[ "$(header_of x-cache <<<"$r")" = MISS ] && [ "$(header_of cache-tag <<<"$r")" = "a,b" ] || fail "keep.test MISS: $r"
r=$(hv keep.test '/tagged?tags=a,b')
[ "$(header_of x-cache <<<"$r")" = HIT ] && [ "$(header_of cache-tag <<<"$r")" = "a,b" ] || fail "keep.test HIT without Cache-Tag: $r"
pass "Cache-Tag hidden by default, forwarded for sites that keep it (cache hits too)"

# Request ids: nginx's, or the client's when valid; the origin sees the
# same one and its own never reaches the client.
r=$(hv tags.test "/echo?u=$RANDOM")
id=$(header_of x-request-id <<<"$r")
[[ "$id" =~ ^[0-9a-f]{32}$ ]] && [ "$(grep -ci '^x-request-id:' <<<"$r")" = 1 ] || fail "request id: $r"
body=$(curl -s -D "$TMPDIR_E2E/rid.h" -H 'Host: tags.test' -H 'X-Request-Id: e2e-request-0001' "$NODE/echo?u=$RANDOM")
grep -q "rid e2e-request-0001" <<<"$body" && [ "$(tr -d '\r' <"$TMPDIR_E2E/rid.h" | header_of x-request-id)" = e2e-request-0001 ] ||
  fail "client request id not reused: $body"
[[ "$(hv tags.test "/echo?u=$RANDOM" -H 'X-Request-Id: bad id!' | header_of x-request-id)" =~ ^[0-9a-f]{32}$ ]] || fail "invalid client request id kept"
pass "X-Request-Id: the client's when valid, else nginx's; the origin sees it, never its own"

# Purge by tag through the control socket (POST /v1/purge, with the id of
# the agent's marker set so that the agent keeps it).
r=$(hv tags.test '/tagged?plain=1')
[ "$(header_of x-cache <<<"$r")" = MISS ] || fail "untagged object: $r"
CACHE=HIT cache_is tags.test '/tagged?plain=1' || fail "untagged object not cached"
tag_purge() { # site tag
  local set now
  set=$(control GET /v1/purge | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  # Milliseconds after every epoch the agent assigned before (perl-base has
  # no Time::HiRes).
  now=$(compose exec -T node perl -e 'printf("%d", time() * 1000 + 999)')
  control POST /v1/purge "{\"id\":\"$set\",\"markers\":[{\"site_id\":\"$1\",\"type\":\"tag\",\"tag\":\"$2\",\"epoch\":$now}]}" |
    grep -q "\"id\":\"$set\"" || fail "tag purge of $2 on $1 rejected"
}
tag_purge site-tags product-42
CACHE=MISS cache_is tags.test '/tagged?tags=Product-42,All' || fail "tagged object still cached after its tag was purged"
CACHE=HIT cache_is tags.test '/tagged?tags=Product-42,All' || fail "refetched tagged object not cached"
CACHE=HIT cache_is tags.test '/tagged?plain=1' || fail "a tag purge moved an untagged object"
pass "tag purge: the tagged object misses once, an untagged one stays cached"

# Slices: the tag of the last slice (a slice subrequest) moves every slice.
r=$(hv slice.test '/big.bin')
[ "$(header_of x-cache <<<"$r")" = MISS ] && [ "$(header_of content-length <<<"$r")" = 3145728 ] || fail "slice.test: $r"
CACHE=HIT cache_is slice.test '/big.bin' -H 'Range: bytes=3000000-3000010' || fail "last slice not cached"
tag_purge site-slice 'range-bytes=2097152-3145727'
CACHE=MISS cache_is slice.test '/big.bin' -H 'Range: bytes=0-10' || fail "a tag only a slice subrequest saw did not move the object"
CACHE=HIT cache_is slice.test '/big.bin' -H 'Range: bytes=0-10' || fail "first slice not cached again"
pass "slice subrequests index their Cache-Tag"

# Background updates (stale-while-revalidate): the refreshed object's tag
# moves it although only the background subrequest saw it.
# The origin numbers its responses: gen-1 for the first fetch, gen-2 for
# the background update. Objects stay fresh for a second only, so cached
# answers are HIT or STALE; a moved key is a MISS.
CACHE=MISS cache_is swr.test /gen || fail "swr.test first request"
sleep 2
CACHE=STALE cache_is swr.test /gen || fail "swr.test not served stale while updating"
sleep 1
tag_purge site-swr gen-99
[ "$(hv swr.test /gen | header_of x-cache)" != MISS ] || fail "an unrelated tag moved swr.test"
tag_purge site-swr gen-2
CACHE=MISS cache_is swr.test /gen || fail "a tag only the background update saw did not move the object"
pass "background updates index their Cache-Tag"

# stale-if-error: for an origin's 5xx the origin layer closes the
# connection without a response and the edge serves its expired copy after
# one attempt (each attempt is a trip to the origin). The edge keeps no idle
# connections to the origin layer: nginx tries a request that failed on a
# reused connection again on another one. /flaky answers its first request
# and fails every later one. One client connection carries the three
# requests, so they reach one worker, where the first two would leave an
# idle connection to the origin layer; /slow outlasts the object's second
# of freshness.
r=$(curl -s -D - -H 'Host: sie.test' -o /dev/null "$NODE/flaky" -o /dev/null "$NODE/slow" -o /dev/null "$NODE/flaky" |
  tr -d '\r' | awk -F': ' '/^HTTP\//{split($0,a," ");s=a[2]} tolower($1)=="x-cache"{printf "%s %s;", s, $2}')
hits=$(curl -fsS "$HELPER/flaky?port=8082")
[ "$r" = "200 MISS;200 MISS;200 STALE;" ] && [ "$hits" = 2 ] || fail "stale-if-error: $r with $hits origin requests (want 2)"
pass "stale-if-error: the expired copy after one origin attempt"

# Error pages: unknown and offline hosts (built-in, then the platform's
# page for disabled sites), origin failures (built-in), intercepted origin
# errors (site), origin errors without a page pass unchanged.
page_of() { # host path [curl args...] -> "<status> <x-edgeweir-error> <content-type> <cache-control>" then the body
  local host=$1 path=$2
  shift 2
  curl -s -D "$TMPDIR_E2E/page.h" -o "$TMPDIR_E2E/page.b" -H "Host: $host" "$@" "$NODE$path"
  tr -d '\r' <"$TMPDIR_E2E/page.h" | awk -F': ' 'NR==1{split($0,a," ");s=a[2]} tolower($1)=="x-edgeweir-error"{e=$2} tolower($1)=="content-type"{t=$2} tolower($1)=="cache-control"{c=$2} END{print s, e, t, c}'
  cat "$TMPDIR_E2E/page.b"
}
r=$(page_of nowhere.test / -H 'X-Request-Id: e2e-page-0001')
[ "$(head -1 <<<"$r")" = "404 unknown-host text/html; charset=utf-8 no-store" ] && grep -q '<h1>Site not found</h1>' <<<"$r" &&
  grep -q '<dt>Request ID</dt><dd class="rid">e2e-page-0001</dd>' <<<"$r" || fail "unknown host page: $r"
r=$(page_of nowhere.test / -H 'Accept-Language: zh-CN,zh;q=0.9')
grep -q '<h1>站点不存在</h1>' <<<"$r" || fail "unknown host page in Chinese: $r"
r=$(page_of old.test /)
[ "$(head -1 <<<"$r")" = "503 site-disabled text/html; charset=utf-8 no-store" ] && grep -q '<h1>Site disabled</h1>' <<<"$r" ||
  fail "disabled site page: $r"
r=$(page_of www.gone.test /)
[ "$(head -1 <<<"$r")" = "503 site-disabled text/html; charset=utf-8 no-store" ] && grep -q '<h1>Site disabled</h1>' <<<"$r" ||
  fail "disabled site page (wildcard offline host): $r"
rev=$(curl -fsS -X POST "$HELPER/disabled-page?enabled=true")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
r=$(page_of www.gone.test / -H 'X-Request-Id: e2e-page-0002')
[ "$(head -1 <<<"$r")" = "503 site-disabled text/html; charset=utf-8 no-store" ] &&
  grep -q '<h1>disabled www.gone.test e2e-page-0002</h1>' <<<"$r" || fail "disabled site page (platform template): $r"
rev=$(curl -fsS -X POST "$HELPER/disabled-page?enabled=false")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
r=$(page_of dead.test /x)
[ "$(head -1 <<<"$r")" = "502 origin-unreachable text/html; charset=utf-8 no-store" ] && grep -q '<h1>Origin unreachable</h1>' <<<"$r" ||
  fail "origin failure page: $r"
r=$(page_of pages.test /status/503)
[ "$(head -1 <<<"$r")" = "503 origin-error text/html; charset=utf-8 no-store" ] && grep -q '<h1>busy pages.test</h1>' <<<"$r" ||
  fail "intercepted origin error: $r"
! grep -qi '^etag:' "$TMPDIR_E2E/page.h" || fail "intercepted origin error kept its ETag"
r=$(page_of pages.test /status/404)
[ "$(head -1 <<<"$r" | cut -d' ' -f1)" = 404 ] && grep -q 'origin status 404' <<<"$r" || fail "origin 404 changed: $r"
r=$(page_of tags.test /status/503)
[ "$(head -1 <<<"$r" | cut -d' ' -f1)" = 503 ] && grep -q 'origin status 503' <<<"$r" || fail "origin 503 of a site without pages changed: $r"
curl -s -o /dev/null -H 'Host: pages.test' -H 'X-Request-Id: e2e-log-0001' "$NODE/logged"
logged() { curl -fsS "$HELPER/request-ids" | grep -q '^site-pages 200 /logged e2e-log-0001$'; }
WAIT_SECS=30 wait_for "request id in the access logs" logged
pass "error pages: platform, built-in and site pages, intercepted origin errors; request id in the access logs"

# nginx's own errors answer with built-in pages too: requests nginx refuses
# (a TLS handshake or garbage on the plain port, an invalid Host, a URI,
# headers or a body over the limits, plain HTTP on the HTTPS port) fail at
# the visitor; a CRS 400 keeps waf-blocked and is logged like the CRS's
# other blocks; HEAD gets the page's exact length and no body.
raw() { # request (printf format) -> the response, CR removed
  exec 3<>"/dev/tcp/127.0.0.1/${E2E_NODE_PORT:-28080}"
  printf "$1" >&3
  tr -d '\r' <&3
  exec 3<&-
}
own_page() { # status code title hop (response on stdin) -> true for that built-in page
  local r
  r=$(cat)
  [ "$(status_of <<<"$r")" = "$1" ] && [ "$(header_of x-edgeweir-error <<<"$r")" = "$2" ] &&
    [ "$(header_of content-type <<<"$r")" = "text/html; charset=utf-8" ] && [ "$(header_of cache-control <<<"$r")" = no-store ] &&
    grep -q "<h1>$3</h1>" <<<"$r" && grep -q "<li class=\"x\"><b>$4</b>" <<<"$r"
}
r=$(raw 'GARBAGE\r\n\r\n')
own_page 400 bad-request "Bad request" You <<<"$r" || fail "malformed request line: $r"
r=$(raw '\026\003\001\002\000\001\000\001\374\003\003')
own_page 400 bad-request "Bad request" You <<<"$r" || fail "TLS handshake on the plain port: $r"
r=$(raw 'GET / HTTP/1.1\r\nHost: a/b\r\n\r\n')
own_page 400 bad-request "Bad request" You <<<"$r" && grep -q '<dt>Host</dt><dd></dd>' <<<"$r" || fail "invalid Host: $r"
big=$(head -c 9000 /dev/zero | tr '\0' a)
r=$(raw "GET /$big HTTP/1.1\r\nHost: demo.test\r\n\r\n")
own_page 414 uri-too-long "URL too long" You <<<"$r" || fail "URI too long: $(head -12 <<<"$r")"
r=$(curl -s -D - -X POST -H 'Host: demo.test' -H 'Content-Length: 209715200' "$NODE/upload" | tr -d '\r')
own_page 413 body-too-large "Request too large" You <<<"$r" || fail "body too large: $r"
r=$(page_of demo.test / -H 'X-Request-Id: e2e-big-0001' -H "Cookie: $big")
[ "$(head -1 <<<"$r")" = "400 header-too-large text/html; charset=utf-8 no-store" ] &&
  grep -q '<h1>Request header too large</h1>' <<<"$r" && grep -q '<li class="x"><b>You</b>' <<<"$r" || fail "header too large: $r"
len=$(tr -d '\r' <"$TMPDIR_E2E/page.h" | header_of content-length)
[ "$len" = "$(wc -c <"$TMPDIR_E2E/page.b" | tr -d ' ')" ] || fail "header too large: Content-Length $len for $(wc -c <"$TMPDIR_E2E/page.b") bytes"
r=$(raw "HEAD / HTTP/1.1\r\nHost: demo.test\r\nX-Request-Id: e2e-big-0001\r\nCookie: $big\r\n\r\n")
[ "$(status_of <<<"$r")" = 400 ] && [ "$(header_of content-length <<<"$r")" = "$len" ] && [ -z "$(sed '1,/^$/d' <<<"$r")" ] ||
  fail "HEAD with too large a header: $r"
r=$(client -s -D - -H 'Host: demo.test' -H 'Accept-Language: zh-CN' http://node:8443/ | tr -d '\r')
own_page 400 https-required "需要使用 HTTPS" 你 <<<"$r" || fail "plain HTTP on the HTTPS port: $r"
r=$(page_of crs-block.test /api -X POST -H 'Content-Type: application/json' --data '{bad')
[ "$(head -1 <<<"$r")" = "400 waf-blocked text/html; charset=utf-8 no-store" ] && grep -q '<h1>Bad request</h1>' <<<"$r" ||
  fail "CRS 400 (request body that does not parse): $r"
WAIT_SECS=30 wait_for "CRS 400 in the access logs" logs_have '^site-crs-block 400 /api true [0-9,]*200002'
pass "nginx's own errors: built-in pages for refused requests and CRS 400s, HEAD without a body"

# Session affinity: the first response pins the client, the pin holds.
r=$(hv aff.test /echo)
cookie=$(cookie_of <<<"$r")
header_of set-cookie <<<"$r" | grep -Eq '^__ew_affinity=o[12]\.[0-9]+\.e2e-key-2\.[A-Za-z0-9_-]+; Path=/; Max-Age=120; HttpOnly; SameSite=Lax$' ||
  fail "affinity cookie: $(header_of set-cookie <<<"$r")"
! grep -qi '^x-edgeweir-affinity' <<<"$r" || fail "the internal affinity header reached the client"
pinned=$(header_of x-origin <<<"$r")
for _ in $(seq 1 8); do
  r=$(hv aff.test /echo -H "Cookie: $cookie")
  [ "$(header_of x-origin <<<"$r")" = "$pinned" ] || fail "the pin to port $pinned did not hold"
  [ -z "$(header_of set-cookie <<<"$r")" ] || fail "a valid pin was issued again"
done
origins=$(for _ in $(seq 1 12); do hv aff.test /echo | header_of x-origin; done | sort -u | wc -l | tr -d ' ')
[ "$origins" = 2 ] || fail "clients without a cookie all went to one origin"
pass "session affinity: one cookie, the pinned origin answers"

# Purge tasks from the console: by Cache-Tag (compared in lowercase) and
# by host.
task_done() { curl -fsS "$HELPER/task-result?id=$1" | grep -qx "TASK_STATE_SUCCEEDED - $2 0"; }
CACHE=MISS cache_is tags.test '/tagged?tags=e2e-task' || fail "tags.test first request for the tag purge task"
CACHE=MISS cache_is tags.test '/tagged?plain=2' || fail "tags.test first request for an untagged object"
CACHE=HIT cache_is tags.test '/tagged?tags=e2e-task' || fail "tagged object not cached"
task=$(curl -fsS -X POST "$HELPER/purge-tag?site=site-tags&tag=E2E-Task")
WAIT_SECS=30 wait_for "tag purge task $task" task_done "$task" 1
CACHE=MISS cache_is tags.test '/tagged?tags=e2e-task' || fail "the tag purge task did not move the tagged object"
CACHE=HIT cache_is tags.test '/tagged?plain=2' || fail "the tag purge task moved an untagged object"
CACHE=MISS cache_is keep.test '/host-purge' || fail "keep.test first request for the host purge"
CACHE=HIT cache_is tags.test '/tagged?plain=2' || fail "untagged object not cached"
task=$(curl -fsS -X POST "$HELPER/purge-host?site=site-tags&host=tags.test")
WAIT_SECS=30 wait_for "host purge task $task" task_done "$task" 1
CACHE=MISS cache_is tags.test '/tagged?plain=2' || fail "the host purge task did not move an object of the host"
CACHE=HIT cache_is keep.test '/host-purge' || fail "the host purge task moved an object of another host"
pass "purge tasks by Cache-Tag and by host"

# Sitemap prefetch: a gzipped index with a plain and a gzipped sitemap;
# only smap.test URLs, each in both device variants.
MOBILE_UA='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148'
CACHE=MISS cache_is smap.test /page-0 || fail "smap.test not served"
task=$(curl -fsS -X POST "$HELPER/sitemap?site=site-smap&url=http://smap.test/sitemap-index.xml.gz&variants=desktop,mobile")
WAIT_SECS=60 wait_for "sitemap task $task" task_done "$task" 6
for path in /page-1 /page-2 '/page-3?v=1'; do
  CACHE=HIT cache_is smap.test "$path" || fail "sitemap prefetch did not cache $path (desktop)"
  CACHE=HIT cache_is smap.test "$path" -A "$MOBILE_UA" || fail "sitemap prefetch did not cache $path (mobile)"
done
CACHE=MISS cache_is smap.test /page-4 -A "$MOBILE_UA" || fail "a page the sitemap does not list was cached"
pass "sitemap prefetch: gzipped index followed, both device variants cached"

# Prefetches use the node's local listeners: Under Attack does not
# challenge them (ua.test) and the object is cached for visitors with a
# pass.
task=$(curl -fsS -X POST "$HELPER/prefetch?site=site-ua&url=http://ua.test/prefetched")
WAIT_SECS=30 wait_for "prefetch task $task" task_done "$task" 1
CACHE=HIT cache_is ua.test /prefetched -A 'e2e-browser' -H "Cookie: $pass_cookie" || fail "the Under Attack prefetch was not cached"
pass "prefetch under Under Attack: not challenged, cached"

# Active health check: a failing /health takes o2 (port 8083) out of
# rotation although it serves requests; a passing one brings it back.
origins_seen() { for _ in $(seq 1 20); do hv active.test "/echo?n=$RANDOM" | header_of x-origin; done | sort -u | tr '\n' ' '; }
only_8082() { [ "$(origins_seen)" = "8082 " ]; }
both_origins() { [ "$(origins_seen)" = "8082 8083 " ]; }
WAIT_SECS=10 wait_for "both active.test origins in rotation" both_origins
curl -fsS -X POST "$HELPER/health?port=8083&status=503" >/dev/null
active_is() { [ "$(curl -fsS "$HELPER/active-health")" = "$1" ]; }
WAIT_SECS=30 wait_for "o2 reported down by the active check" active_is "site-active o2 false upstream_status"
WAIT_SECS=10 wait_for "o2 out of rotation" only_8082
only_8082 || fail "o2 takes traffic while its active check fails"
curl -fsS -X POST "$HELPER/health?port=8083&status=200" >/dev/null
WAIT_SECS=30 wait_for "o2 healthy again" active_is ""
WAIT_SECS=10 wait_for "o2 back in rotation" both_origins
pass "active health check: a failing origin takes no traffic until its check passes again"

# rules-v2 (rules.test): functions in conditions and values, dynamic
# redirects and rewrites, bulk redirects, origin rules, config overrides,
# cache rule conditions and browser TTLs.
grep -qx rules-v2 <<<"$(curl -fsS "$HELPER/features")" || fail "rules-v2 not reported"
r=$(hv rules.test '/old/a/b?x=1&utm_source=z')
loc=$(header_of location <<<"$r")
[ "$(status_of <<<"$r")" = 301 ] && case "$loc" in */new/a/b\?x=1\&lang=zh%20CN) true ;; *) false ;; esac ||
  fail "dynamic redirect: $(status_of <<<"$r") $loc"
r=$(hv rules.test '/bulk-old?q=1')
loc=$(header_of location <<<"$r")
[ "$(status_of <<<"$r")" = 308 ] && case "$loc" in */bulk-new\?from=bulk\&q=1) true ;; *) false ;; esac ||
  fail "bulk redirect: $(status_of <<<"$r") $loc"
r=$(hv rules.test /bulk-host)
[ "$(status_of <<<"$r")" = 302 ] && [ "$(header_of location <<<"$r")" = https://example.test/host ] ||
  fail "host bulk redirect: $(status_of <<<"$r") $(header_of location <<<"$r")"
echoed=$(curl -fsS -H 'Host: rules.test' "$NODE/api/Item?drop=1")
grep -q '^GET /internal/Item?v=2 HTTP/1.1' <<<"$echoed" && grep -q '^Host: api.internal' <<<"$echoed" ||
  fail "rewrite to the api group with its Host: $echoed"
if grep -qi '^x-edgeweir' <<<"$echoed"; then fail "internal headers reached the api origin: $echoed"; fi
[ "$(curl -fsS -H 'Host: rules.test' "$NODE/port/x")" = "/port/x from 8083" ] || fail "port override"
[ "$(curl -fsS -H 'Host: rules.test' "$NODE/plain")" = "/plain from 8082" ] || fail "default group"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: rules.test' "$NODE/slow")
[ "$code" = 504 ] || fail "read timeout of 1 s against a 2.5 s origin: $code"
r=$(hv rules.test /ws -H 'Connection: Upgrade' -H 'Upgrade: websocket')
[ "$(status_of <<<"$r")" = 403 ] && [ "$(header_of x-edgeweir-error <<<"$r")" = websocket-disabled ] ||
  fail "config websocket=false: $(status_of <<<"$r") $(header_of x-edgeweir-error <<<"$r")"
r=$(hv rules.test /guarded -A e2e-browser)
[ "$(status_of <<<"$r")" = 403 ] && [ "$(header_of x-edgeweir-challenge <<<"$r")" = js ] ||
  fail "config under_attack=true: $(status_of <<<"$r") $(header_of x-edgeweir-challenge <<<"$r")"
[ "$(status_code rules.test)" = 200 ] || fail "rules.test without Under Attack"
r=$(hv rules.test /img/a.png)
[ "$(header_of x-cache <<<"$r")" = MISS ] && [ "$(header_of cache-control <<<"$r")" = max-age=600 ] || fail "browser TTL (MISS): $r"
r=$(hv rules.test /img/a.png)
[ "$(header_of x-cache <<<"$r")" = HIT ] && [ "$(header_of cache-control <<<"$r")" = max-age=600 ] || fail "browser TTL (HIT): $r"
r=$(hv rules.test /img/a.gif)
[ -z "$(header_of cache-control <<<"$r")" ] || fail "a rule without browser TTL set Cache-Control: $r"
curl -s -o /dev/null -H 'Host: rules.test' "$NODE/unsampled"
curl -s -o /dev/null -H 'Host: rules.test' "$NODE/sampled"
WAIT_SECS=30 wait_for "the sampled request in the access logs" sh -c "curl -fsS $HELPER/logs | grep -q '^site-rules 200 /sampled '"
if curl -fsS "$HELPER/logs" | grep -q '^site-rules .* /unsampled '; then fail "a request of a site sampling nothing was logged"; fi
pass "rules-v2: dynamic and bulk redirects, rewrite, origin group, Host, port and timeout, WebSocket, Under Attack, sampling, browser TTL"

# HTTP/2 to origins (origin-http2-v1): with prior knowledge and over TLS
# (ALPN h2), cached like any request, WebSocket still over HTTP/1.1, no
# fallback for an origin without HTTP/2, health probes over HTTP/2.
curl -fsS "$HELPER/features" | grep -qx origin-http2-v1 || fail "origin-http2-v1 not announced"
r=$(curl -fsS -H 'Host: h2.test' "$NODE/proto")
[ "$r" = "HTTP/2.0 h2.test -" ] || fail "h2.test: the origin saw '$r', want HTTP/2 with prior knowledge"
[ "$(x_cache_path h2.test /proto)" = HIT ] || fail "h2.test: an HTTP/2 origin's response is not cached"
r=$(curl -fsS -H 'Host: h2tls.test' "$NODE/proto")
[ "$r" = "HTTP/2.0 h2tls.test h2" ] || fail "h2tls.test: the origin saw '$r', want HTTP/2 over TLS (ALPN h2)"
# Request bodies: one with a length (over the edge's in-memory buffer) and
# a chunked one.
r=$(head -c 300000 /dev/zero | curl -fsS -H 'Host: h2.test' --data-binary @- "$NODE/body")
[ "$r" = "HTTP/2.0 300000" ] || fail "POST with a body to an HTTP/2 origin: '$r'"
r=$(head -c 70000 /dev/zero | curl -fsS -H 'Host: h2.test' -H 'Transfer-Encoding: chunked' --data-binary @- "$NODE/body")
[ "$r" = "HTTP/2.0 70000" ] || fail "chunked POST to an HTTP/2 origin: '$r'"
r=$(curl -fsS "$HELPER/ws?host=h2.test")
[ "$r" = "ws HTTP/1.1 hello" ] || fail "WebSocket on an HTTP/2 site: '$r', want the origin to see HTTP/1.1"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: h2bad.test' "$NODE/proto")
[ "$code" = 502 ] || fail "h2bad.test (origin without HTTP/2): $code, want 502"
WAIT_SECS=30 wait_for "HTTP/2 health probes" sh -c "curl -fsS $HELPER/h2-probes | grep -q '^HTTP/2.0 [1-9]'"
if curl -fsS "$HELPER/h2-probes" | grep -q '^HTTP/1.1 '; then fail "an HTTP/2 pool was probed over HTTP/1.1: $(curl -fsS "$HELPER/h2-probes")"; fi
WAIT_SECS=30 wait_for "h2bad.test's origin reported failing" origin_health_has "^site-h2bad o1 connect_failed "
pass "HTTP/2 to origins: h2c and h2 over TLS, cached, request bodies, WebSocket over HTTP/1.1, no fallback, health probes over HTTP/2"

# gRPC end to end over h2c on the plain listener: unary, bidirectional
# streaming (each message waits for the echo of the one before), error
# trailers and a trailers-only response, to HTTP and TLS origins; the CRS
# of grpc.test still inspects its other requests; h2c to a site without
# gRPC is misdirected (421).
r=$(curl -fsS "$HELPER/grpc?host=grpc.test")
grep -qx 'unary 200 0 echo:hello proto=HTTP/2.0 host=grpc.test te=trailers alpn=-' <<<"$r" || fail "gRPC unary: $r"
grep -qx 'bidi 3 0' <<<"$r" || fail "gRPC bidirectional streaming: $r"
grep -qx 'fail 200 5 no such thing' <<<"$r" || fail "gRPC error trailers: $r"
grep -qx 'unknown 200 12' <<<"$r" || fail "gRPC trailers-only response: $r"
r=$(curl -fsS "$HELPER/grpc?host=grpctls.test")
grep -qx 'unary 200 0 echo:hello proto=HTTP/2.0 host=grpctls.test te=trailers alpn=h2' <<<"$r" || fail "gRPC to a TLS origin: $r"
grep -qx 'bidi 3 0' <<<"$r" || fail "gRPC bidirectional streaming to a TLS origin: $r"
[ "$(crs grpc.test "$NODE/search?q=%3Cscript%3Ealert(5)%3C%2Fscript%3E")" = "403 - waf-blocked" ] || fail "grpc.test: the CRS does not inspect requests that are not gRPC"
code=$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge -H 'Host: compress.test' "$NODE/")
[ "$code" = 421 ] || fail "h2c to a site without gRPC: $code, want 421"
pass "gRPC end to end: unary, bidirectional streaming, error trailers and a trailers-only status over h2c, to HTTP and TLS origins; the CRS skips gRPC only"

# Heartbeats carry host metrics (metrics-v1); the data plane reports its
# connections.
read -r cpu _ mem_total mem_used _ _ <<<"$(curl -fsS "$HELPER/metrics")"
[ "$mem_total" -gt 0 ] && [ "$mem_used" -gt 0 ] && [ "$mem_used" -le "$mem_total" ] &&
  awk -v c="$cpu" 'BEGIN { exit !(c >= 0 && c <= 100) }' || fail "host metrics: $(curl -fsS "$HELPER/metrics")"
curl -fsS "$HELPER/features" | grep -qx metrics-v1 || fail "metrics-v1 not announced"
curl -fsS "$HELPER/features" | grep -qx probe-health-v1 || fail "probe-health-v1 not announced"
control GET /v1/status | grep -q '"connections_active":[0-9]' || fail "no connections_active in the data plane status: $(control GET /v1/status)"
pass "heartbeats carry host metrics ($(curl -fsS "$HELPER/metrics")), probe-health-v1 and metrics-v1 announced"

# The node probes its peer (its own address under another node id) while
# the console lets it, and never itself.
curl -fsS -X POST "$HELPER/probe-node?enabled=true" >/dev/null
WAIT_SECS=60 wait_for "a probe round of the node" sh -c "curl -fsS $HELPER/probe-results | grep -q '^node-e2e '"
results=$(curl -fsS "$HELPER/probe-results")
probed() { grep -Eq "^$1 $2 $3 $4 3 $5 $6 $7\$" <<<"$results" || fail "no result '$*' in: $results"; }
for prober in node-e2e; do
  probed "$prober" node-peer tcp 9 3 0 refused
  probed "$prober" node-peer http 80 0 '[1-9][0-9]*' -
  probed "$prober" node-peer tcp 80 0 '[1-9][0-9]*' -
  probed "$prober" node-peer http 8081 0 '[1-9][0-9]*' -
  probed "$prober" node-peer https 8443 0 '[1-9][0-9]*' -
done
if grep -q '^node-e2e node-e2e ' <<<"$results"; then fail "the node probed itself: $results"; fi
curl -fsS -X POST "$HELPER/probe-node?enabled=false" >/dev/null
node_logged() { local l; l=$(compose logs node); grep -q "$1" <<<"$l"; }
WAIT_SECS=30 wait_for "the node stops probing" node_logged 'stopped probing the other nodes'
pass "node as a probe: HTTP, PROXY protocol, HTTPS and TCP of its peer, refused port lost, never itself"

# `edgeweir-node probe`: enrolls with a probe token (key 0600) and reports.
PROBE_TOKEN=$(curl -fsS "$HELPER/probe-token")
compose exec -T -e EDGEWEIR_TOKEN="$PROBE_TOKEN" node timeout --preserve-status 8 edgeweir-node probe \
  --server https://console:8443 --ca-sha256 "$PIN" --state-dir /tmp/edgeweir-probe-e2e
results=$(curl -fsS "$HELPER/probe-results")
probed probe-1 node-e2e http 80 0 '[1-9][0-9]*' -
probed probe-1 node-peer tcp 9 3 0 refused
probed probe-1 node-peer https 8443 0 '[1-9][0-9]*' -
probed probe-1 node-peer http 8081 0 '[1-9][0-9]*' -
key_mode=$(compose exec -T node stat -c '%a' /tmp/edgeweir-probe-e2e/probe.key)
[ "$key_mode" = 600 ] || fail "probe.key mode $key_mode"
pass "edgeweir-node probe: enrolled (probe.key 0600) and reported a round"

# Layer-4 applications (l4-v1). The helper in the console container
# connects to the node's stream ports inside the compose network.
grep -qx l4-v1 <<<"$(curl -fsS "$HELPER/features")" || fail "l4-v1 not reported"
l4() { local what=$1; shift; local args=(-G); for a in "$@"; do args+=(--data-urlencode "$a"); done; curl -fsS "${args[@]}" "$HELPER/l4/$what"; }
reloads() { compose logs node | grep -c "nginx configuration installed and reloaded" || true; }
conf_id() { control GET /v1/status | sed -n 's/.*"conf_id":"\([0-9a-f]*\)".*/\1/p'; }
compose exec -T node grep -q '^stream {' /var/lib/edgeweir-node/nginx/conf/nginx.conf || fail "nginx.conf has no stream block"
r=$(l4 tcp port=9100 send=hello-l4)
[ "$r" = hello-l4 ] || fail "TCP echo through the node: '$r'"
[ "$(l4 tcp port=9100 send=NAME)" = a ] || fail "TCP 9100 not served by the echo origin a"
r=$(control GET /v1/l4)
grep -q '"app_id":"l4-echo"[^}]*"origin_id":"dead"\|"origin_id":"dead"[^}]*"app_id":"l4-echo"' <<<"$r" ||
  fail "the dead origin (weight 100) was not tried and held down: $r"
r=$(l4 udp port=9100 send=dgram-1)
[ "$r" = dgram-1 ] || fail "UDP echo through the node: '$r'"
r=$(l4 pp port=9101 version=1)
case "$r" in "ok "*) ;; *) fail "PROXY protocol v1 (nginx): $r" ;; esac
r=$(l4 pp port=9102 version=2)
case "$r" in "ok "*) ;; *) fail "PROXY protocol v2 (nginx): $r" ;; esac
r=$(l4 pp port=9103 version=2 pp=203.0.113.5)
[ "$r" = "ok 203.0.113.5:40000 192.0.2.9:443" ] || fail "PROXY protocol v2 relay with the client's address from the PROXY header: $r"
pass "layer 4: TCP and UDP echo, dead origin retried past and held down, PROXY v1 and v2 (nginx and relay) at the origin"
r=$(l4 tcp port=9103 pp=198.51.100.66 send=x)
[ "$r" = closed ] || fail "a blocked client address (from the PROXY header) got '$r'"
r=$(l4 tcp port=9103 pp=198.51.100.67 send=x lines=2)
grep -q '"source":"198.51.100.67"' <<<"$r" || fail "a neighbouring address was refused: $r"
r=$(l4 limit)
[ "$r" = ok ] || fail "connection limit: $r"
pass "layer 4: block list and connection limit close the connection"

r=$(curl -fsS -X POST "$HELPER/l4/long?op=open")
[ "$r" = ok ] || fail "long connection: $r"
reloads_before=$(reloads)
conf_before=$(conf_id)
rev=$(curl -fsS -X POST "$HELPER/l4/add-port")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
[ "$(reloads)" -eq "$((reloads_before + 1))" ] && [ "$(conf_id)" != "$conf_before" ] || fail "a new layer-4 port did not reload nginx once"
r=$(l4 tcp port=9105 send=extra)
[ "$r" = extra ] || fail "the new port 9105: '$r'"
r=$(curl -fsS -X POST "$HELPER/l4/long?op=check")
[ "$r" = ok ] || fail "the long connection did not survive the reload: $r"
pass "layer 4: a new port reloads nginx, the long connection opened before keeps working"
reloads_before=$(reloads)
conf_before=$(conf_id)
rev=$(curl -fsS -X POST "$HELPER/l4/hot")
wait_for "revision $rev applied" applied_is "$rev APPLY_STATE_APPLIED"
r=$(l4 tcp port=9100 send=NAME)
[ "$r" = b ] || fail "the changed origin of TCP 9100 does not answer: '$r'"
[ "$(reloads)" = "$reloads_before" ] && [ "$(conf_id)" = "$conf_before" ] || fail "an origin change reloaded nginx"
r=$(curl -fsS -X POST "$HELPER/l4/long?op=check")
[ "$r" = ok ] || fail "the long connection did not survive the hot update: $r"
pass "layer 4: an origin change applies to new connections without a reload"

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
  # The restart emptied the data plane's counters: match CRS rules again.
  [ "$(crs crs-block.test "$NODE/search?q=%3Cscript%3Ealert(4)%3C%2Fscript%3E")" = "403 - waf-blocked" ] || fail "CRS not active after the restart"
  WAIT_SECS=180 wait_for "CRS rule counts uploaded" sh -c "curl -fsS $HELPER/waf-rules | grep -q '^site-crs-block 949110 '"
  pass "CRS rules counted per minute ($(curl -fsS "$HELPER/waf-rules" | tr '\n' ';'))"
  # Layer 4 after the restart: a refused and an accepted connection.
  [ "$(l4 tcp port=9103 pp=198.51.100.66 send=x)" = closed ] || fail "block list after the restart"
  [ "$(l4 tcp port=9100 send=counted)" = counted ] || fail "TCP 9100 after the restart"
  l4_counted() { curl -fsS "$HELPER/l4-stats" | awk '$1=="l4-echo" && $2>0 && $5>0 && $6>0 {e=1} $1=="l4-relay" && $3>0 {r=1} END {exit !(e && r)}'; }
  WAIT_SECS=180 wait_for "layer-4 statistics uploaded" l4_counted
  pass "layer-4 statistics per minute ($(curl -fsS "$HELPER/l4-stats" | tr '\n' ';'))"
fi

echo "e2e smoke test passed"
