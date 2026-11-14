#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose -f compose.yml "$@"; }
helper="http://127.0.0.1:${E2E_HELPER_PORT:-28090}"
port="${E2E_TLS_PORT:-28443}"
tmp=$(mktemp -d)
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then compose logs --tail=100 node console; fi
  rm -rf "$tmp"
  if [ "${EARLY_HINTS_REUSE:-0}" != 1 ]; then compose down -v --remove-orphans; fi
  exit "$result"
}
trap cleanup EXIT
trap 'echo "FAIL informational response at line $LINENO" >&2' ERR
wait_for() {
  for _ in $(seq 1 90); do if "$@" >/dev/null 2>&1; then return; fi; sleep 1; done
  echo "FAIL timed out: $*" >&2
  exit 1
}
applied() { [ "$(curl -fsS "$helper/applied")" = "$1 APPLY_STATE_APPLIED" ]; }
publish() {
  local revision
  revision=$(curl -fsS -X POST "$helper/informational?$1")
  wait_for applied "$revision"
}

if [ "${EARLY_HINTS_REUSE:-0}" != 1 ]; then
  if [ "${E2E_SKIP_BUILD:-0}" = 1 ]; then compose up -d --no-build; else compose up -d --build; fi
  wait_for curl -fsS "$helper/pin"
  wait_for curl -sS "http://127.0.0.1:${E2E_NODE_PORT:-28080}/"
  compose exec -T node edgeweir-node enroll --server https://console:8443 \
    --token "$(curl -fsS "$helper/token")" --ca-sha256 "$(curl -fsS "$helper/pin")"
fi

fetch() { # protocol, path, status, hint count, [HEAD]
  local protocol=$1 path=$2 status=$3 hints=$4
  local flags=(--http1.1)
  if [ "$protocol" = 2 ]; then flags=(--http2); fi
  if [ "$protocol" = 3 ]; then flags=(--http3-only); fi
  if [ "${5:-}" = HEAD ]; then flags+=(--head); fi
  : > "$tmp/body"
  curl -ksS --noproxy '*' --max-time 10 "${flags[@]}" \
    --resolve "hints.test:$port:127.0.0.1" -D "$tmp/headers" -o "$tmp/body" \
    -w '%{time_starttransfer} %{time_total}' "https://hints.test:$port$path" > "$tmp/timing"
  python3 - "$tmp/headers" "$protocol" "$status" "$hints" "$path" "$tmp/timing" "${5:-GET}" <<'PY'
import pathlib, sys
raw, protocol, status, count, path, timing, method = sys.argv[1:]
blocks = [b.splitlines() for b in pathlib.Path(raw).read_text().split("\n\n") if b.strip()]
infos = [b for b in blocks if b[0].split()[1] == "103"]
assert len(infos) == int(count), blocks
expected_protocol = "HTTP/1.1" if protocol == "1" else "HTTP/" + protocol
assert blocks[-1][0].split()[:2] == [expected_protocol, status], blocks
for info in infos:
    assert info[0].split()[0] == expected_protocol, info
    assert len(info) == 3 and all(h.lower().startswith("link: ") for h in info[1:]), info
    assert "</static/example.css>; rel=preload; as=style" in info[1], info
    assert "<https://static.example.org>; rel=preconnect" in info[2], info
assert not any("</static/example.css>" in h for h in blocks[-1]), blocks[-1]
if path.endswith("/timeout") and protocol != "1":
    first, total = map(float, pathlib.Path(timing).read_text().split())
    assert total - first > 0.5, ("103 was buffered until the origin timeout", first, total)
print("ok   " + method + " " + path + ": " + " -> ".join(b[0] for b in blocks))
PY
}

publish 'phase=access'
fetch 2 /informational-links/ok 200 1
grep -qi '^x-info-informational-links-second: sent' "$tmp/headers"
publish 'phase=access_late'
fetch 3 /informational-links/ok 200 1
grep -qi '^x-info-informational-links-second: sent' "$tmp/headers"
publish 'phase=both'
for protocol in 1 2 3; do
  count=1
  if [ "$protocol" = 1 ]; then count=0; fi
  fetch "$protocol" /informational-links/ok 200 "$count"
  grep -q 'origin informational response' "$tmp/body"
  grep -qi '^link: </final.css>' "$tmp/headers"
  if [ "$protocol" != 1 ]; then
    grep -qi '^x-info-informational-links: sent' "$tmp/headers"
    grep -qi '^x-info-informational-links-second: sent' "$tmp/headers"
  fi
  fetch "$protocol" /informational-links/not-modified 304 "$count"
  [ ! -s "$tmp/body" ]
  fetch "$protocol" /informational-links/redirect 301 "$count"
  grep -qiE '^location: (https://hints[.]test(:[0-9]+)?)?/destination' "$tmp/headers"
  fetch "$protocol" /informational-links/ok 200 "$count" HEAD
  fetch "$protocol" "/informational-links/cache/$protocol" 200 "$count"
  grep -qi '^x-cache: MISS' "$tmp/headers"
  fetch "$protocol" "/informational-links/cache/$protocol" 200 "$count"
  grep -qi '^x-cache: HIT' "$tmp/headers"
  grep -q 'origin informational response' "$tmp/body"
  fetch "$protocol" /informational-links/timeout 504 "$count"
done
publish 'deny=1'
for protocol in 1 2 3; do
  count=1
  if [ "$protocol" = 1 ]; then count=0; fi
  fetch "$protocol" /informational-links/ok 403 "$count"
  grep -qi '^x-edgeweir-error: extension-denied' "$tmp/headers"
done
publish 'disabled=1'
fetch 2 /informational-links/ok 200 0
fetch 3 /informational-links/ok 200 0
echo 'ok   informational response protocol matrix: HTTP/1.1, HTTP/2, HTTP/3, both hooks, two signed extensions, final headers and bodies'
