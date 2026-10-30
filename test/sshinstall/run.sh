#!/usr/bin/env bash
# SSH install test: runs the console's install.sh and `edgeweir-node enroll`
# the way the console's one-shot SSH install does (non-tty `ssh -T`, the
# token in a 0600 file, no prompts) against fresh Debian hosts with sshd:
#
#   - root, and a sudo user (`sudo -n`), install and enroll; stdout carries
#     the node's EDGEWEIR_RESULT line, exit status 0;
#   - a sudo user whose sudo wants a password fails at once (`sudo -n`);
#   - a re-run on an enrolled host neither enrolls again nor fails: it
#     reports the same node (install.sh asks `enroll --if-not-enrolled`);
#   - an answer lost after the console issued the certificate: the retry
#     with the same token gets the same node (same key), not a second one;
#   - an SSH session with a terminal dropped during the enrollment: the
#     enrollment still completes (SIGHUP, closed pipes);
#   - two enrollments of one host at once: one succeeds, one is busy (16).
#
# The release is a fake one (edgeweir-node built from this checkout as
# version 1.7.0, a stub edgeweir-openresty .deb) served by the test
# console's mirror, installed with --allow-unsigned --no-start (no systemd
# in the hosts; the signature, systemd and health steps are not covered).
#
#   INSTALL_SH=../edgeweir/apps/console/src/server/install/install.sh test/sshinstall/run.sh
#
# Needs Docker with Compose, Go and ssh-keygen. COMPOSE_PROJECT_NAME
# defaults to edgeweir-node-ssh; the stack is removed at the end
# (KEEP=1 keeps it).
set -euo pipefail

cd "$(dirname "$0")/../.."
INSTALL_SH="${INSTALL_SH:-../edgeweir/apps/console/src/server/install/install.sh}"
[ -r "$INSTALL_SH" ] || { echo "install.sh not found: set INSTALL_SH" >&2; exit 2; }
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-edgeweir-node-ssh}"
export SSH_TEST_IMAGE="edgeweir-node:ssh-host-${COMPOSE_PROJECT_NAME}"
VERSION=1.7.0
WORK="$(mktemp -d)"
export SSH_TEST_WORK="$WORK"
compose() { docker compose -f test/sshinstall/compose.yml "$@"; }
cleanup() {
  if [ "${KEEP:-}" != "1" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

failures=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failures=$((failures + 1)); }
check() { # check NAME CONDITION...
  local name="$1"
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

echo "== build (edgeweir-node ${VERSION}, test console, stub packages)"
mkdir -p "$WORK/bin" "$WORK/keys" "$WORK/mirror/v${VERSION}" "$WORK/deb/DEBIAN" \
  "$WORK/deb/usr/lib/edgeweir-openresty/nginx/sbin"
# Default build tags: the release's nodynamic,wasm2go image converter takes
# gigabytes to compile and plays no part here.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-X github.com/marvinli001/edgeweir-node/internal/version.Version=${VERSION}" \
  -o "$WORK/bin/edgeweir-node" ./cmd/edgeweir-node
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$WORK/bin/console" ./test/sshinstall/console
ssh-keygen -q -t ed25519 -N '' -f "$WORK/keys/id_ed25519"
chmod 0644 "$WORK/keys/id_ed25519" # read by the client container's root only
top="edgeweir-node_${VERSION}_linux_amd64"
mkdir -p "$WORK/tar/$top/systemd" "$WORK/tar/$top/lua"
cp "$WORK/bin/edgeweir-node" "$WORK/tar/$top/"
cp packaging/systemd/edgeweir-node.service "$WORK/tar/$top/systemd/"
cp -r lua/edgeweir "$WORK/tar/$top/lua/"
tar -czf "$WORK/mirror/v${VERSION}/${top}.tar.gz" -C "$WORK/tar" "$top"
cat >"$WORK/deb/DEBIAN/control" <<CONTROL
Package: edgeweir-openresty
Version: 1.0.0-1
Architecture: amd64
Maintainer: test <test@example.invalid>
Description: stub of edgeweir-openresty for the SSH install test
CONTROL
printf '#!/bin/sh\necho "nginx version: openresty/1.0.0" >&2\n' >"$WORK/deb/usr/lib/edgeweir-openresty/nginx/sbin/nginx"
chmod 0755 "$WORK/deb/usr/lib/edgeweir-openresty/nginx/sbin/nginx"

docker build -q -t "$SSH_TEST_IMAGE" test/sshinstall >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -v "$WORK:/work" "$SSH_TEST_IMAGE" \
  dpkg-deb --root-owner-group --build /work/deb "/work/mirror/v${VERSION}/edgeweir-openresty_1.0.0-1_amd64.deb" >/dev/null
(cd "$WORK/mirror/v${VERSION}" && sha256sum -- * >checksums.txt)
cp "$INSTALL_SH" "$WORK/install.sh"

echo "== start"
compose up -d --quiet-pull >/dev/null
for _ in $(seq 1 30); do
  if compose exec -T client curl -fsS http://console:8080/pin >/dev/null 2>&1; then break; fi
  sleep 1
done
PIN="$(compose exec -T client curl -fsS http://console:8080/pin | tr -d '[:space:]')"

# cssh [-t] USER HOST CMD: the console's SSH session (no terminal unless -t).
cssh() {
  local tty="-T"
  if [ "$1" = "-t" ]; then tty="-tt"; shift; fi
  local user="$1" host="$2"
  shift 2
  compose exec -T client ssh "$tty" -i /work/keys/id_ed25519 -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$user@$host" "$@"
}
# token T [CLUSTER]: a single-use token (of cluster-ssh by default).
token() { compose exec -T client curl -fsS -X POST "http://console:8080/token?t=$1&cluster=${2:-cluster-ssh}" >/dev/null; }
mode() { compose exec -T client curl -fsS -X POST "http://console:8080/mode?$1" >/dev/null; }
state() { compose exec -T client curl -fsS http://console:8080/state; }
# put_token USER HOST FILE TOKEN: a 0600 token file, sent on stdin.
put_token() { printf '%s' "$4" | cssh "$1" "$2" "umask 077; cat >$3"; }
# result FILE [STEP]: the JSON of the last EDGEWEIR_RESULT line of STEP
# (default enroll: the node's own line) in FILE. install.sh writes one
# line per step and ends with {"step":"done",...}.
result() { sed -n 's/^EDGEWEIR_RESULT //p' "$1" | grep -F "\"step\":\"${2:-enroll}\"" | tail -n1 || true; }
# field FILE NAME [STEP]: one field of that line.
field() { result "$1" "${3:-}" | sed -n "s/.*\"$2\":\"\{0,1\}\([^,\"}]*\).*/\1/p"; }
for _ in $(seq 1 30); do
  if cssh root host1 true 2>/dev/null && cssh root host2 true 2>/dev/null; then break; fi
  sleep 1
done
ARGS="--server https://console:8443 --ca-sha256 ${PIN} --version ${VERSION} --format tar \
  --mirror http://console:8080/mirror --mirror-only --allow-unsigned --no-modsecurity --no-start"

echo "== install as root (host1)"
token ewt_root
put_token root host1 /root/edgeweir.token ewt_root
set +e
cssh root host1 "bash -s -- ${ARGS} --token-file /root/edgeweir.token" <"$WORK/install.sh" >"$WORK/root.out" 2>"$WORK/root.err"
code=$?
set -e
check "root install exits 0 (got $code)" test "$code" = 0
check "root install prints the enroll result" test "$(field "$WORK/root.out" status)" = enrolled
check "root install ends with done ok" test "$(field "$WORK/root.out" status done):$(field "$WORK/root.out" exit done)" = "ok:0"
check "root install: identity owned by the service user" \
  test "$(cssh root host1 'stat -c %U /var/lib/edgeweir-node/node.key')" = edgeweir
check "root install: no pending key left" cssh root host1 'test ! -e /var/lib/edgeweir-node/enroll.key'
if grep -q $'\033\\[' "$WORK/root.err"; then
  echo "NOTE install.sh writes ANSI colour codes to a non-terminal stderr"
fi
node1="$(field "$WORK/root.out" node_id)"

echo "== re-run on the enrolled host (new token, as a retried batch does)"
token ewt_root-2
put_token root host1 /root/edgeweir.token ewt_root-2
set +e
cssh root host1 "bash -s -- ${ARGS} --token-file /root/edgeweir.token" <"$WORK/install.sh" >"$WORK/rerun.out" 2>"$WORK/rerun.err"
code=$?
set -e
check "re-run exits 0 (got $code)" test "$code" = 0
check "re-run keeps the node (already_enrolled ${node1})" \
  test "$(field "$WORK/rerun.out" status):$(field "$WORK/rerun.out" node_id)" = "already_enrolled:${node1}"
check "re-run ends with done ok" test "$(field "$WORK/rerun.out" status done)" = ok
set +e
cssh root host1 "edgeweir-node enroll --if-not-enrolled --server https://console:8443 --ca-sha256 ${PIN}" >"$WORK/ine.out" 2>/dev/null
code=$?
set -e
check "--if-not-enrolled: exit 0, already_enrolled ${node1}" \
  test "$code:$(field "$WORK/ine.out" status):$(field "$WORK/ine.out" node_id)" = "0:already_enrolled:${node1}"

echo "== install as a sudo user (host2, sudo -n)"
token ewt_sudo
put_token deploy host2 /home/deploy/edgeweir.token ewt_sudo
set +e
cssh deploy host2 "sudo -n bash -s -- ${ARGS} --token-file /home/deploy/edgeweir.token" <"$WORK/install.sh" >"$WORK/sudo.out" 2>"$WORK/sudo.err"
code=$?
set -e
check "sudo install exits 0 (got $code)" test "$code" = 0
check "sudo install prints the enroll result" test "$(field "$WORK/sudo.out" status)" = enrolled
set +e
cssh pwuser host2 'sudo -n true' >/dev/null 2>"$WORK/pw.err"
code=$?
set -e
check "sudo with a password fails at once without a terminal" \
  test "$code" != 0 -a -n "$(grep -i 'password is required' "$WORK/pw.err")"

echo "== lost answer, retried with the same token (host2, own state dir)"
token ewt_lost
mode "lose=1"
put_token root host2 /root/lost.token ewt_lost
E="edgeweir-node enroll --server https://console:8443 --ca-sha256 ${PIN} --token-file /root/lost.token"
set +e
cssh root host2 "$E --state-dir /var/lib/lost" >"$WORK/lost1.out" 2>/dev/null
code1=$?
cssh root host2 "$E --state-dir /var/lib/lost" >"$WORK/lost2.out" 2>/dev/null
code2=$?
set -e
check "lost answer: unreachable (13), retry true" \
  test "$code1:$(field "$WORK/lost1.out" status):$(field "$WORK/lost1.out" retry)" = "13:unreachable:true"
check "retry with the same token enrolls (got $code2)" test "$code2:$(field "$WORK/lost2.out" status)" = "0:enrolled"
nodes_before="$(state)"

echo "== lost answer, retried with a token of another cluster (host2)"
token ewt_other-a
token ewt_other-b other-cluster
mode "lose=1"
put_token root host2 /root/xa.token ewt_other-a
put_token root host2 /root/xb.token ewt_other-b
X="edgeweir-node enroll --server https://console:8443 --ca-sha256 ${PIN} --state-dir /var/lib/xcluster"
set +e
cssh root host2 "$X --token-file /root/xa.token" >/dev/null 2>&1
cssh root host2 "$X --token-file /root/xb.token" >"$WORK/xb.out" 2>/dev/null
codeb=$?
cssh root host2 "$X --token-file /root/xa.token" >"$WORK/xa.out" 2>/dev/null
codea=$?
set -e
check "known key with another cluster's token: token_rejected (got $codeb)" \
  test "$codeb:$(field "$WORK/xb.out" status)" = "12:token_rejected"
check "then its own token: enrolled (got $codea)" test "$codea:$(field "$WORK/xa.out" status)" = "0:enrolled"

echo "== SSH session with a terminal dropped during the enrollment (host1)"
token ewt_drop
mode "delay=4s"
put_token root host1 /root/drop.token ewt_drop
cssh -t root host1 "edgeweir-node enroll --server https://console:8443 --ca-sha256 ${PIN} --token-file /root/drop.token --state-dir /var/lib/drop" >/dev/null 2>&1 &
ssh_pid=$!
sleep 1.5
# The console's side of the connection goes away (as when the SSH link drops).
compose exec -T client pkill -f 'ssh -tt' || true
wait "$ssh_pid" 2>/dev/null || true
sleep 6
check "dropped session: the enrollment completed" cssh root host1 'test -s /var/lib/drop/identity.json'

echo "== two enrollments of one host at once (host2)"
token ewt_a
token ewt_b
mode "delay=3s"
put_token root host2 /root/a.token ewt_a
put_token root host2 /root/b.token ewt_b
C="edgeweir-node enroll --server https://console:8443 --ca-sha256 ${PIN} --state-dir /var/lib/twice"
set +e
cssh root host2 "$C --token-file /root/a.token" >"$WORK/a.out" 2>/dev/null &
pa=$!
sleep 0.5
cssh root host2 "$C --token-file /root/b.token" >"$WORK/b.out" 2>/dev/null
cb=$?
wait "$pa"
ca=$?
set -e
check "concurrent: first enrolls, second busy (got $ca/$cb)" \
  test "$ca:$(field "$WORK/a.out" status):$cb:$(field "$WORK/b.out" status)" = "0:enrolled:16:busy"
mode "delay=0s"

echo "== console"
final="$(state)"
echo "$final"
# root, sudo, lost (once), other cluster (once), dropped, concurrent: six
# nodes, one per identity.
count_nodes() { printf '%s' "$1" | grep -o '"node-[0-9]*"' | sort -u | wc -l || true; }
nodes="$(count_nodes "$final")"
check "console has exactly 6 nodes (got $nodes)" test "$nodes" = 6
check "lost answer made no second node" test "$(count_nodes "$nodes_before")" = 3

if [ "$failures" -ne 0 ]; then
  for f in root.err sudo.err lost1.out; do
    echo "--- $f"
    cat "$WORK/$f" 2>/dev/null || true
  done
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
