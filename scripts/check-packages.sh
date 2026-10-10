#!/usr/bin/env bash
# Checks the release artifacts in dist/ (goreleaser release --snapshot --clean,
# or a release): every deb, rpm and tar.gz carries the binary, the Lua
# modules, LICENSE and the repository's NOTICE; every binary was built with the
# release tags (nodynamic, wasm2go) and links neither purego nor wazero, and
# NOTICE lists every module it links. Needs bsdtar (macOS tar, libarchive) or
# GNU tar with ar for the deb files, and Go for `go version -m`.
set -euo pipefail
cd "$(dirname "$0")/.."
DIST="${1:-dist}"
TAGS=nodynamic,wasm2go
fail() { echo "FAIL: $*" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

shopt -s nullglob
debs=("$DIST"/edgeweir-node_*.deb)
rpms=("$DIST"/edgeweir-node-*.rpm)
tars=("$DIST"/edgeweir-node_*.tar.gz)
[ ${#debs[@]} -ge 2 ] && [ ${#rpms[@]} -ge 2 ] && [ ${#tars[@]} -ge 2 ] ||
  fail "expected deb, rpm and tar.gz for amd64 and arm64 in $DIST (${#debs[@]} / ${#rpms[@]} / ${#tars[@]})"

# extract <package> <dir>: unpacks a deb (its data archive), rpm or tar.gz.
extract() {
  mkdir -p "$2"
  case "$1" in
  *.deb)
    (cd "$2" && ar x "$OLDPWD/$1" && tar -xf data.tar.* && rm -f data.tar.* control.tar.* debian-binary)
    ;;
  *) tar -xf "$1" -C "$2" ;;
  esac
}

check_binary() { # binary, label
  local info
  info=$(go version -m "$1") || fail "$2: not a Go binary"
  grep -q "build	-tags=$TAGS" <<<"$info" || fail "$2: not built with -tags=$TAGS"
  grep -q "build	CGO_ENABLED=0" <<<"$info" || fail "$2: built with cgo"
  for module in github.com/ebitengine/purego github.com/tetratelabs/wazero; do
    if grep -q "dep	$module	" <<<"$info"; then fail "$2: links $module"; fi
  done
  while read -r path version; do
    grep -qF "  $path $version: " NOTICE || fail "$2: NOTICE does not list $path $version (scripts/notice.sh)"
  done < <(awk -F'\t' '$2 == "dep" { print $3, $4 }' <<<"$info")
}

for pkg in "${debs[@]}" "${rpms[@]}" "${tars[@]}"; do
  dir="$tmp/$(basename "$pkg")"
  extract "$pkg" "$dir"
  case "$pkg" in
  *.tar.gz)
    root=$(find "$dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    bin="$root/edgeweir-node"
    notice="$root/NOTICE"
    license="$root/LICENSE"
    lua="$root/lua/edgeweir/imageconv.lua"
    ;;
  *)
    bin="$dir/usr/bin/edgeweir-node"
    notice="$dir/usr/share/doc/edgeweir-node/NOTICE"
    license="$dir/usr/share/doc/edgeweir-node/LICENSE"
    lua="$dir/usr/share/edgeweir-node/lua/edgeweir/imageconv.lua"
    ;;
  esac
  for f in "$bin" "$notice" "$license" "$lua"; do
    [ -f "$f" ] || fail "$(basename "$pkg") lacks ${f#"$dir"/}"
  done
  cmp -s "$notice" NOTICE || fail "$(basename "$pkg"): NOTICE differs from the repository's"
  check_binary "$bin" "$(basename "$pkg")"
  echo "ok   $(basename "$pkg"): $(wc -c <"$bin" | tr -d ' ') bytes, -tags=$TAGS, NOTICE, LICENSE, Lua modules"
done
echo "packages checked"
