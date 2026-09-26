#!/usr/bin/env bash
# Mirror docs/adr from the console repository, which is the source of truth.
# The only change is that relative links to files that exist only in the
# console repository (BOOTSTRAP.md, proto/, ...) become GitHub URLs.
#
#   scripts/sync-adr.sh [--check] [console-dir]    (default: ../edgeweir)
#
# --check exits non-zero when docs/adr differs from the mirrored copy.
set -euo pipefail
cd "$(dirname "$0")/.."

check=false
if [ "${1:-}" = "--check" ]; then
  check=true
  shift
fi
src="${1:-../edgeweir}/docs/adr"
dst="docs/adr"
base="https://github.com/marvinli001/edgeweir/blob/master"
[ -d "$src" ] || { echo "no ADR directory at $src" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in "$src"/*.md; do
  BASE="$base" perl -pe '
    s{\]\(\.\./\.\./([^)#\s]+)(#[^)\s]*)?\)}{
      my ($path, $frag) = ($1, $2 // "");
      -e $path ? "](../../$path$frag)" : "]($ENV{BASE}/$path$frag)"
    }ge' "$f" >"$tmp/$(basename "$f")"
done

if $check; then
  diff -ru "$tmp" "$dst" && echo "docs/adr is in sync with $src"
  exit
fi
rm -f "$dst"/*.md
cp "$tmp"/*.md "$dst"/
echo "mirrored $(ls "$tmp" | wc -l | tr -d ' ') files from $src"
