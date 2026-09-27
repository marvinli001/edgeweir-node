#!/usr/bin/env bash
# Fail when a third-party container image or GitHub Action is referenced by a
# movable tag (ADR-0017): images need a digest (tag@sha256:...), Actions a full
# commit SHA followed by the release it came from (@<sha> # vX.Y.Z). Images
# built from this repository (edgeweir-node:*) keep plain tags.
#
#   scripts/check-pins.sh        (make pin-check; runs in CI)
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
unpinned() { echo "unpinned: $*" >&2; fail=1; }
digest='@sha256:[0-9a-f]{64}$'

# GitHub Actions.
while IFS= read -r line; do
  ref="$(sed -E 's/^[^:]+:[0-9]+:[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*//' <<<"$line")"
  [[ "$ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\ \#\ v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    unpinned "$line"
done < <(grep -HnE '^[[:space:]]*(-[[:space:]]*)?uses:' .github/workflows/*.yml)

# Compose files.
while IFS= read -r line; do
  image="$(sed -E 's/^[^:]+:[0-9]+:[[:space:]]*image:[[:space:]]*//; s/[[:space:]]+$//' <<<"$line")"
  [[ "$image" =~ ^edgeweir-node: || "$image" =~ $digest ]] || unpinned "$line"
done < <(git ls-files -z '*compose*.yml' | xargs -0 grep -HnE '^[[:space:]]*image:')

# Dockerfiles: the syntax frontend, *_IMAGE defaults and every FROM that is
# neither such an argument, an earlier stage nor scratch.
while IFS= read -r -d '' file; do
  awk -v file="$file" '
    function check(ref) {
      # mawk has no {64} intervals: check the digest length separately.
      if (ref !~ /@sha256:[0-9a-f]+$/ || length(substr(ref, index(ref, "@sha256:") + 8)) != 64) {
        print "unpinned: " file ":" NR ": " ref > "/dev/stderr"; bad = 1
      }
    }
    NR == 1 && /^# syntax=/ { check(substr($0, 10)) }
    /^ARG [A-Z_]+_IMAGE=/ { ref = $2; sub(/^[^=]*=/, "", ref); check(ref) }
    toupper($1) == "FROM" {
      i = 2; if ($i ~ /^--platform=/) i++
      if (!($i in stage) && $i != "scratch" && $i !~ /^\$\{[A-Z_]+_IMAGE\}$/) check($i)
      if (toupper($(i + 1)) == "AS") stage[$(i + 2)] = 1
    }
    END { exit bad }' "$file" || fail=1
done < <(git ls-files -z '*Dockerfile*')

# Makefile variables naming an image (the Lua tests run in OPENRESTY_FAT).
while IFS= read -r line; do
  [[ "$line" =~ \?=[[:space:]]*edgeweir-node: || "$line" =~ $digest ]] || unpinned "Makefile: $line"
done < <(grep -E '^[A-Z_]+[[:space:]]*\?=[[:space:]]*[a-z0-9./-]+:[^[:space:]]+$' Makefile)

if ((fail)); then
  echo "pin images by digest and Actions by commit SHA (CONTRIBUTING.md)" >&2
  exit 1
fi
echo "images and GitHub Actions are pinned"
