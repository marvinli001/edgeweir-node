#!/usr/bin/env bash
# Downloads and verifies every source listed in sources.lock.
#
#   fetch.sh [lock file] [key directory] [download directory]
#
# Each archive is saved as <name>-<version>.tar.{gz,xz} and must match its
# pinned SHA-256. When the lock names a signature, it is verified with gpgv
# against that single pinned key file, and the key that made the signature
# must belong to the pinned primary fingerprint (a subkey of it is fine).
# Anything else fails the build.
set -euo pipefail

lock=${1:-/build/sources.lock}
keys=${2:-/build/keys}
dl=${3:-/build/dl}
mkdir -p "$dl"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
install -d -m 0700 "$GNUPGHOME"

fetch() { # url file
  local attempt
  for attempt in 1 2 3 4 5; do
    if curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2.part" "$1"; then
      mv "$2.part" "$2"
      return 0
    fi
    echo "download of $1 failed (attempt $attempt)" >&2
    sleep $((attempt * 3))
  done
  return 1
}

while read -r name version sha256 url sig key fpr; do
  case "$name" in ''|'#'*|epoch) continue ;; esac
  case "$url" in
    *.tar.xz) ext=tar.xz ;;
    *.tar.gz) ext=tar.gz ;;
    *) echo "unsupported archive type: $url" >&2; exit 1 ;;
  esac
  file="$dl/$name-$version.$ext"
  [ -s "$file" ] || fetch "$url" "$file"
  echo "$sha256  $file" | sha256sum -c --quiet - || { echo "SHA-256 mismatch: $name $version" >&2; exit 1; }

  if [ -n "${sig:-}" ]; then
    [ -n "${key:-}" ] && [ -n "${fpr:-}" ] || { echo "$name: signature without key and fingerprint" >&2; exit 1; }
    fetch "$sig" "$file.sig"
    ring="$work/$key.gpg"
    gpg --batch --quiet --dearmor <"$keys/$key" >"$ring"
    # The key file must hold exactly the pinned primary key.
    got=$(gpg --batch --with-colons --show-keys "$keys/$key" | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; p = 0 }')
    [ "$got" = "$fpr" ] || { echo "$name: keys/$key holds $got, want $fpr" >&2; exit 1; }
    status=$(gpgv --keyring "$ring" --status-fd 1 "$file.sig" "$file" 2>/dev/null) ||
      { echo "bad signature: $name $version" >&2; exit 1; }
    # VALIDSIG <signing key> <date> <timestamp> <expiry> <version> <reserved>
    #          <pubkey algo> <hash algo> <class> <primary key fingerprint>
    primary=$(awk '$2 == "VALIDSIG" { print $NF }' <<<"$status")
    [ "$primary" = "$fpr" ] || { echo "$name: signed by $primary, want $fpr" >&2; exit 1; }
    echo "verified $name $version (sha256 + signature by $fpr)"
  else
    echo "verified $name $version (sha256)"
  fi
done <"$lock"
