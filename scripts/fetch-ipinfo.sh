#!/bin/sh
# Download the IPinfo Lite MMDB (country + ASN) into DIR at build time and
# check it against the sha256 IPinfo publishes for the same file.
#
#   IPINFO_TOKEN=... scripts/fetch-ipinfo.sh [--require] DIR
#
# The token goes to ipinfo.io in the documented ?token= parameter, not a
# header: wget would repeat a header to the CDN host IPinfo redirects to.
# wget -q prints neither URLs nor headers, and nothing is written to DIR but
# the database and its NOTICE. Without IPINFO_TOKEN, or when the download
# fails, DIR stays empty (the node then runs without bundled GeoIP data);
# --require turns both into errors. BusyBox-compatible wget, grep, sha256sum.
set -eu

require=0
if [ "${1:-}" = "--require" ]; then
	require=1
	shift
fi
dir=${1:?usage: fetch-ipinfo.sh [--require] DIR}
mkdir -p "$dir"

skip() {
	if [ "$require" = 1 ]; then
		echo "fetch-ipinfo: $1" >&2
		exit 1
	fi
	echo "fetch-ipinfo: $1; building without the IPinfo Lite database" >&2
	exit 0
}

[ -n "${IPINFO_TOKEN:-}" ] || skip "IPINFO_TOKEN not set"

url=https://ipinfo.io/data/ipinfo_lite.mmdb
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# IPinfo refreshes the file daily; a checksum taken across an update will not
# match, so try a second time before giving up.
for attempt in 1 2; do
	wget -q -T 60 -O "$tmp/ipinfo_lite.mmdb" "$url?token=${IPINFO_TOKEN}" || skip "download failed"
	wget -q -T 60 -O "$tmp/checksums.json" "$url/checksums?token=${IPINFO_TOKEN}" || skip "checksum download failed"
	want=$(grep -o '"sha256": *"[0-9a-f]\{64\}"' "$tmp/checksums.json" | grep -o '[0-9a-f]\{64\}') || want=
	got=$(sha256sum "$tmp/ipinfo_lite.mmdb" | cut -d' ' -f1)
	if [ -n "$want" ] && [ "$got" = "$want" ]; then
		break
	fi
	[ "$attempt" = 1 ] || skip "sha256 mismatch (got $got, IPinfo lists ${want:-nothing})"
done

mv "$tmp/ipinfo_lite.mmdb" "$dir/ipinfo_lite.mmdb"
chmod 0644 "$dir/ipinfo_lite.mmdb"
cat > "$dir/NOTICE" <<EOF
IP address data is powered by IPinfo (https://ipinfo.io).

ipinfo_lite.mmdb is the IPinfo Lite database, licensed under the Creative
Commons Attribution-ShareAlike 4.0 International License
(https://creativecommons.org/licenses/by-sa/4.0/). It is redistributed
unmodified.

Downloaded: $(date -u +%Y-%m-%dT%H:%M:%SZ)
SHA-256:    $got
EOF
chmod 0644 "$dir/NOTICE"
echo "fetch-ipinfo: bundled IPinfo Lite database ($got)" >&2
