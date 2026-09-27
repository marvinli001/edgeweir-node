#!/bin/sh
# Download the IPinfo Lite MMDB (country + ASN) into DIR at build time and
# check it against the sha256 IPinfo publishes for the same file.
#
#   IPINFO_TOKEN=... scripts/fetch-ipinfo.sh [--require] DIR
#
# The token is only sent to ipinfo.io as a Bearer header; it is never written
# to DIR. Without IPINFO_TOKEN the script leaves DIR empty (the node then runs
# without bundled GeoIP data) unless --require is given. Uses BusyBox-compatible
# wget, grep and sha256sum only.
set -eu

require=0
if [ "${1:-}" = "--require" ]; then
	require=1
	shift
fi
dir=${1:?usage: fetch-ipinfo.sh [--require] DIR}
mkdir -p "$dir"

if [ -z "${IPINFO_TOKEN:-}" ]; then
	if [ "$require" = 1 ]; then
		echo "fetch-ipinfo: IPINFO_TOKEN is required for this build" >&2
		exit 1
	fi
	echo "fetch-ipinfo: IPINFO_TOKEN not set; building without the IPinfo Lite database" >&2
	exit 0
fi

url=https://ipinfo.io/data/ipinfo_lite.mmdb
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# IPinfo refreshes the file daily; a checksum taken across an update will not
# match, so try a second time before giving up.
for attempt in 1 2; do
	wget -q -T 60 --header "Authorization: Bearer ${IPINFO_TOKEN}" -O "$tmp/ipinfo_lite.mmdb" "$url"
	wget -q -T 60 --header "Authorization: Bearer ${IPINFO_TOKEN}" -O "$tmp/checksums.json" "$url/checksums"
	want=$(grep -o '"sha256": *"[0-9a-f]\{64\}"' "$tmp/checksums.json" | grep -o '[0-9a-f]\{64\}') || want=
	got=$(sha256sum "$tmp/ipinfo_lite.mmdb" | cut -d' ' -f1)
	if [ -n "$want" ] && [ "$got" = "$want" ]; then
		break
	fi
	if [ "$attempt" = 2 ]; then
		echo "fetch-ipinfo: sha256 mismatch (got $got, IPinfo lists ${want:-nothing})" >&2
		exit 1
	fi
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
