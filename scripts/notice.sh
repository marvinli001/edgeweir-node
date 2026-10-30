#!/usr/bin/env bash
# Writes NOTICE: the third-party software compiled into edgeweir-node with
# its license texts. Go modules come from the release build (the build tags
# of .goreleaser.yaml); the C libraries compiled to WebAssembly inside
# github.com/gen2brain/webp and github.com/gen2brain/avif come with the
# versions their lib/Makefile builds and the texts in packaging/licenses/.
# Run after changing go.mod (make notice); a new module fails until its
# license is reviewed and added to spdx() below.
set -euo pipefail
cd "$(dirname "$0")/.."

TAGS=nodynamic,wasm2go
modcache=$(go env GOMODCACHE)

spdx() {
	case "$1" in
	connectrpc.com/connect) echo Apache-2.0 ;;
	github.com/coder/websocket) echo ISC ;;
	github.com/JohannesKaufmann/dom | github.com/JohannesKaufmann/html-to-markdown/v2) echo MIT ;;
	github.com/gen2brain/avif | github.com/gen2brain/webp) echo MIT ;;
	github.com/oschwald/maxminddb-golang/v2) echo ISC ;;
	golang.org/x/crypto | golang.org/x/net | golang.org/x/sys | golang.org/x/text | google.golang.org/protobuf) echo BSD-3-Clause ;;
	*)
		echo "notice.sh: review the license of $1 and add it to spdx()" >&2
		return 1
		;;
	esac
}

makefile_var() { awk -v k="$2" '$1 == k && $2 == "=" { print $3 }' "$1"; }

mods=$(GOOS=linux go list -deps -tags "$TAGS" -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/edgeweir-node | sort -u)
webp_dir="$modcache/$(go list -m -f '{{.Path}}@{{.Version}}' github.com/gen2brain/webp)"
avif_dir="$modcache/$(go list -m -f '{{.Path}}@{{.Version}}' github.com/gen2brain/avif)"
libwebp=$(makefile_var "$webp_dir/lib/Makefile" LIBWEBP_VERSION)
libavif=$(makefile_var "$avif_dir/lib/Makefile" LIBAVIF_VERSION)
aom=$(makefile_var "$avif_dir/lib/Makefile" LIBAVIF_AOM_VERSION)
dav1d=$(makefile_var "$avif_dir/lib/Makefile" LIBAVIF_DAV1D_VERSION)
libyuv=$(makefile_var "$avif_dir/lib/Makefile" LIBAVIF_YUV_VERSION)
go_version=$(go mod edit -json | awk -F'"' '$2 == "Go" { print $4 }')

text() {
	printf '\n-------------------------------------------------------------------------------\n%s\n-------------------------------------------------------------------------------\n\n' "$1"
	cat "$2"
}

{
	cat <<EOF
edgeweir-node
Copyright the Edgeweir authors. Licensed under AGPL-3.0-only (LICENSE).

edgeweir-node includes the following third-party software. Their license
texts follow below.

Go (standard library), go ${go_version}: BSD-3-Clause

Go modules:
EOF
	while read -r path version; do
		printf '  %s %s: %s\n' "$path" "$version" "$(spdx "$path")"
	done <<<"$mods"
	cat <<EOF

C libraries compiled to WebAssembly and transpiled to Go inside
github.com/gen2brain/webp and github.com/gen2brain/avif (WebP / AVIF
conversion):
  libwebp ${libwebp}: BSD-3-Clause, with the WebM Additional IP Rights Grant
  libavif ${libavif}: BSD-2-Clause
  aom ${aom}: BSD-2-Clause, with the Alliance for Open Media Patent License 1.0
  dav1d ${dav1d}: BSD-2-Clause
  libyuv ${libyuv}: BSD-3-Clause, with the LibYuv Additional IP Rights Grant
EOF
	text "Go (standard library)" "$modcache/$(go list -m -f '{{.Path}}@{{.Version}}' golang.org/x/sys)/LICENSE"
	while read -r path version; do
		for f in "$modcache/$path@$version"/{LICENSE,LICENSE.txt,LICENSE.md,COPYING,NOTICE,PATENTS}; do
			[ -f "$f" ] && text "$path $version: $(basename "$f")" "$f"
		done
	done <<<"$mods"
	for lib in libwebp.LICENSE libwebp.PATENTS libavif.LICENSE aom.LICENSE aom.PATENTS dav1d.LICENSE libyuv.LICENSE libyuv.PATENTS; do
		text "${lib%%.*}: ${lib#*.}" "packaging/licenses/$lib"
	done
} >NOTICE
echo "NOTICE: $(wc -l <NOTICE) lines"
