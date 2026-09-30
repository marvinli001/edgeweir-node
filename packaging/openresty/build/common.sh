# Shared settings of the build steps (sourced by build/*.sh).
#
#   /build/dl/*.tar.*  ->  /out/tree/usr/lib/edgeweir-openresty       (OpenResty)
#                          /out/tree/usr/share/edgeweir-openresty     (CRS, unicode.mapping)
#                          /out/tree/usr/share/doc/edgeweir-openresty (NOTICE, component list)
#
# Reproducible: fixed paths, SOURCE_DATE_EPOCH from sources.lock,
# -ffile-prefix-map, stripped binaries, normalized timestamps.
set -euo pipefail

lock=/build/sources.lock
dl=/build/dl
src=/build/src
deps=/build/deps
modsec_dev=/build/modsec
prefix=/usr/lib/edgeweir-openresty
share=/usr/share/edgeweir-openresty
doc=/usr/share/doc/edgeweir-openresty
out=/out/tree
jobs=${JOBS:-2}

epoch=$(awk '$1 == "epoch" { print $2 }' "$lock")
export SOURCE_DATE_EPOCH=$epoch TZ=UTC LC_ALL=C LANG=C
umask 022
ver() { awk -v n="$1" '$1 == n { print $2 }' "$lock"; }

case "$(uname -m)" in
  x86_64) openssl_target=linux-x86_64; cet=-fcf-protection ;;
  aarch64) openssl_target=linux-aarch64; cet= ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

map="-ffile-prefix-map=/build/src=/usr/src/edgeweir-openresty"
harden="-fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 $cet"
cflags="-O2 -pipe $harden $map"
pic="$cflags -fPIC"
ldflags="-Wl,-z,relro -Wl,-z,now"

openresty=$src/openresty-$(ver openresty)
openssl=$src/openssl-$(ver openssl)
pcre2=$src/pcre2-$(ver pcre2)
zlib=$src/zlib-$(ver zlib)
zstd=$src/zstd-$(ver zstd)
zstd_module=$src/zstd-nginx-module-$(ver zstd-nginx-module)
modsecurity=$src/modsecurity-v$(ver modsecurity)
modsecurity_nginx=$src/ModSecurity-nginx-v$(ver modsecurity-nginx)
yajl=$src/yajl-$(ver yajl)
libxml2=$src/libxml2-$(ver libxml2)
crs=$src/coreruleset-$(ver coreruleset)
ngx_brotli=$src/ngx_brotli
nginx_src=$openresty/bundle/nginx-$(ver openresty | cut -d. -f1-3)

# Components, their licenses (all permit commercial use) and a phrase each
# license file must still contain; NOTICE reproduces the files.
#   component|version|SPDX|license file|phrase
licenses() {
  local bundle=$openresty/bundle
  cat <<LIST
OpenResty (bundle: ngx_lua, lua-resty-*, resty-cli and the other bundled modules)|$(ver openresty)|BSD-2-Clause|$openresty/COPYRIGHT|Redistribution and use in source and binary forms
nginx|$(ver openresty | cut -d. -f1-3)|BSD-2-Clause|$nginx_src/LICENSE|Redistribution and use in source and binary forms
LuaJIT|$(basename "$bundle"/LuaJIT-* | sed 's/^LuaJIT-//')|MIT|$(echo "$bundle"/LuaJIT-*/COPYRIGHT)|Permission is hereby granted, free of charge
lua-cjson|$(basename "$bundle"/lua-cjson-* | sed 's/^lua-cjson-//')|MIT|$(echo "$bundle"/lua-cjson-*/LICENSE)|Permission is hereby granted, free of charge
lua-resty-openssl|$(basename "$bundle"/lua-resty-openssl-* | sed 's/^lua-resty-openssl-//')|BSD-2-Clause|$(echo "$bundle"/lua-resty-openssl-*/LICENSE)|Redistribution and use in source and binary forms
lua-resty-rsa|$(basename "$bundle"/lua-resty-rsa-* | sed 's/^lua-resty-rsa-//')|MIT|$(echo "$bundle"/lua-resty-rsa-*/LICENSE)|Permission is hereby granted, free of charge
ngx_devel_kit|$(basename "$bundle"/ngx_devel_kit-* | sed 's/^ngx_devel_kit-//')|BSD-3-Clause|$(echo "$bundle"/ngx_devel_kit-*/LICENSE)|Redistribution and use in source and binary forms
echo-nginx-module|$(basename "$bundle"/echo-nginx-module-* | sed 's/^echo-nginx-module-//')|BSD-2-Clause|$(echo "$bundle"/echo-nginx-module-*/LICENSE)|Redistribution and use in source and binary forms
headers-more-nginx-module|$(basename "$bundle"/headers-more-nginx-module-* | sed 's/^headers-more-nginx-module-//')|BSD-2-Clause|$(echo "$bundle"/headers-more-nginx-module-*/LICENSE)|Redistribution and use in source and binary forms
ngx_coolkit|$(basename "$bundle"/ngx_coolkit-* | sed 's/^ngx_coolkit-//')|BSD-2-Clause|$(echo "$bundle"/ngx_coolkit-*/LICENSE)|Redistribution and use in source and binary forms
ngx_stream_lua|$(basename "$bundle"/ngx_stream_lua-* | sed 's/^ngx_stream_lua-//')|BSD-2-Clause|$(echo "$bundle"/ngx_stream_lua-*/LICENSE)|Redistribution and use in source and binary forms
redis-nginx-module|$(basename "$bundle"/redis-nginx-module-* | sed 's/^redis-nginx-module-//')|BSD-2-Clause|$(echo "$bundle"/redis-nginx-module-*/LICENSE)|Redistribution and use in source and binary forms
OpenSSL|$(ver openssl)|Apache-2.0|$openssl/LICENSE.txt|Apache License
PCRE2|$(ver pcre2)|BSD-3-Clause WITH PCRE2-exception|$pcre2/LICENCE.md|BSD-3-Clause WITH PCRE2-exception
zlib|$(ver zlib)|Zlib|$zlib/LICENSE|provided 'as-is', without any express or implied
Brotli|$(ver brotli)|MIT|$ngx_brotli/deps/brotli/LICENSE|Permission is hereby granted, free of charge
ngx_brotli|$(ver ngx_brotli)|BSD-2-Clause|$ngx_brotli/LICENSE|Redistribution and use in source and binary forms
Zstandard (used under its BSD license)|$(ver zstd)|BSD-3-Clause|$zstd/LICENSE|Redistribution and use in source and binary forms
zstd-nginx-module|$(ver zstd-nginx-module)|BSD-2-Clause|$zstd_module/LICENSE|BSD 2-Clause License
ModSecurity (libmodsecurity)|$(ver modsecurity)|Apache-2.0|$modsecurity/LICENSE|Apache License
libinjection (bundled with ModSecurity)|$(ver modsecurity)|BSD-3-Clause|$modsecurity/others/libinjection/COPYING|Redistribution and use in source and binary forms
Mbed TLS (bundled with ModSecurity, used under Apache-2.0)|$(ver modsecurity)|Apache-2.0|$modsecurity/others/mbedtls/LICENSE|Apache-2.0
ModSecurity-nginx|$(ver modsecurity-nginx)|Apache-2.0|$modsecurity_nginx/LICENSE|Apache License
YAJL|$(ver yajl)|ISC|$yajl/COPYING|Permission to use, copy, modify, and/or distribute
libxml2|$(ver libxml2)|MIT|$libxml2/Copyright|Permission is hereby granted, free of charge
OWASP CRS|$(ver coreruleset)|Apache-2.0|$crs/LICENSE|Apache License
LIST
}
