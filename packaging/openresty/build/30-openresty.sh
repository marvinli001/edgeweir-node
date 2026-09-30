#!/usr/bin/env bash
# Step 3: OpenResty with the official configure arguments plus Brotli and
# Zstandard (static modules), then ModSecurity-nginx as a dynamic module in
# a second nginx configure pass against the same patched nginx sources.
#
# The nginx binary links OpenSSL and PCRE2 as whole archives and exports
# them (-Wl,-E, from ngx_lua): LuaJIT FFI code (lua-resty-openssl,
# resty.sha256) resolves libcrypto functions in the process and would
# otherwise fall back to loading the system's libcrypto. Dynamic modules
# are linked with --with-ld-opt too, hence the separate pass for the
# module without those archives.
source /build/steps/common.sh

# OpenResty's configure adds -O2 in front (as in the official -V output);
# nginx's own configure (module pass) does not.
cc_opt="-DNGX_LUA_ABORT_AT_PANIC $harden $map -I$deps/include"
common=(
  --with-pcre-jit
  --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module
  --with-http_v2_module --with-http_v3_module
  --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module
  --with-http_stub_status_module --with-http_realip_module --with-http_addition_module
  --with-http_auth_request_module --with-http_secure_link_module --with-http_random_index_module
  --with-http_gzip_static_module --with-http_sub_module --with-http_dav_module --with-http_flv_module
  --with-http_mp4_module --with-http_slice_module --with-http_gunzip_module
  --with-threads --with-compat --with-http_ssl_module
  # auth_basic needs crypt(3): libcrypt.so.2 on EL9 but libcrypt.so.1 on
  # Debian and Ubuntu, so the binary would not run everywhere. Unused.
  --without-http_auth_basic_module
)

rm -rf "$prefix/nginx" "$prefix/luajit" "$prefix/lualib" "$prefix/bin" "$prefix/modules"
(
  cd "$openresty"
  ZSTD_INC="$zstd/lib" ZSTD_LIB="$zstd/lib" ./configure \
    --prefix="$prefix" \
    --with-ld-opt="$ldflags -L$deps/lib -Wl,--whole-archive $deps/lib/libcrypto.a $deps/lib/libpcre2-8.a -Wl,--no-whole-archive" \
    --without-http_rds_json_module --without-http_rds_csv_module --without-lua_rds_parser \
    --with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT' \
    --with-cc-opt="$cc_opt" \
    "${common[@]}" \
    --add-module="$ngx_brotli" \
    --add-module="$zstd_module" \
    -j"$jobs"
  make -j"$jobs"
  make install
)
(
  rm -rf /build/nginx-modules
  cp -a "$nginx_src" /build/nginx-modules
  cd /build/nginx-modules
  MODSECURITY_INC="$modsec_dev/include" MODSECURITY_LIB="$prefix/lib" ./configure \
    --prefix="$prefix/nginx" \
    --with-ld-opt="$ldflags -L$deps/lib" \
    --with-cc-opt="-O2 $cc_opt" \
    "${common[@]}" \
    --add-dynamic-module="$modsecurity_nginx"
  make -j"$jobs" modules
  install -d "$prefix/modules"
  install -m 0755 objs/ngx_http_modsecurity_module.so "$prefix/modules/"
)
"$prefix/nginx/sbin/nginx" -V
