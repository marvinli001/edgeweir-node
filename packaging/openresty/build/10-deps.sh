#!/usr/bin/env bash
# Step 1: unpack and patch the sources, check their licenses, build the
# static dependencies (PIC: PCRE2 also goes into libmodsecurity).
source /build/steps/common.sh

rm -rf "$src" "$deps"
mkdir -p "$src" "$deps/lib/pkgconfig" "$deps/include"
for f in "$dl"/*.tar.gz "$dl"/*.tar.xz; do tar -xf "$f" -C "$src" --no-same-owner; done
mv "$src/ngx_brotli-$(ver ngx_brotli)" "$ngx_brotli"
rm -rf "$ngx_brotli/deps/brotli"
mv "$src/brotli-$(ver brotli)" "$ngx_brotli/deps/brotli"
patch -d "$nginx_src" -p1 --no-backup-if-mismatch </build/patches/nginx-nogroup.patch
for p in /build/patches/yajl-*.patch; do patch -d "$yajl" -p1 --no-backup-if-mismatch <"$p"; done
patch -d "$modsecurity" -p1 --no-backup-if-mismatch </build/patches/modsecurity-request-body-phase.patch
patch -d "$modsecurity_nginx" -p1 --no-backup-if-mismatch </build/patches/modsecurity-nginx-log-vars.patch
patch -d "$zstd_module" -p1 --no-backup-if-mismatch </build/patches/zstd-nginx-module-libs.patch

while IFS='|' read -r name version spdx file phrase; do
  [ -f "$file" ] || { echo "license file missing: $name ($file)" >&2; exit 1; }
  grep -qF -- "$phrase" "$file" || { echo "license of $name changed: '$phrase' not in $file" >&2; exit 1; }
  echo "license ok: $name $version $spdx"
done < <(licenses)

(
  cd "$zlib"
  CFLAGS="$pic" ./configure --prefix="$deps" --static
  make -j"$jobs" libz.a
  make install
)
(
  cd "$pcre2"
  CFLAGS="$pic" ./configure --prefix="$deps" --disable-shared --enable-static --with-pic \
    --enable-pcre2-8 --disable-pcre2-16 --disable-pcre2-32 --enable-jit --enable-unicode \
    --enable-newline-is-lf --disable-pcre2grep-libz --disable-pcre2grep-libbz2
  make -j"$jobs" libpcre2-8.la
  make install-libLTLIBRARIES install-nodist_includeHEADERS install-pkgconfigDATA
)
(
  cd "$openssl"
  ./Configure "$openssl_target" --prefix="$deps" --libdir=lib --openssldir="$prefix/openssl" \
    no-shared no-tests no-docs enable-ktls $cflags
  make -j"$jobs" build_libs
  make install_dev
)
(
  cd "$ngx_brotli/deps/brotli"
  cmake -S . -B out -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
    -DCMAKE_C_FLAGS="$cflags" -DCMAKE_C_FLAGS_RELEASE="-DNDEBUG"
  cmake --build out --target brotlienc brotlicommon -j"$jobs"
)
make -C "$zstd/lib" -j"$jobs" libzstd.a CFLAGS="$cflags"
(
  # YAJL: nine C files, compiled directly instead of through its CMake.
  mkdir -p "$deps/include/yajl" /build/yajl-obj
  install -m 0644 "$yajl"/src/api/yajl_common.h "$yajl"/src/api/yajl_gen.h "$yajl"/src/api/yajl_parse.h \
    "$yajl"/src/api/yajl_tree.h "$deps/include/yajl/"
  sed -e 's/${YAJL_MAJOR}/2/' -e 's/${YAJL_MINOR}/1/' -e 's/${YAJL_MICRO}/0/' \
    "$yajl/src/api/yajl_version.h.cmake" >"$deps/include/yajl/yajl_version.h"
  cd "$yajl/src"
  for c in yajl.c yajl_alloc.c yajl_buf.c yajl_encode.c yajl_gen.c yajl_lex.c yajl_parser.c yajl_tree.c yajl_version.c; do
    gcc $pic -std=c99 -DNDEBUG -DYAJL_BUILD -I"$deps/include" -I. -c "$c" -o "/build/yajl-obj/${c%.c}.o"
  done
  ar rcsD "$deps/lib/libyajl.a" /build/yajl-obj/*.o
  cat >"$deps/lib/pkgconfig/yajl.pc" <<PC
prefix=$deps
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: Yet Another JSON Library
Description: A Portable JSON parsing and serialization library in ANSI C
Version: $(ver yajl)
Cflags: -I\${includedir}
Libs: -L\${libdir} -lyajl
PC
)
(
  cd "$libxml2"
  CFLAGS="$pic" ./configure --prefix="$deps" --disable-shared --enable-static --with-pic \
    --without-python --without-zlib --without-icu --without-http --without-catalog --without-debug \
    --without-history --without-readline --without-modules --without-docs
  make -j"$jobs" libxml2.la
  make install-libLTLIBRARIES install-pkgconfigDATA
  make -C include install
)
ls -l "$deps/lib"
