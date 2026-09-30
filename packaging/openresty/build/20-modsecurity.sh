#!/usr/bin/env bash
# Step 2: libmodsecurity as a private shared library in $prefix/lib, with
# PCRE2, YAJL and libxml2 linked in statically and their symbols hidden
# (--exclude-libs), so they never interpose with the nginx binary's PCRE2.
source /build/steps/common.sh

rm -rf "$modsec_dev"
cd "$modsecurity"
PKG_CONFIG_PATH="$deps/lib/pkgconfig" ./configure \
  --prefix="$prefix" --libdir="$prefix/lib" --includedir="$modsec_dev/include" \
  --bindir="$modsec_dev/bin" --datarootdir="$modsec_dev/share" \
  --enable-shared --disable-static --disable-examples --disable-doxygen-doc \
  --with-pcre2="$deps" --with-yajl="$deps" --with-libxml="$deps" \
  --without-pcre --without-curl --without-geoip --without-maxmind --without-lmdb \
  --without-lua --without-ssdeep \
  CFLAGS="$pic" CXXFLAGS="$pic" LDFLAGS="$ldflags -Wl,--exclude-libs,ALL" LIBS="-lm"
for feature in WITH_YAJL WITH_LIBXML2; do
  grep -q -- "-D$feature" src/Makefile || { echo "libmodsecurity configured without $feature" >&2; exit 1; }
done
grep -q '^PCRE2_LDADD = .*pcre2-8' src/Makefile || { echo "libmodsecurity configured without PCRE2" >&2; exit 1; }
make -j"$jobs"
make install
ls -l "$prefix/lib"
