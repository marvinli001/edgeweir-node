#!/usr/bin/env bash
# Step 4: trim and strip the installation, add the CRS, check what the
# node relies on, write NOTICE and the component list (CycloneDX, picked up
# by syft), and copy everything with normalized owners, modes and
# timestamps to /out/tree.
source /build/steps/common.sh

rm -rf "$prefix/pod" "$prefix/site" "$prefix/resty.index" "$prefix/nginx/html" "$prefix/nginx/logs" \
  "$prefix/luajit/share/man" "$prefix/luajit/lib/pkgconfig" "$prefix/luajit/include" \
  "$prefix/luajit/lib/libluajit-5.1.a" "$prefix/luajit/lib/libluajit-5.1.so" \
  "$prefix/bin/opm" "$prefix/bin/restydoc" "$prefix/bin/restydoc-index" "$prefix/bin/md2pod.pl" \
  "$prefix/bin/nginx-xml2pod" "$prefix/lib/libmodsecurity.so" "$prefix/lib/libmodsecurity.la" \
  "$prefix/lib/pkgconfig" "$prefix/COPYRIGHT"
find "$prefix" -name '*.so*' -type f -exec strip --strip-unneeded {} +
strip "$prefix/nginx/sbin/nginx" "$prefix"/luajit/bin/luajit-*

rm -rf "$share" "$doc"
install -d "$share/crs" "$share/modsecurity" "$doc"
cp -a "$crs/rules" "$crs/plugins" "$crs/LICENSE" "$share/crs/"
rm -f "$share/crs/rules/"*.example
# CRS needs a setup file; the upstream example is its supported default.
install -m 0644 "$crs/crs-setup.conf.example" "$share/crs/crs-setup.conf"
install -m 0644 "$modsecurity/unicode.mapping" "$share/modsecurity/unicode.mapping"

# --- checks ------------------------------------------------------------------
nginx=$prefix/nginx/sbin/nginx
"$nginx" -V 2>"$doc/nginx-V.txt"
cat "$doc/nginx-V.txt"
grep -Eq -- "--add-module=$ngx_brotli( |\$)" "$doc/nginx-V.txt"
grep -Eq -- "--add-module=$zstd_module( |\$)" "$doc/nginx-V.txt"
grep -q "built with OpenSSL $(ver openssl) " "$doc/nginx-V.txt"
needed() { objdump -p "$1" | awk '$1 == "NEEDED" { print $2 }' | sort | tr '\n' ' '; }
echo "nginx needs: $(needed "$nginx")"
echo "libmodsecurity needs: $(needed "$prefix/lib/libmodsecurity.so.3")"
echo "ModSecurity module needs: $(needed "$prefix/modules/ngx_http_modsecurity_module.so")"
for lib in $(needed "$nginx"); do
  case "$lib" in
    libluajit-5.1.so.2|libc.so.6|libm.so.6|libdl.so.2|libpthread.so.0|libgcc_s.so.1|ld-linux-*) ;;
    *) echo "nginx must not need $lib" >&2; exit 1 ;;
  esac
done
for lib in $(needed "$prefix/lib/libmodsecurity.so.3") $(needed "$prefix/modules/ngx_http_modsecurity_module.so"); do
  case "$lib" in
    libmodsecurity.so.3|libstdc++.so.6|libc.so.6|libm.so.6|libgcc_s.so.1|ld-linux-*) ;;
    *) echo "ModSecurity must not need $lib" >&2; exit 1 ;;
  esac
done
glibc=$(objdump -T "$nginx" "$prefix/lib/libmodsecurity.so.3" "$prefix/modules/ngx_http_modsecurity_module.so" \
  "$prefix"/luajit/lib/libluajit-5.1.so.2 | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
[ "$glibc" = GLIBC_2.34 ] || { echo "the binaries need $glibc; the baseline is glibc 2.34" >&2; exit 1; }
glibcxx=$(objdump -T "$prefix/lib/libmodsecurity.so.3" | grep -o 'GLIBCXX_[0-9.]*' | sort -uV | tail -1)
# libstdc++ of GCC 11 (EL9); Debian 12 and Ubuntu 22.04 ship newer ones.
[ "$(printf '%s\n' "$glibcxx" GLIBCXX_3.4.29 | sort -V | tail -1)" = GLIBCXX_3.4.29 ] ||
  { echo "libmodsecurity needs $glibcxx, more than EL9's GLIBCXX_3.4.29" >&2; exit 1; }
echo "glibc baseline $glibc, libmodsecurity needs $glibcxx"
# (Symbol lists go through files: grep -q closing a pipe early would fail
# the pipeline under pipefail.)
exported() { objdump -T "$1" | grep -vF '*UND*' | awk '{ print $NF }' | sort -u >"$2"; }
exported "$nginx" /tmp/nginx.syms
exported "$prefix/modules/ngx_http_modsecurity_module.so" /tmp/module.syms
exported "$prefix/lib/libmodsecurity.so.3" /tmp/libmodsecurity.syms
for sym in OpenSSL_version_num EVP_MAC_fetch EVP_MAC_init RAND_bytes SHA256_Init EVP_DigestInit_ex pcre2_compile_8; do
  grep -qx "$sym" /tmp/nginx.syms || { echo "nginx does not export $sym" >&2; exit 1; }
done
for sym in EVP_MAC_fetch pcre2_compile_8 xmlReadMemory yajl_alloc; do
  if grep -qx "$sym" /tmp/module.syms /tmp/libmodsecurity.syms; then
    echo "ModSecurity must not export $sym" >&2; exit 1
  fi
done
rm -f /tmp/*.syms

t=$(mktemp -d)
mkdir -p "$t/logs"
cat >"$t/modsec.conf" <<CONF
SecRuleEngine On
SecRequestBodyAccess On
SecUnicodeMapFile $share/modsecurity/unicode.mapping 20127
Include $share/crs/crs-setup.conf
Include $share/crs/rules/*.conf
CONF
cat >"$t/nginx.conf" <<CONF
load_module $prefix/modules/ngx_http_modsecurity_module.so;
error_log stderr notice;
pid $t/logs/nginx.pid;
events {}
http {
    modsecurity_rules_file $t/modsec.conf;
    server {
        listen 127.0.0.1:18080;
        brotli on;
        brotli_comp_level 6;
        zstd on;
        zstd_comp_level 3;
        location / { modsecurity on; return 200 "\$modsecurity_intervention \$modsecurity_triggered_rules\n"; }
    }
}
CONF
"$nginx" -p "$t" -c "$t/nginx.conf" -e stderr -t
"$prefix/bin/resty" -e '
  local version = require("resty.openssl.version")
  assert(version.version_text:find("'"$(ver openssl)"'", 1, true), version.version_text)
  local hmac = require("resty.openssl.hmac").new("key", "sha256")
  assert(#hmac:final("data") == 32)
  assert(#require("resty.openssl.rand").bytes(16) == 16)
  local sha = require("resty.sha256"):new()
  sha:update("abc")
  assert(require("resty.string").to_hex(sha:final()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  print("LuaJIT FFI uses the built-in ", version.version_text)'
rm -rf "$t"

# --- NOTICE, component list, build information ------------------------------
{
  echo "edgeweir-openresty $(ver openresty) and edgeweir-openresty-modsecurity"
  echo
  echo "These packages contain software built from the third-party sources below."
  echo "Every component is under a license that permits commercial use; the full"
  echo "license texts follow. Local changes: security fixes for YAJL taken from"
  echo "Fedora (CVE-2017-16516, CVE-2022-24795, CVE-2023-33460 and memory leaks)"
  echo "and a backport of ModSecurity-nginx pull request #374"
  echo "(\$modsecurity_intervention, \$modsecurity_triggered_rules)."
  echo
  while IFS='|' read -r name version spdx file phrase; do
    printf '  %-50s %-42s %s\n' "$name" "$version" "$spdx"
  done < <(licenses)
  while IFS='|' read -r name version spdx file phrase; do
    echo
    echo "================================================================================"
    echo "$name $version ($spdx): ${file#"$src"/}"
    echo "================================================================================"
    echo
    cat "$file"
  done < <(licenses)
} >"$doc/NOTICE"

python3 - "$lock" "$doc/edgeweir-openresty.cdx.json" "$openresty" "$modsecurity" <<'PY'
# Component list (CycloneDX) of everything built into the packages: the
# pinned sources, the OpenResty bundle components that are built, and the
# libraries ModSecurity bundles. syft includes it in the release SBOM.
import json, os, re, sys
lock, out, openresty, modsecurity = sys.argv[1:5]
spdx = {
    "openresty": "BSD-2-Clause", "openssl": "Apache-2.0", "pcre2": "BSD-3-Clause WITH PCRE2-exception",
    "zlib": "Zlib", "brotli": "MIT", "ngx_brotli": "BSD-2-Clause", "zstd": "BSD-3-Clause",
    "zstd-nginx-module": "BSD-2-Clause", "modsecurity": "Apache-2.0", "modsecurity-nginx": "Apache-2.0",
    "yajl": "ISC", "libxml2": "MIT", "coreruleset": "Apache-2.0",
}
def component(name, version, lic, purl, description=None, sha256=None, url=None):
    c = {
        "type": "library", "bom-ref": f"{name}@{version}", "name": name, "version": version, "purl": purl,
        "licenses": [{"expression": lic}] if " " in lic else [{"license": {"id": lic}}],
    }
    if description:
        c["description"] = description
    if sha256:
        c["hashes"] = [{"alg": "SHA-256", "content": sha256}]
    if url:
        c["externalReferences"] = [{"type": "distribution", "url": url}]
    return c
components = []
for line in open(lock):
    f = line.split()
    if not f or f[0].startswith("#") or f[0] == "epoch":
        continue
    name, version, sha256, url = f[:4]
    components.append(component(name, version, spdx[name], f"pkg:generic/{name}@{version}?download_url={url}",
                                sha256=sha256, url=url))
openresty_version = next(c["version"] for c in components if c["name"] == "openresty")
# Bundle components that the build leaves out (see build/30-openresty.sh).
skip = {"drizzle-nginx-module", "iconv-nginx-module", "ngx_postgres", "rds-csv-nginx-module",
        "rds-json-nginx-module", "lua-rds-parser", "opm", "pod", "install"}
bundle_licenses = {"LuaJIT": "MIT", "lua-cjson": "MIT", "lua-resty-rsa": "MIT", "ngx_devel_kit": "BSD-3-Clause"}
for entry in sorted(os.listdir(os.path.join(openresty, "bundle"))):
    m = re.match(r"^(.+?)-(\d[\w.]*(?:-\d+)?)$", entry)
    if not m or not os.path.isdir(os.path.join(openresty, "bundle", entry)) or m.group(1) in skip:
        continue
    name, version = m.group(1), m.group(2)
    components.append(component(name, version, bundle_licenses.get(name, "BSD-2-Clause"),
                                f"pkg:generic/{name}@{version}", f"bundled with OpenResty {openresty_version}"))
def grep(path, pattern):
    return re.search(pattern, open(os.path.join(modsecurity, path)).read()).group(1)
modsec_version = next(c["version"] for c in components if c["name"] == "modsecurity")
components.append(component("libinjection", grep("others/libinjection/src/libinjection_sqli.c", r'LIBINJECTION_VERSION "([^"]+)"'),
                            "BSD-3-Clause", "pkg:generic/libinjection", f"bundled with ModSecurity {modsec_version}"))
components.append(component("mbedtls", grep("others/mbedtls/include/mbedtls/build_info.h", r'MBEDTLS_VERSION_STRING\s+"([^"]+)"'),
                            "Apache-2.0", "pkg:generic/mbedtls", f"bundled with ModSecurity {modsec_version}, used under Apache-2.0"))
for c in components:
    if c["purl"] in ("pkg:generic/libinjection", "pkg:generic/mbedtls"):
        c["purl"] += "@" + c["version"]
json.dump({
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"component": {"type": "application", "name": "edgeweir-openresty", "version": openresty_version}},
    "components": components,
}, open(out, "w"), indent=2, sort_keys=True)
PY
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort >"$doc/build-toolchain.txt"

# --- output tree -------------------------------------------------------------
rm -rf "$out"
install -d "$out/usr/lib" "$out/usr/share/doc"
cp -a "$prefix" "$out/usr/lib/"
cp -a "$share" "$out/usr/share/"
cp -a "$doc" "$out/usr/share/doc/"
chown -R 0:0 "$out"
find "$out" -type d -exec chmod 0755 {} +
find "$out" -type f -perm /0111 -exec chmod 0755 {} +
find "$out" -type f ! -perm /0111 -exec chmod 0644 {} +
find "$out" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$out" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >/out/tree.sha256
echo "edgeweir-openresty tree: $(sha256sum /out/tree.sha256)"
