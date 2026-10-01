# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# edgeweir-openresty and edgeweir-openresty-modsecurity (deb and rpm):
# OpenResty built from pinned, verified sources with Brotli, Zstandard and
# the ModSecurity dynamic module plus the OWASP CRS. The build context is the
# repository root:
#
#   make openresty-packages ARCH=arm64
#   docker buildx build --platform linux/arm64 -f packaging/openresty/Dockerfile \
#     --target packages --output type=local,dest=out/openresty .
#
# The stages between the openresty-build markers are also in the node
# image's Dockerfile (a test keeps both copies identical), so `docker build`
# of the node image needs nothing but this repository and BuildKit reuses
# one build for both.

ARG OPENRESTY_BUILDER_IMAGE=almalinux:9.7@sha256:2d57aea965da8fbda97736ec5125c1b683ce271438038ea1906b2391e89b77d2
ARG NFPM_IMAGE=goreleaser/nfpm:v2.47.0@sha256:a662cb167d7b6d3a83920c83d76b12d02b8ac5dd2c13e5c62c15270b23f6df0c

# BEGIN openresty-build
# glibc 2.34 baseline (AlmaLinux 9): the result runs on RHEL/Rocky/Alma 9,
# Debian 12, Ubuntu 22.04 and newer. The toolchain comes from the frozen
# AlmaLinux 9.7 vault. Sources: packaging/openresty/sources.lock.
FROM ${OPENRESTY_BUILDER_IMAGE} AS openresty-toolchain
COPY packaging/openresty/vault.repo /etc/yum.repos.d/edgeweir-vault.repo
RUN rm -f /etc/yum.repos.d/almalinux-*.repo \
 && dnf -y -q --setopt=install_weak_deps=False install \
      gcc gcc-c++ make cmake perl-core patch xz bzip2 gnupg2 findutils diffutils which file \
      pkgconf-pkg-config python3 binutils \
 && dnf clean all

FROM openresty-toolchain AS openresty-sources
COPY packaging/openresty/sources.lock packaging/openresty/fetch.sh /build/
COPY packaging/openresty/keys/ /build/keys/
RUN /build/fetch.sh /build/sources.lock /build/keys /build/dl

FROM openresty-sources AS openresty-build
ARG OPENRESTY_JOBS=2
COPY packaging/openresty/patches/ /build/patches/
COPY packaging/openresty/build/common.sh packaging/openresty/build/10-deps.sh /build/steps/
RUN JOBS=$OPENRESTY_JOBS /build/steps/10-deps.sh
COPY packaging/openresty/build/20-modsecurity.sh /build/steps/
RUN JOBS=$OPENRESTY_JOBS /build/steps/20-modsecurity.sh
COPY packaging/openresty/build/30-openresty.sh /build/steps/
RUN JOBS=$OPENRESTY_JOBS /build/steps/30-openresty.sh
COPY packaging/openresty/build/40-tree.sh /build/steps/
RUN /build/steps/40-tree.sh
# END openresty-build

FROM scratch AS tree
COPY --from=openresty-build /out/ /

# nfpm runs natively; only the package architecture follows the target.
FROM --platform=$BUILDPLATFORM ${NFPM_IMAGE} AS packager
ARG TARGETARCH
COPY --from=openresty-build /out/tree/ /tree/
COPY packaging/openresty/nfpm/ /nfpm/
COPY packaging/openresty/sources.lock /nfpm/
RUN set -eu; \
    epoch=$(awk '$1 == "epoch" { print $2 }' /nfpm/sources.lock); \
    version=$(awk '$1 == "openresty" { print $2 }' /nfpm/sources.lock); \
    release=$(awk '$1 == "release:" { print $2 }' /nfpm/edgeweir-openresty.yaml); \
    case "$release" in ''|*[!0-9]*) echo "release of edgeweir-openresty.yaml: '$release'" >&2; exit 1 ;; esac; \
    mtime=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ); \
    export SOURCE_DATE_EPOCH="$epoch"; \
    mkdir -p /out; \
    for pkg in edgeweir-openresty edgeweir-openresty-modsecurity; do \
      sed -e "s/\${ARCH}/$TARGETARCH/g" -e "s/\${VERSION}/$version/g" -e "s/\${RELEASE}/$release/g" \
        -e "s/\${MTIME}/$mtime/g" \
        "/nfpm/$pkg.yaml" >"/tmp/$pkg.yaml"; \
      for format in deb rpm; do \
        nfpm package --config "/tmp/$pkg.yaml" --packager "$format" --target /out/; \
      done; \
    done; \
    ls -l /out

FROM scratch AS packages
COPY --from=packager /out/ /
COPY --from=openresty-build /out/tree.sha256 /tree.sha256
