# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# edgeweir-node container image: the Go agent supervising OpenResty.
#
#   docker build -t edgeweir-node:dev .
#   docker run -d -p 80:80 -v edgeweir-node:/var/lib/edgeweir-node edgeweir-node:dev
#   read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # paste the one-time token
#   docker exec -e EDGEWEIR_TOKEN <container> edgeweir-node enroll \
#       --server https://console:8443 --ca-sha256 <sha256>
#
# Kernel bans (nftables) need an image built with
# --build-arg NFT_CAPABILITY=true and `docker run --cap-add NET_ADMIN`.
#
# `-e EDGEWEIR_TOKEN` without a value passes the variable from the current
# environment, so the token never appears on a command line (--token would
# show it in ps).
#
# The agent starts OpenResty immediately with a bootstrap configuration
# (404 X-Edgeweir-Error: unknown-host on :80), waits until the node is
# enrolled and then follows the console.

# Base images are pinned by tag and multi-arch index digest; the digest is
# what gets pulled (ADR-0017). Refresh tag and digest together (CONTRIBUTING.md).
ARG GO_IMAGE=golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
# OpenResty (edgeweir-openresty) is built from source below; see
# packaging/openresty for the pinned sources and the deb/rpm packages.
ARG OPENRESTY_BUILDER_IMAGE=almalinux:9.7@sha256:2d57aea965da8fbda97736ec5125c1b683ce271438038ea1906b2391e89b77d2

# ---- build: static agent, cross-compiled on the build platform ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/marvinli001/edgeweir-node/internal/version.Version=${VERSION} \
        -X github.com/marvinli001/edgeweir-node/internal/version.Commit=${COMMIT} \
        -X github.com/marvinli001/edgeweir-node/internal/version.Date=${DATE}" \
      -o /out/edgeweir-node ./cmd/edgeweir-node

# Synthetic MMDBs (City, ASN, IPinfo Lite schema) for compose.e2e.yml; never
# copied into the release image.
FROM build AS geoip-build
COPY test/geoip ./test/geoip
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/geoip-fixture ./test/geoip
FROM scratch AS geoip-fixture
COPY --from=geoip-build /out/geoip-fixture /geoip-fixture
ENTRYPOINT ["/geoip-fixture", "/data"]

# A pinned, checksum-verified verifier travels with both image architectures.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS verifier
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) digest=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;; \
      arm64) digest=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;; \
      *) exit 1 ;; \
    esac; \
    wget -q -O /cosign "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-${TARGETARCH}"; \
    echo "$digest  /cosign" | sha256sum -c -; chmod 0755 /cosign

# IPinfo Lite (country + ASN, CC BY-SA 4.0), downloaded at build time when the
# build is given the ipinfo_token secret (`IPINFO_TOKEN=... make docker`):
#   docker build --secret id=ipinfo_token,env=IPINFO_TOKEN \
#     --build-arg IPINFO_DATE=$(date -u +%F) .
# Without the secret, or if the download fails, the image ships no GeoIP data
# (--geoip-ipinfo auto finds nothing). The token is a BuildKit secret, so it
# never reaches a layer, the build arguments or the provenance attestation.
# BuildKit caches this step regardless of the secret; IPINFO_DATE only keys the
# cache, so the data is fetched at most once a day (IPinfo limits downloads).
# IPINFO_REQUIRED=1 (release builds) makes a missing secret or failed download
# fatal. The agent's own reader then vets the file, so a format change fails
# the build rather than the nodes.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS ipinfo
ARG IPINFO_REQUIRED=
ARG IPINFO_DATE=
COPY scripts/fetch-ipinfo.sh /usr/local/bin/fetch-ipinfo
RUN --mount=type=secret,id=ipinfo_token,env=IPINFO_TOKEN \
    fetch-ipinfo ${IPINFO_REQUIRED:+--require} /out/geoip
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/geoip ./internal/geoip
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ -f /out/geoip/ipinfo_lite.mmdb ]; then go run ./internal/geoip/check /out/geoip/ipinfo_lite.mmdb; fi

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

# ---- runtime: Debian with edgeweir-openresty, unprivileged user -----------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.title="edgeweir-node" \
      org.opencontainers.image.description="Edgeweir edge node: Go agent + OpenResty" \
      org.opencontainers.image.source="https://github.com/marvinli001/edgeweir-node" \
      org.opencontainers.image.url="https://edgeweir.dev" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

# nftables for kernel bans (platform bans dropped in the input hook). The
# agent runs as uid 10001, so nft only works when the image is built with
# --build-arg NFT_CAPABILITY=true (nft gets the file capability
# cap_net_admin+ep) and the container is started with --cap-add NET_ADMIN.
# Without both the agent enforces bans at the edge layer only; the default
# image adds no capability.
ARG NFT_CAPABILITY=false
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates nftables; \
    case "$NFT_CAPABILITY" in \
      true) apt-get install -y --no-install-recommends libcap2-bin; \
            setcap cap_net_admin+ep /usr/sbin/nft; \
            apt-get purge -y --auto-remove libcap2-bin ;; \
      false) ;; \
      *) echo "NFT_CAPABILITY must be true or false" >&2; exit 1 ;; \
    esac; \
    rm -rf /var/lib/apt/lists/*

# Agent, nginx master and workers all run as uid 10001. Docker lets
# unprivileged processes bind :80 inside the container network namespace
# (net.ipv4.ip_unprivileged_port_start=0).
RUN groupadd --system --gid 10001 edgeweir \
 && useradd --system --uid 10001 --gid edgeweir --home-dir /var/lib/edgeweir-node \
      --no-create-home --shell /usr/sbin/nologin edgeweir \
 && install -d -o edgeweir -g edgeweir -m 0700 /var/lib/edgeweir-node /var/lib/edgeweir-probe \
 && install -d -o edgeweir -g edgeweir -m 0750 /run/edgeweir-node /var/cache/edgeweir-node

# The same tree as the edgeweir-openresty and edgeweir-openresty-modsecurity
# packages: OpenResty, the ModSecurity module and the OWASP CRS.
COPY --from=openresty-build /out/tree/usr/lib/edgeweir-openresty/ /usr/lib/edgeweir-openresty/
COPY --from=openresty-build /out/tree/usr/share/edgeweir-openresty/ /usr/share/edgeweir-openresty/
COPY --from=openresty-build /out/tree/usr/share/doc/edgeweir-openresty/ /usr/share/doc/edgeweir-openresty/
COPY --from=build /out/edgeweir-node /usr/local/bin/edgeweir-node
COPY --from=verifier /cosign /usr/local/bin/cosign
COPY lua/ /usr/share/edgeweir-node/lua/
# ipinfo_lite.mmdb + NOTICE, or nothing when built without the token.
COPY --from=ipinfo /out/geoip/ /usr/share/edgeweir-node/geoip/

ENV EDGEWEIR_STATE_DIR=/var/lib/edgeweir-node \
    EDGEWEIR_NGINX_BIN=/usr/lib/edgeweir-openresty/nginx/sbin/nginx \
    EDGEWEIR_LUA_DIR=/usr/share/edgeweir-node/lua \
    EDGEWEIR_CACHE_DIR=/var/cache/edgeweir-node \
    EDGEWEIR_CONTROL_SOCKET=/run/edgeweir-node/control.sock \
    EDGEWEIR_ORIGIN_SOCKET=/run/edgeweir-node/origin.sock

USER edgeweir
VOLUME ["/var/lib/edgeweir-node"]
EXPOSE 80
# The agent handles SIGTERM and stops OpenResty gracefully (SIGQUIT, nginx's
# graceful stop, would make the Go runtime dump goroutines).
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/edgeweir-node", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/edgeweir-node", "supervise", "--manage-nginx"]
