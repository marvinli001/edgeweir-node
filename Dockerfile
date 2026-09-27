# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# edgeweir-node container image: the Go agent supervising OpenResty.
#
#   docker build -t edgeweir-node:dev .
#   docker run -d -p 80:80 -v edgeweir-node:/var/lib/edgeweir-node edgeweir-node:dev
#   read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # paste the one-time token
#   docker exec -e EDGEWEIR_TOKEN <container> edgeweir-node enroll \
#       --server https://console:8443 --ca-sha256 <sha256>
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
ARG OPENRESTY_IMAGE=openresty/openresty:1.31.1.1-bookworm@sha256:8005b87dcb25df5e202e71dcc4b8a2c20a4845a75302b2bb6ee816b5392883e4

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

# Synthetic MMDBs for compose.e2e.yml; never copied into the release image.
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

# ---- runtime: official OpenResty image, unprivileged user ----------------
FROM ${OPENRESTY_IMAGE}
ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.title="edgeweir-node" \
      org.opencontainers.image.description="Edgeweir edge node: Go agent + OpenResty" \
      org.opencontainers.image.source="https://github.com/marvinli001/edgeweir-node" \
      org.opencontainers.image.url="https://edgeweir.dev" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

# Agent, nginx master and workers all run as uid 10001. Docker lets
# unprivileged processes bind :80 inside the container network namespace
# (net.ipv4.ip_unprivileged_port_start=0).
RUN groupadd --system --gid 10001 edgeweir \
 && useradd --system --uid 10001 --gid edgeweir --home-dir /var/lib/edgeweir-node \
      --no-create-home --shell /usr/sbin/nologin edgeweir \
 && install -d -o edgeweir -g edgeweir -m 0700 /var/lib/edgeweir-node \
 && install -d -o edgeweir -g edgeweir -m 0750 /run/edgeweir-node /var/cache/edgeweir-node

COPY --from=build /out/edgeweir-node /usr/local/bin/edgeweir-node
COPY --from=verifier /cosign /usr/local/bin/cosign
COPY lua/ /usr/share/edgeweir-node/lua/

ENV EDGEWEIR_STATE_DIR=/var/lib/edgeweir-node \
    EDGEWEIR_NGINX_BIN=/usr/local/openresty/nginx/sbin/nginx \
    EDGEWEIR_LUA_DIR=/usr/share/edgeweir-node/lua \
    EDGEWEIR_CACHE_DIR=/var/cache/edgeweir-node \
    EDGEWEIR_CONTROL_SOCKET=/run/edgeweir-node/control.sock \
    EDGEWEIR_ORIGIN_SOCKET=/run/edgeweir-node/origin.sock

USER edgeweir
VOLUME ["/var/lib/edgeweir-node"]
EXPOSE 80
# The agent handles SIGTERM and stops OpenResty gracefully (the base image
# uses SIGQUIT, which would make the Go runtime dump goroutines).
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/edgeweir-node", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/edgeweir-node", "supervise", "--manage-nginx"]
