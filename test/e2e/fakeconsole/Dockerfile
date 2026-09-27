# Fake console for the container smoke test only (never published).
FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY internal ./internal
COPY test/e2e/fakeconsole ./test/e2e/fakeconsole
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/fakeconsole ./test/e2e/fakeconsole

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
COPY --from=build /out/fakeconsole /usr/local/bin/fakeconsole
# /shared receives the HTTPS origin's CA for the node (named volume).
RUN install -d -o 65534 -g 65534 -m 0755 /shared
USER 65534:65534
EXPOSE 8443 8444 8081
ENTRYPOINT ["/usr/local/bin/fakeconsole"]
