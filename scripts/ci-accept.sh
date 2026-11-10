#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export E2E_NODE_IMAGE="${E2E_NODE_IMAGE:-edgeweir-node:${COMPOSE_PROJECT_NAME:-ci}}"
export E2E_GEOIP_IMAGE="${E2E_GEOIP_IMAGE:-edgeweir-node:${COMPOSE_PROJECT_NAME:-ci}-geoip}"
export E2E_CONSOLE_IMAGE="${E2E_CONSOLE_IMAGE:-edgeweir-node:${COMPOSE_PROJECT_NAME:-ci}-console}"
case "${1:-}" in
  checks)
    go mod verify
    test -z "$(gofmt -l cmd internal test)"
    make pin-check
    go vet ./...
    go test -race -count=1 ./...
    ;;
  proto)
    make proto-check PROTO_INPUT='https://github.com/marvinli001/edgeweir.git#tag=$(PROTO_TAG),subdir=proto'
    ;;
  lua) make lua-test ;;
  snapshot)
    goreleaser check
    goreleaser release --snapshot --clean
    make package-check
    ;;
  containers)
    docker buildx bake -f test/e2e/compose.yml --set '*.context=.' --set node.args.OPENRESTY_JOBS=4 --load node console geoip
    E2E_SKIP_BUILD=1 E2E_STATS=1 make e2e
    ;;
  cleanup)
    docker compose -f test/e2e/compose.yml down -v --remove-orphans
    for image in "$E2E_NODE_IMAGE" "$E2E_GEOIP_IMAGE" "$E2E_CONSOLE_IMAGE"; do
      if docker image inspect "$image" >/dev/null 2>&1; then docker image rm "$image"; fi
    done
    docker builder prune -f
    ;;
  *) echo 'Expected checks, proto, lua, snapshot, containers or cleanup' >&2; exit 2 ;;
esac
