# edgeweir-node developer tasks. Run `make help` for a list.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Protobuf contract -------------------------------------------------------
# The node channel contract lives in the console repository (edgeweir/proto)
# and is consumed from an immutable git tag. Locally we read the sibling
# checkout; CI overrides PROTO_INPUT with the GitHub URL:
#   make proto-check PROTO_INPUT='https://github.com/marvinli001/edgeweir.git#tag=$(PROTO_TAG),subdir=proto'
PROTO_TAG   ?= proto/v0.28.0
PROTO_INPUT ?= ../edgeweir/.git\#tag=$(PROTO_TAG),subdir=proto

# --- Build metadata ----------------------------------------------------------
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
PKG     := github.com/marvinli001/edgeweir-node/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

# --- edgeweir-openresty -------------------------------------------------------
# OpenResty with Brotli, Zstandard, ModSecurity and the OWASP CRS, built from
# packaging/openresty/sources.lock. ARCH is the package architecture.
ARCH              ?= $(if $(filter arm64 aarch64,$(shell uname -m)),arm64,amd64)
OPENRESTY_OUT     ?= out/openresty
OPENRESTY_JOBS    ?= 2
OPENRESTY_VERSION := $(shell awk '$$1 == "openresty" { print $$2 }' packaging/openresty/sources.lock)
OPENRESTY_RELEASE := $(shell awk '$$1 == "release:" { print $$2 }' packaging/openresty/nfpm/edgeweir-openresty.yaml)
OPENRESTY_BUILD   := docker buildx build --platform linux/$(ARCH) --build-arg OPENRESTY_JOBS=$(OPENRESTY_JOBS) \
	-f packaging/openresty/Dockerfile

IMAGE          ?= edgeweir-node:dev
OPENRESTY_FAT  ?= openresty/openresty:1.31.1.1-bookworm-fat@sha256:59eaa54c12021e799adbea1bc3acdf4097f9cac105f889e417d017deb263a755

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build a static binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/edgeweir-node ./cmd/edgeweir-node

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: test
test: ## Run unit and in-process integration tests
	go test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector
	go test -race ./...

.PHONY: proto
proto: ## Regenerate Go code from the edgeweir proto git tag
	buf generate "$(PROTO_INPUT)"

.PHONY: proto-check
proto-check: proto ## Regenerate and fail if the committed code differs
	@git diff --exit-code -- internal/gen || { echo "generated code is stale: run 'make proto' and commit"; exit 1; }
	@test -z "$$(git status --porcelain -- internal/gen)" || { git status --porcelain -- internal/gen; echo "untracked generated files: run 'make proto' and commit"; exit 1; }

.PHONY: pin-check
pin-check: ## Fail if an image or GitHub Action is referenced by a movable tag
	scripts/check-pins.sh

.PHONY: lua-test
lua-test: ## Run Lua unit tests with resty inside the OpenResty image
	docker run --rm -v "$(CURDIR)/lua:/lua:ro" -v "$(CURDIR)/test/lua:/t:ro" $(OPENRESTY_FAT) sh -c '\
		resty -I /lua --shdict "edgeweir_sites 4m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_stats 4m" \
			--shdict "edgeweir_purge 4m" --shdict "edgeweir_health 1m" --shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_topstats 4m" \
			--shdict "edgeweir_bans 4m" --shdict "edgeweir_tags 1m" --shdict "edgeweir_purge_rate 1m" /t/run.lua && \
		resty -I /lua --shdict "edgeweir_purge 4m" --shdict "edgeweir_tags 1m" /t/tags.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" /t/errorpages.lua && \
		resty -I /lua --shdict "edgeweir_challenge 1m" --shdict "edgeweir_health 1m" /t/origins.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_health 1m" \
			--shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_stats 1m" --shdict "edgeweir_topstats 1m" /t/rules_v2.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_health 1m" \
			--shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_stats 1m" --shdict "edgeweir_topstats 1m" /t/rules_v3.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_health 1m" \
			--shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_stats 1m" --shdict "edgeweir_topstats 1m" /t/edgeports.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_health 1m" \
			--shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_stats 1m" --shdict "edgeweir_topstats 1m" \
			--shdict "edgeweir_auth 1m" /t/auth.lua && \
		resty -I /lua --shdict "edgeweir_sites 4m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_cc 1m" --shdict "edgeweir_bans 1m" /t/domains.lua && \
		resty -I /lua /t/sigv4.lua && resty -I /lua /t/expressions.lua && resty -I /lua /t/http3.lua && resty -I /lua /t/ja4.lua && \
		resty -I /lua /t/compress.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_health 1m" \
			--shdict "edgeweir_challenge 1m" --shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_purge_rate 1m" /t/content.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" /t/probehealth.lua && \
		resty -I /lua --shdict "edgeweir_sites 1m" --shdict "edgeweir_meta 1m" --shdict "edgeweir_bans 1m" --shdict "edgeweir_cc 1m" \
			--shdict "edgeweir_health 1m" --shdict "edgeweir_policy_logs 1m" --shdict "edgeweir_stats 1m" --shdict "edgeweir_topstats 1m" /t/tls.lua && \
		resty -I /lua --shdict "edgeweir_stats 4m" --shdict "edgeweir_topstats 4m" --shdict "edgeweir_logs 1m" /t/waf.lua && \
		resty -I /lua --shdict "edgeweir_challenge 4m" /t/challenge.lua && \
		resty -I /lua --shdict "edgeweir_cc 8m" --shdict "edgeweir_bans 4m" /t/cc.lua && \
		resty -I /lua --shdict "edgeweir_rate_61 256k" --shdict "edgeweir_rate_62 256k" --shdict "edgeweir_policy_logs 1m" /t/ratelimit.lua && \
		resty -I /lua --shdict "edgeweir_bans 4m" /t/bans.lua && resty -I /lua --shdict "edgeweir_bans 64k" /t/bans_memory.lua && \
		resty -I /lua --shdict "edgeweir_l4 1m" --shdict "edgeweir_l4_state 1m" --shdict "edgeweir_l4_stats 1m" /t/l4.lua'

.PHONY: docker
docker: ## Build the node container image (bundles IPinfo Lite when IPINFO_TOKEN is set)
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		--secret id=ipinfo_token,env=IPINFO_TOKEN $(if $(IPINFO_TOKEN),--build-arg IPINFO_DATE=$$(date -u +%F)) -t $(IMAGE) .

.PHONY: openresty-packages
openresty-packages: ## Build the edgeweir-openresty(-modsecurity) deb/rpm packages and their SBOM for ARCH into out/openresty
	@case "$(ARCH)" in amd64|arm64) ;; *) echo "ARCH must be amd64 or arm64" >&2; exit 1 ;; esac
	rm -rf $(OPENRESTY_OUT)/.$(ARCH)
	$(OPENRESTY_BUILD) --target packages --output type=local,dest=$(OPENRESTY_OUT)/.$(ARCH)/packages .
	$(OPENRESTY_BUILD) --target tree --output type=local,dest=$(OPENRESTY_OUT)/.$(ARCH)/tree .
	mv $(OPENRESTY_OUT)/.$(ARCH)/packages/*.deb $(OPENRESTY_OUT)/.$(ARCH)/packages/*.rpm $(OPENRESTY_OUT)/
	syft scan dir:$(OPENRESTY_OUT)/.$(ARCH)/tree/tree --select-catalogers +sbom-cataloger --source-name edgeweir-openresty \
		--source-version $(OPENRESTY_VERSION)-$(OPENRESTY_RELEASE) \
		-o spdx-json=$(OPENRESTY_OUT)/edgeweir-openresty_$(OPENRESTY_VERSION)-$(OPENRESTY_RELEASE)_$(ARCH).sbom.json
	cd $(OPENRESTY_OUT) && ls -1 *_$(ARCH).* *.$(if $(filter arm64,$(ARCH)),aarch64,x86_64).rpm

.PHONY: e2e
e2e: ## Run the container smoke test (fake console + node + origin)
	./test/e2e/run.sh

.PHONY: release-check
release-check: ## Validate the goreleaser configuration
	goreleaser check

.PHONY: snapshot
snapshot: ## Build release artifacts locally without publishing (unsigned)
	goreleaser release --snapshot --clean

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist coverage.out
