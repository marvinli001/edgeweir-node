# Edgeweir Node

English | [简体中文](README.zh-CN.md)

`edgeweir-node` is the edge node of [Edgeweir](https://edgeweir.dev), an open-source, self-hosted CDN / WAF / edge traffic platform. A node is a small Go agent that supervises an OpenResty data plane. It enrolls with an Edgeweir console, receives its configuration over mutually authenticated TLS, and serves and caches traffic for the sites of its cluster.

> **Why "weir"?** Edgeweir is named after a weir. Around 256 BC, Li Bing built the Dujiangyan irrigation system on the Min River. One of its parts, the Feisha ("flying sand") Weir, sits at the edge of the inner channel: in normal times it lets water flow on through the Bottle-Neck Channel to irrigate the Chengdu Plain; in floods, the river bend flings sand and excess water over the weir back into the outer channel. Edgeweir aims to do the same at the network edge: let good traffic through, shed attacks, and steer the flow.

## Relationship to the console

| Repository | What it is |
| --- | --- |
| [edgeweir/edgeweir](https://github.com/edgeweir/edgeweir) | The console (control plane): TypeScript, one app, one image. Compiles sites and rules into the engine-agnostic `NodeConfig` IR, runs the internal CA and the node channel on `:8443`. |
| **edgeweir/edgeweir-node** (this repo) | The node: Go agent `edgeweir-node` + OpenResty (Lua). |

The only contract between the two is the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService` and `NodeConfig`). This repository generates its Go code from a git tag of that directory (currently `proto/v0.2.1`) and never copies `.proto` files.

## How it works

1. **Enroll**: `edgeweir-node enroll` generates an ECDSA P-256 key locally (it never leaves the node), pins the console's internal CA by the SHA-256 in the install command, and exchanges a single-use token and a CSR for a node certificate.
2. **mTLS channel**: every later RPC uses the node certificate. `WatchConfig` streams revision notifications; `GetConfig` is also polled every 30 s as a fallback.
3. **Apply**: snapshots and diffs are verified against the `content_hash`, validated, and persisted as the last-known-good (LKG) configuration. Only structural changes (listeners, cache zones, resolver) re-render `nginx.conf` and reload OpenResty after `openresty -t`; sites, origins and cache rules are hot-updated through a local unix socket.
4. **Serve**: the Lua data plane routes by `Host`, caches with `proxy_cache` (responses carry `X-Cache: MISS/HIT`), and answers unknown hosts with `404` and `X-Edgeweir-Error: unknown-host`.
5. **Report**: status heartbeats with the applied revision, per-site per-minute traffic stats, and automatic certificate renewal.

If the console is unreachable the node keeps serving its LKG configuration. See [ARCHITECTURE.md](ARCHITECTURE.md) (Chinese) for the details.

## Install

### One-line install (recommended)

The console shows an install command for each node:

```sh
curl -fsSL https://<console>/install.sh | sudo bash -s -- --token <one-time-token>
```

`install.sh` is served by your own console. Before executing anything it downloads the release artifacts (optionally mirrored by the console, useful where GitHub is slow) and verifies their SHA-256 **and** cosign signature; it then installs OpenResty and the `edgeweir-node` package, enrolls the node with the pinned CA fingerprint and starts the service. Installing over SSH from the console is an optional one-shot convenience: the credentials are used once and never stored.

### Manual install (deb / rpm)

1. Install OpenResty from the [official repositories](https://openresty.org/en/linux-packages.html) and disable its own service (the agent runs OpenResty as a child process): `sudo systemctl disable --now openresty`.
2. Download `edgeweir-node_<version>_linux_<arch>.deb` (or `.rpm`) and `checksums.txt*` from the release page and [verify them](#verify-release-artifacts).
3. Install, enroll and start:

   ```sh
   sudo apt install ./edgeweir-node_<version>_linux_amd64.deb   # or: sudo dnf install ./edgeweir-node-<version>.x86_64.rpm
   sudo edgeweir-node enroll --server https://console.example.com:8443 --token <token> --ca-sha256 <sha256>
   sudo systemctl enable --now edgeweir-node
   ```

The package installs `/usr/bin/edgeweir-node`, the Lua modules in `/usr/share/edgeweir-node/lua`, the systemd unit and `/etc/default/edgeweir-node`, and creates the unprivileged `edgeweir` user.

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/edgeweir/edgeweir-node:<version>
docker exec edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --token <token> --ca-sha256 <sha256>
```

The container starts OpenResty immediately (every host answers `404 unknown-host`), waits for the enrollment, and then follows the console. It runs as uid 10001 and keeps its identity and LKG configuration in the `/var/lib/edgeweir-node` volume.

## Command line

```text
edgeweir-node enroll --server URL --token TOKEN --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80] ...
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node version
```

Every flag can also be set as an environment variable `EDGEWEIR_<FLAG>` (for example `--state-dir` → `EDGEWEIR_STATE_DIR`, `--token` → `EDGEWEIR_TOKEN`); command-line flags win. `run` waits (polling every 2 s) until the node is enrolled, so `enroll` can be run while `run` is already running.

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | state: `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG), `nginx/` (prefix, rendered `nginx.conf`) |
| `/var/cache/edgeweir-node` | proxy cache zones |
| `/run/edgeweir-node/control.sock` | local control API of the Lua data plane (unix socket only) |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `:80` | HTTP listener before any configuration; afterwards the listeners in the config |

## Build and test

Requirements: Go 1.27, Docker, and for release work buf, goreleaser and syft.

```sh
make build         # static binary in bin/
make vet test      # go vet ./... && go test ./...
make test-race     # tests with the race detector
make lua-test      # Lua unit tests with resty in the OpenResty image
make docker        # docker build -t edgeweir-node:dev .
make e2e           # container smoke test: fake console + node + whoami origin
make proto-check   # regenerate from the proto git tag and fail on drift
make snapshot      # goreleaser release --snapshot --clean (unsigned)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the proto regeneration flow and conventions.

## Verify release artifacts

Releases are built in GitHub Actions from the tagged source (reproducible: `-trimpath`, timestamps from the commit). `checksums.txt` covers every archive, package and SBOM and is signed with cosign keyless; each artifact also has a SLSA build provenance attestation.

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/edgeweir/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<version>_linux_amd64.tar.gz --repo edgeweir/edgeweir-node
```

## Security

No phone-home, no license checks, no telemetry. The node talks only to the console you enrolled it with. Report vulnerabilities to security@edgeweir.dev; see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE). Roadmap: [ROADMAP.md](ROADMAP.md).
