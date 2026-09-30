# Edgeweir Node

[简体中文](README.md) | English

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

The edge node of [Edgeweir](https://github.com/marvinli001/edgeweir). A Go agent handles enrollment, configuration sync, tasks and signed upgrades; an OpenResty (Lua) data plane handles routing, caching, origin requests and policy enforcement.

## Relationship to the console

| Repository | Contents |
| --- | --- |
| [marvinli001/edgeweir](https://github.com/marvinli001/edgeweir) | Console (control plane): TypeScript, one app, one image. Compiles sites and rules into the engine-agnostic `NodeConfig` IR; runs the internal CA and the node channel (default `:8443`). |
| **marvinli001/edgeweir-node** (this repo) | Node: Go agent `edgeweir-node` + OpenResty (Lua). |

The only contract between the two is the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService`, `NodeConfig`). This repository generates its Go code with buf from a git tag of that directory (currently `proto/v0.10.0`) and never copies `.proto` files.

## Features

| Area | Capabilities |
| --- | --- |
| HTTPS and protocols | SNI HTTPS, HTTP/2, HTTP/3, TLS policy, HSTS, Gzip; hot certificate rotation |
| Access policy | IP / GeoIP lists, phased rules, WAF, rate limits, request / response transforms, all hot-updated; dynamic bans take effect within seconds without a revision, platform bans can also be dropped in the kernel with nftables; GeoIP reads local MMDBs and sends no client IPs to third parties; release images bundle IPinfo Lite (country, ASN) |
| Cache and origins | `Host` routing, `proxy_cache`, origin-pool load balancing with passive health checks, purge and prefetch |
| Statistics and logs | Per-site per-minute traffic statistics (persisted before upload, recovered by sequence after lost acknowledgements or restarts), bounded approximate Top URL / IP, sampled access logs (off by default; no query strings, headers or bodies) |
| Configuration reliability | Validated before apply; structural changes recover on activation failure; persisted last-known-good (LKG) configuration; keeps serving LKG while the console is unreachable |
| Signed upgrades | `supervise` parent process, locally pinned release source and trust anchor, agent and Lua switched together, node-group trials with explicit promotion, automatic rollback |

## How it works

1. **Enroll**: `edgeweir-node enroll` generates an ECDSA P-256 key locally (it never leaves the node), pins the console's internal CA by the SHA-256 in the install command, and exchanges a single-use token and a CSR for a node certificate.
2. **mTLS channel**: every later RPC authenticates with the node certificate. `WatchConfig` streams revision notifications; `GetConfig` is polled about every 30 s as a fallback, with ±20 % jitter.
3. **Apply**: snapshots and diffs are checked against `content_hash` and validated. Structural changes (listeners, cache zones, resolver, the set of published site IDs, domains and protocol settings of sites with HTTPS settings) re-render `nginx.conf` and reload OpenResty after `openresty -t`; origins, cache rules, certificates and policy rules of existing sites are hot-updated through a local unix socket without a reload. An applied configuration is persisted as LKG.
4. **Serve**: the Lua data plane routes by `Host`, caches with `proxy_cache` (`X-Cache: MISS/HIT/BYPASS`), balances over origin pools with passive health checks, and answers unknown hosts with `404` and `X-Edgeweir-Error: unknown-host`. Origins may not point at special-purpose addresses (loopback, link-local / cloud metadata, private networks, ...) unless the platform administrator allows them; every upstream request carries `CDN-Loop`, and loops end with `508`.
5. **Tasks and reports**: purge and prefetch tasks, status heartbeats (applied revision, origin health), per-site per-minute traffic statistics, automatic certificate renewal.
6. **Configuration receipts**: persisted before apply and returned over mTLS. After a console database restore, only console-authenticated higher revisions can advance the publication counter.

Details: [ARCHITECTURE.md](ARCHITECTURE.md) (Chinese).

## Install

### One-line install (recommended)

The console generates an install command for each node. `install.sh` is served by the console and:

1. Downloads the release artifacts (optionally through the console's mirror) and verifies their SHA-256 and cosign signature before executing anything. `--allow-unsigned` is for development only: it skips the signature check; SHA-256 is still verified.
2. Installs OpenResty and the `edgeweir-node` package.
3. Enrolls with the pinned CA fingerprint. The one-time token is passed in the `EDGEWEIR_TOKEN` environment variable, never on a command line.
4. Starts the service.

The console never stores SSH credentials.

### Manual install (deb / rpm)

1. Install OpenResty from the [official repositories](https://openresty.org/en/linux-packages.html) and disable its own service (the agent runs OpenResty as a child process): `sudo systemctl disable --now openresty`.
2. Download `edgeweir-node_<version>_<arch>.deb` (`amd64`, `arm64`) or `edgeweir-node-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`) and `checksums.txt*` from the release page and [verify them](#verify-release-artifacts).
3. Install, enroll and start:

   ```sh
   sudo apt install ./edgeweir-node_<version>_amd64.deb   # or: sudo dnf install ./edgeweir-node-<version>-1.x86_64.rpm
   # the token file keeps the one-time token out of the process list
   sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
   sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
   sudo rm /root/edgeweir-token
   sudo systemctl enable --now edgeweir-node
   ```

Package contents: `/usr/bin/edgeweir-node`, the Lua modules in `/usr/share/edgeweir-node/lua`, the systemd unit and `/etc/default/edgeweir-node`; creates the unprivileged `edgeweir` user and the state and cache directories it owns.

Kernel bans (platform bans dropped by nftables) need `nftables` and `CAP_NET_ADMIN`, which the default unit does not grant. To enable them add `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
```

and run `sudo systemctl daemon-reload && sudo systemctl restart edgeweir-node`. Without it bans are enforced at L7 only (`403`).

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<version>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # paste the one-time token
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

The container starts OpenResty immediately (every host answers `404 unknown-host`) and follows the console once enrolled. It runs as uid 10001 and keeps its identity and LKG configuration in the `/var/lib/edgeweir-node` volume. Kernel bans need an image built with `docker build --build-arg NFT_CAPABILITY=true` and a container started with `--cap-add NET_ADMIN`; the default image adds no privilege and enforces bans at L7 only.

Release images contain `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb`, the [IPinfo Lite](https://ipinfo.io/lite) database downloaded at build time (CC BY-SA 4.0, IP address data is powered by [IPinfo](https://ipinfo.io); the `NOTICE` next to it records the download time and sha256). It answers `ip.geoip.country` and `ip.geoip.asnum` locally, with no runtime download. For newer data, pull a newer image, or mount a separately downloaded copy and set `EDGEWEIR_GEOIP_IPINFO`. Packages and archives do not bundle the database; point `EDGEWEIR_GEOIP_IPINFO` at a downloaded file. Subdivisions need a City MMDB (`EDGEWEIR_GEOIP_CITY`).

## Command line

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...   # --token TOKEN also works but shows in ps
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...   # same flags as run; entry point of the systemd unit and the image
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # ban status of the data plane (JSON); --list adds up to 1000 bans
edgeweir-node version
```

- Every flag can also be set as an environment variable `EDGEWEIR_<FLAG>` (e.g. `--state-dir` → `EDGEWEIR_STATE_DIR`, `--token` → `EDGEWEIR_TOKEN`, `--token-file` → `EDGEWEIR_TOKEN_FILE`); command-line flags take precedence.
- `run` polls the state directory every 2 s until the node is enrolled, so `enroll` may run after `run` has started.
- `supervise` adds signed upgrades, trials and rollback on top of `run`.

| `enroll` flag | Default | Purpose |
| --- | --- | --- |
| `--server` | required | Console node-channel URL, e.g. `https://console.example.com:8443` |
| `--ca-sha256` | required | SHA-256 of the console's internal CA certificate (DER, hex) from the install command |
| `--token-file` | none | Read the one-time token from this file (surrounding whitespace ignored) |
| `--token` | none | The one-time token; visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory for the node identity |
| `--force` | off | Replace an existing identity (re-enroll) |
| `--timeout` | `30s` | Enrollment RPC timeout |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `text` | `text` or `json` |

| `run` flag | Default | Purpose |
| --- | --- | --- |
| `--manage-nginx` | off | Run OpenResty as a supervised child process (set by the container and the systemd unit) |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory (identity, LKG configuration) |
| `--nginx-bin` | `openresty` | OpenResty binary |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix directory |
| `--nginx-user` | none | User for nginx workers when the agent runs as root (running the agent unprivileged is preferred) |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | Directory containing `edgeweir/*.lua` |
| `--cache-dir` | `/var/cache/edgeweir-node` | Parent directory of the proxy cache zones |
| `--control-socket` | `/run/edgeweir-node/control.sock` | Unix socket of the data-plane control API |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | Unix socket of the internal origin layer |
| `--origin-socket-noverify` | `origin-noverify.sock` next to the origin socket | Unix socket of the origin layer without TLS verification |
| `--edge-socket` | `edge.sock` next to the control socket | Local edge listener for prefetches when every listener uses the PROXY protocol |
| `--trusted-ca` | system bundle | CA bundle for verifying HTTPS origins |
| `--resolv-conf` | `/etc/resolv.conf` | Source of the nginx resolvers |
| `--resolver` | none | Comma-separated resolver addresses (overrides `--resolv-conf`) |
| `--resolver-ipv6` | `auto` | Resolve AAAA records for origins: `auto` (when the host has a global IPv6 address), `on` or `off` |
| `--listen-ipv6` | `auto` | Also listen on IPv6: `auto` (when the host can bind IPv6), `on` or `off` |
| `--default-port` | `80` | HTTP port served before any configuration exists |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-ipinfo` | `auto` | IPinfo Lite MMDB (country, ASN): `auto` uses `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb` when the image bundles it, `off` disables it, any other value is a path |
| `--geoip-city` | empty | Operator-provided City MMDB; empty disables it |
| `--geoip-asn` | empty | Operator-provided ASN MMDB; empty disables it |
| `--cosign-bin` | `cosign` | Local signature verifier in supervise mode |
| `--upgrade-source` | official GitHub release download base | Operator-trusted release mirror; upgrade tasks cannot change it |
| `--upgrade-public-key` | empty | Local release public key; when empty, the official GitHub OIDC identity is pinned |
| `--upgrade-allow-http` | `false` | Permit plaintext HTTP for a local test or air-gapped mirror |
| `--purge-dict-mb` | `32` | Size of the purge marker store (`lua_shared_dict edgeweir_purge`) in MiB |
| `--purge-markers-per-site` | `1000` | URL and prefix purge markers per site before they collapse into one site-level marker |
| `--prefetch-budget` | `4m` | Time limit for one pulled batch of prefetches |
| `--ban-capacity` | `100000` | Dynamic bans the data plane holds (console bans and the node's own); the oldest automatic bans make room first, manual bans that do not fit are reported |
| `--ban-dict-mb` | `32` | Size of the ban store (`lua_shared_dict edgeweir_bans`) in MiB |
| `--cc-dict-mb` | `32` | Size of the CC mitigation store (`lua_shared_dict edgeweir_cc`: counters, levels, events) in MiB |
| `--challenge-dict-mb` | `8` | Size of the challenge store (`lua_shared_dict edgeweir_challenge`: keys, captcha pool, used challenge nonces) in MiB |
| `--kernel-bans` | `auto` | Also write platform bans into nftables: `auto` (when `nft` works and `CAP_NET_ADMIN` is granted) or `off` |
| `--nft-bin` | `nft` | nftables binary for kernel bans |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `text` | `text` or `json` |

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | State (0700): `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG, 0700, files 0600), `credentials.json` (S3 origin keys in plain text, 0600), `purge.json` (purge markers, 0600), `bans.json` (dynamic bans and their sequence, 0600), `nginx/` (prefix, rendered `nginx.conf`) |
| `/var/cache/edgeweir-node` | Proxy cache zones |
| `/run/edgeweir-node/control.sock` | Local control API of the Lua data plane (unix socket only) |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | Local edge listener and internal origin layers |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `/usr/share/edgeweir-node/geoip` | Bundled IPinfo Lite database and its `NOTICE` (container image) |
| `:80` | HTTP listener before any configuration; afterwards the listeners in the configuration |

## Build and test

Requirements: Go 1.27.1, Docker; buf, goreleaser and syft for release work.

```sh
make build         # static binary in bin/
make vet test      # go vet ./... && go test ./...
make test-race     # tests with the race detector
make lua-test      # Lua unit tests with resty in the OpenResty image
make docker        # docker build -t edgeweir-node:dev .; with IPINFO_TOKEN set, downloads and bundles IPinfo Lite via a BuildKit secret, otherwise the image has no GeoIP data
make e2e           # container smoke test: fake console + node + whoami origins
make proto-check   # regenerate from the proto git tag and fail on drift
make snapshot      # goreleaser release --snapshot --clean (unsigned)
```

`make e2e` publishes host ports on 127.0.0.1: 28080 (node), 28081 (PROXY protocol listener) and 28090 (fake console helper) by default. `COMPOSE_PROJECT_NAME` separates only containers, networks and volumes; to run alongside another stack, also choose free ports with `E2E_NODE_PORT`, `E2E_PP_PORT` and `E2E_HELPER_PORT`:

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

Proto regeneration flow and conventions: [CONTRIBUTING.md](CONTRIBUTING.md) (Chinese).

## Verify release artifacts

Releases are built in GitHub Actions from the tagged source and are reproducible (`-trimpath`, timestamps from the commit); the container image also carries the IPinfo Lite data of its build day, so a rebuild carries different data, and the sha256 in `/usr/share/edgeweir-node/geoip/NOTICE` identifies the copy. `checksums.txt` covers every archive, package and SBOM and is signed with cosign keyless; each artifact also carries a SLSA build provenance attestation.

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/marvinli001/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<version>_linux_amd64.tar.gz --repo marvinli001/edgeweir-node
```

## Known limitations

- The stock OpenResty engine does not include Brotli or Zstd.
- Certificate materials live in `certificates.json` (0600) and are readable by host administrators.
- The V2 statistics RPC does not fall back to an older console; upgrade the console and nodes together.
- Each published site reserves a fixed 256 KiB rate-limit counter partition; a cluster supports up to 512 published sites, and adding a site does not resize existing partitions. See [rate-limit storage](docs/rate-limit-storage.md).
- Self-update covers the agent and Lua only. The supervisor, cosign and OpenResty are upgraded through system packages or the image; a system package or image takes precedence over an older self-updated bundle in the state volume.

## Security

- No vendor phone-home, no license checks, no telemetry.
- The control channel connects only to the console the node enrolled with; the data plane connects to configured origins and, when OCSP checks are enabled, to certificate OCSP responders.
- Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/marvinli001/edgeweir-node/security/advisories/new); see [SECURITY.md](SECURITY.md).

## Documentation

Documents other than the READMEs are in Chinese.

| Document | Contents |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Node architecture |
| [SECURITY.md](SECURITY.md) | Security model and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development conventions and proto generation |
| [HTTPS and certificates](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/https.md) | Certificates, protocols and TLS policy |
| [Rules](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/rules.md) | Rules, IP lists and GeoIP |
| [Access logs](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/access-logs.md) | Access-log collection and storage |
| [Node upgrades](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/node-upgrades.md) | Signed upgrades, trials and rollback |

## License

[AGPL-3.0-only](LICENSE); commercial use is permitted subject to the license.

Nodes and the console's organizations, members and isolation are part of the open-source core; customer portals, plans and billing, finance and reselling belong to a separate commercial product. Node operation does not depend on an official commercial license. See [LICENSING.md](LICENSING.md).

The bundled GeoIP data is [IPinfo Lite](https://ipinfo.io/lite) under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/): IP address data is powered by [IPinfo](https://ipinfo.io).
