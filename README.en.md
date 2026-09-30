# Edgeweir Node

[简体中文](README.md) | English

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Edge node for [Edgeweir](https://github.com/marvinli001/edgeweir): the `edgeweir-node` Go agent and an OpenResty (Lua) data plane.

## Features

| Area | Capabilities |
| --- | --- |
| HTTPS and protocols | SNI HTTPS, HTTP/2, HTTP/3, TLS policy, HSTS, Gzip, hot certificate rotation |
| Access policy | IP / GeoIP lists, phased rules, WAF, rate limits, request / response transforms, all hot-updated; dynamic bans within seconds, platform bans optionally dropped in the kernel with nftables |
| Challenges and CC mitigation | Four challenge levels (cookie redirect, JS, proof of work, image captcha), signed passes, node-local tiered CC mitigation, JA4 fingerprints |
| Cache and origins | `Host` routing, `proxy_cache`, origin-pool load balancing, passive health checks, purge, prefetch |
| Statistics and logs | Per-site per-minute traffic statistics (persisted, resumed by sequence), Top URL / IP, sampled access logs (off by default) |
| GeoIP | Local MMDB lookups; release images bundle IPinfo Lite (country, ASN) |
| Configuration reliability | Validated apply, rollback on activation failure, persisted last-known-good (LKG) configuration; serves LKG while the console is unreachable |
| Signed upgrades | `supervise` parent process, locally pinned release source and trust anchor, node-group trials, automatic rollback |

## Architecture

| Component | Role |
| --- | --- |
| `edgeweir-node` agent | Enrollment, mTLS channel (`WatchConfig` push, `GetConfig` fallback poll about every 30 s), configuration validation and apply, tasks, heartbeats and statistics, signed upgrades |
| OpenResty data plane | Routing, caching, origin requests, policy enforcement; hot updates for sites, origins, certificates and rules over a local unix socket |
| [edgeweir](https://github.com/marvinli001/edgeweir) console | Control plane: internal CA, node channel (default `:8443`), `NodeConfig` compilation and delivery |

- Contract: the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService`, `NodeConfig`), generated with buf from git tag `proto/v0.10.1`.
- Structural changes (listeners, cache zones, resolver, the set of sites, domains and protocol settings of HTTPS sites) re-render `nginx.conf` and reload after `openresty -t`; all other changes are hot-updated without a reload.

| Data-plane behavior | Response |
| --- | --- |
| Cache status | `X-Cache: MISS` / `HIT` / `BYPASS` |
| Unknown host | `404`, `X-Edgeweir-Error: unknown-host` |
| Forwarding loop | Upstream requests carry `CDN-Loop`; loops end with `508` |
| Origin addresses | Special-purpose ranges (loopback, link-local / cloud metadata, private networks, ...) rejected unless allowed by the platform |

Details: [ARCHITECTURE.md](ARCHITECTURE.md) (Chinese).

## Install

### Console install command (recommended)

The console generates an install command per node. `install.sh` verifies the SHA-256 and cosign signature of the release artifacts, installs OpenResty and `edgeweir-node`, enrolls with the pinned CA fingerprint and starts the service; the one-time token is passed in `EDGEWEIR_TOKEN`. `--allow-unsigned` is for development only: it skips the signature check and keeps the SHA-256 check.

### deb / rpm

Prerequisite: OpenResty from the [official repositories](https://openresty.org/en/linux-packages.html) with its own service disabled (`sudo systemctl disable --now openresty`); the agent runs OpenResty as a child process.

Artifacts: `edgeweir-node_<version>_<arch>.deb` (`amd64`, `arm64`), `edgeweir-node-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`), `checksums.txt*`. [Verify](#verify-release-artifacts) before installing.

```sh
sudo apt install ./edgeweir-node_<version>_amd64.deb   # or sudo dnf install ./edgeweir-node-<version>-1.x86_64.rpm
sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
sudo rm /root/edgeweir-token
sudo systemctl enable --now edgeweir-node
```

Package contents: `/usr/bin/edgeweir-node`, `/usr/share/edgeweir-node/lua`, the systemd unit, `/etc/default/edgeweir-node`; creates the unprivileged `edgeweir` user and its state and cache directories.

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<version>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

The container runs as uid 10001; before enrollment every host answers `404 unknown-host`. Identity and LKG configuration live in the `/var/lib/edgeweir-node` volume.

### Kernel bans

Platform bans dropped by nftables require `nftables` and `CAP_NET_ADMIN`. Neither is granted by default; bans are then enforced at L7 (`403`).

- systemd: add `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`, then run `sudo systemctl daemon-reload && sudo systemctl restart edgeweir-node`.

  ```ini
  [Service]
  AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  ```

- Docker: build the image with `docker build --build-arg NFT_CAPABILITY=true` and start the container with `--cap-add NET_ADMIN`.

### GeoIP

| Database | Source | Flag |
| --- | --- | --- |
| IPinfo Lite (country, ASN) | Bundled in release images at `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb` (downloaded at build time; the adjacent `NOTICE` records download time and sha256); not bundled in packages or archives | `--geoip-ipinfo` |
| City (subdivisions) | Operator-provided | `--geoip-city` |
| ASN | Operator-provided | `--geoip-asn` |

Lookups are local: no runtime download, no client IPs sent to third parties. To update, pull a newer image or mount a newer copy and set `EDGEWEIR_GEOIP_IPINFO`.

## Command line

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...            # same flags as run; systemd unit and image entry point
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # ban status (JSON); --list adds up to 1000 bans
edgeweir-node security [--control-socket PATH]        # challenge keys, captcha pool, per-site CC levels (JSON)
edgeweir-node version
```

- Every flag can be set as `EDGEWEIR_<FLAG>` (e.g. `--state-dir` → `EDGEWEIR_STATE_DIR`); command-line flags take precedence.
- `run` polls the state directory every 2 s until enrolled and may start before `enroll`.
- `supervise` adds signed upgrades, trials and rollback on top of `run`.

| `enroll` flag | Default | Description |
| --- | --- | --- |
| `--server` | required | Console node-channel URL, e.g. `https://console.example.com:8443` |
| `--ca-sha256` | required | SHA-256 of the console's internal CA certificate (DER, hex) |
| `--token-file` | none | One-time token file (surrounding whitespace ignored) |
| `--token` | none | One-time token; visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory |
| `--force` | off | Replace an existing identity (re-enroll) |
| `--timeout` | `30s` | Enrollment RPC timeout |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| `run` flag | Default | Description |
| --- | --- | --- |
| `--manage-nginx` | off | Run OpenResty as a supervised child process (set by the container and the systemd unit) |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory (identity, LKG configuration) |
| `--nginx-bin` | `openresty` | OpenResty binary |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix directory |
| `--nginx-user` | none | nginx worker user when the agent runs as root |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | Directory containing `edgeweir/*.lua` |
| `--cache-dir` | `/var/cache/edgeweir-node` | Parent directory of the cache zones |
| `--control-socket` | `/run/edgeweir-node/control.sock` | Data-plane control API socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | Internal origin layer socket |
| `--origin-socket-noverify` | `origin-noverify.sock` next to the origin socket | Origin layer socket without TLS verification |
| `--edge-socket` | `edge.sock` next to the control socket | Local edge listener for prefetches when every listener uses the PROXY protocol |
| `--trusted-ca` | system bundle | CA bundle for HTTPS origins |
| `--resolv-conf` | `/etc/resolv.conf` | Source of the nginx resolvers |
| `--resolver` | none | Comma-separated resolver addresses; overrides `--resolv-conf` |
| `--resolver-ipv6` | `auto` | Resolve AAAA for origins: `auto` (host has a global IPv6 address), `on`, `off` |
| `--listen-ipv6` | `auto` | Listen on IPv6: `auto` (host can bind IPv6), `on`, `off` |
| `--default-port` | `80` | HTTP port before any configuration |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-ipinfo` | `auto` | IPinfo Lite MMDB: `auto` (bundled copy if present), `off`, or a path |
| `--geoip-city` | empty | City MMDB path |
| `--geoip-asn` | empty | ASN MMDB path |
| `--cosign-bin` | `cosign` | Signature verifier in supervise mode |
| `--upgrade-source` | official GitHub release download base | Release mirror; upgrade tasks cannot change it |
| `--upgrade-public-key` | empty | Release public key; empty pins the official GitHub OIDC identity |
| `--upgrade-allow-http` | `false` | Permit a plaintext HTTP mirror (local test, air-gapped) |
| `--purge-dict-mb` | `32` | Purge marker store (`lua_shared_dict edgeweir_purge`), MiB |
| `--purge-markers-per-site` | `1000` | URL and prefix markers per site before collapsing into a site-level marker |
| `--prefetch-budget` | `4m` | Time limit per prefetch batch |
| `--ban-capacity` | `100000` | Maximum dynamic bans; oldest automatic bans are evicted first |
| `--ban-dict-mb` | `32` | Ban store (`lua_shared_dict edgeweir_bans`), MiB |
| `--cc-dict-mb` | `32` | CC mitigation store (`lua_shared_dict edgeweir_cc`), MiB |
| `--challenge-dict-mb` | `8` | Challenge store (`lua_shared_dict edgeweir_challenge`), MiB |
| `--kernel-bans` | `auto` | Write platform bans into nftables: `auto` (`nft` works and `CAP_NET_ADMIN` granted), `off` |
| `--nft-bin` | `nft` | nftables binary |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | State (0700): `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG, 0700, files 0600), `credentials.json` (S3 origin keys in plain text, 0600), `purge.json` (purge markers, 0600), `bans.json` (dynamic bans and sequence, 0600), `challenge-keys.json` (challenge pass keys, 0600), `nginx/` (prefix, `nginx.conf`) |
| `/var/cache/edgeweir-node` | Cache zones |
| `/run/edgeweir-node/control.sock` | Data-plane control API (unix socket only) |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | Local edge listener and internal origin layers |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `/usr/share/edgeweir-node/geoip` | IPinfo Lite database and `NOTICE` (container image) |
| `:80` | HTTP listener before any configuration; afterwards as configured |

## Build and test

Requirements: Go 1.27.1, Docker; buf, goreleaser and syft for releases.

```sh
make build         # static binary in bin/
make vet test      # go vet ./... && go test ./...
make test-race     # race detector
make lua-test      # Lua unit tests (resty in the OpenResty image)
make docker        # image; bundles IPinfo Lite via a BuildKit secret when IPINFO_TOKEN is set
make e2e           # container smoke test: fake console + node + whoami origins
make proto-check   # regenerate from the proto tag and check for drift
make snapshot      # local goreleaser snapshot (unsigned)
```

`make e2e` binds 127.0.0.1 ports 28080, 28081 and 28090 by default. To run alongside another compose project, set both the project name and the ports:

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

Conventions and proto generation: [CONTRIBUTING.md](CONTRIBUTING.md) (Chinese).

## Verify release artifacts

Releases are built in GitHub Actions from the tagged source and are reproducible (`-trimpath`, commit timestamps); the IPinfo Lite copy in a container image is identified by the sha256 in its `NOTICE`. `checksums.txt` covers every archive, package and SBOM and is signed with cosign keyless; each artifact carries a SLSA build provenance attestation.

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

- The OpenResty engine does not include Brotli or Zstd.
- Certificate materials live in `certificates.json` (0600), readable by host administrators.
- The V2 statistics RPC is incompatible with older consoles; upgrade the console and nodes together.
- Each published site reserves a fixed 256 KiB rate-limit counter partition; up to 512 published sites per cluster. See [rate-limit storage](docs/rate-limit-storage.md).
- Self-update covers the agent and Lua only; the supervisor, cosign and OpenResty are upgraded with system packages or the image, which take precedence over an older self-updated bundle in the state volume.

## Security

- The node key (ECDSA P-256) is generated locally and never leaves the node; enrollment pins the console CA by `--ca-sha256`.
- All RPCs after enrollment use mTLS; the data-plane control API listens on a unix socket only.
- Configuration receipts are persisted before apply; after a console database restore, only console-authenticated higher revisions advance the publication counter.
- Outbound connections: the control channel reaches only the enrolling console; the data plane reaches configured origins and, with OCSP checks enabled, OCSP responders.
- The console never stores SSH credentials.
- No vendor phone-home, no license checks, no telemetry.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/marvinli001/edgeweir-node/security/advisories/new); see [SECURITY.md](SECURITY.md).

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

[AGPL-3.0-only](LICENSE); commercial use is permitted under its terms. Open-source core and commercial product boundaries: [LICENSING.md](LICENSING.md).

Bundled GeoIP data: [IPinfo Lite](https://ipinfo.io/lite), [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). IP address data is powered by [IPinfo](https://ipinfo.io).
