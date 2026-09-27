# Edgeweir Node

English | [简体中文](README.zh-CN.md)

`edgeweir-node` is the edge node of [Edgeweir](https://github.com/marvinli001/edgeweir), an open-source, self-hosted CDN / WAF / edge traffic platform. A node is a small Go agent that supervises an OpenResty data plane. It enrolls with an Edgeweir console, receives its configuration over mutually authenticated TLS, and serves and caches traffic for the sites of its cluster.

> **Why "weir"?** Edgeweir is named after a weir. Around 256 BC, Li Bing built the Dujiangyan irrigation system on the Min River. One of its parts, the Feisha ("flying sand") Weir, sits at the edge of the inner channel: in normal times it lets water flow on through the Bottle-Neck Channel to irrigate the Chengdu Plain; in floods, the river bend flings sand and excess water over the weir back into the outer channel. Edgeweir aims to do the same at the network edge: let good traffic through, shed attacks, and steer the flow.

## Relationship to the console

| Repository | What it is |
| --- | --- |
| [marvinli001/edgeweir](https://github.com/marvinli001/edgeweir) | The console (control plane): TypeScript, one app, one image. Compiles sites and rules into the engine-agnostic `NodeConfig` IR, runs the internal CA and the node channel on `:8443`. |
| **marvinli001/edgeweir-node** (this repo) | The node: Go agent `edgeweir-node` + OpenResty (Lua). |

The only contract between the two is the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService` and `NodeConfig`). This repository generates its Go code from a git tag of that directory (currently `proto/v0.7.0`) and never copies `.proto` files.

## Status

M3 adds SNI HTTPS, HTTP/2, HTTP/3, TLS policy, HSTS and Gzip. Certificate rotation is hot; structural policy changes reload only after validation and recover on activation failure. Brotli and Zstd are unavailable in the stock engine. Node certificate materials live in `certificates.json` with mode 0600; host administrators can read them. See the [HTTPS guide](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/https.md).

M4 adds IP/GeoIP lists, phased rules, WAF, rate limits and request/response transforms through hot updates. GeoIP reads local MMDBs without sending client IPs to a third party: release images bundle the IPinfo Lite database (country and ASN), downloaded when the image is built, and operator-provided City / ASN MMDBs add subdivisions. See the [rule guide](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/rules.md).

M5 persists sequenced statistics before upload, recovers from lost acknowledgements and restarts, and reports bounded approximate Top URL/IP counters. The V2 statistics RPC prevents unsafe fallback to an older console. Update the console and nodes together.

There is no official binary release yet. Installation instructions below describe the release workflow; build from source for current evaluation. This is an experimental MVP.

M6 runs a stable `supervise` parent with locally pinned release trust. It rejects bad signatures and unsafe archives, switches the agent and Lua together, and commits only after healthy configuration receipts. A failed candidate or interrupted trial restores the previous program and LKG. System-package/image updates take precedence over an older self-updated bundle; the guardian, cosign and OpenResty are maintained through that full-install path.

Opaque configuration receipts are persisted before apply and returned over mTLS. After a database restore, only console-authenticated higher revisions can advance the control plane's counter. A node cannot invent an enormous revision to block future publication.

## How it works

1. **Enroll**: `edgeweir-node enroll` generates an ECDSA P-256 key locally (it never leaves the node), pins the console's internal CA by the SHA-256 in the install command, and exchanges a single-use token and a CSR for a node certificate.
2. **mTLS channel**: every later RPC uses the node certificate. `WatchConfig` streams revision notifications; `GetConfig` is also polled about every 30 s (with ±20 % jitter, so that nodes do not poll in lockstep) as a fallback.
3. **Apply**: snapshots and diffs are verified against the `content_hash` and validated. Structural changes (listeners, cache zones, resolver and the set of published site IDs) re-render `nginx.conf` and reload OpenResty after `openresty -t`; ordinary existing-site origins, cache rules and policy rules are hot-updated through a local unix socket. A configuration that applied is persisted as the last-known-good (LKG) configuration.
4. **Serve**: the Lua data plane routes by `Host`, caches with `proxy_cache` (responses carry `X-Cache: MISS/HIT/BYPASS`), balances over origin pools with passive health checks, and answers unknown hosts with `404` and `X-Edgeweir-Error: unknown-host`. Origins may not point at special-purpose addresses (loopback, link-local/cloud metadata, private networks, ...) unless the platform administrator allows them, and every upstream request carries `CDN-Loop`, so loops end with `508`.
5. **Tasks and reports**: purge and prefetch tasks, status heartbeats with the applied revision and origin health, per-site per-minute traffic stats, and automatic certificate renewal.

If the console is unreachable the node keeps serving its LKG configuration. See [ARCHITECTURE.md](ARCHITECTURE.md) (Chinese) for the details.

## Install

### One-line install (recommended)

The console shows an install command for each node. `install.sh` is served by your own console. Before executing anything it downloads the release artifacts (optionally mirrored by the console, useful where GitHub is slow) and verifies their SHA-256 **and** cosign signature (the only exception is `--allow-unsigned`, meant for development, which skips the signature check but still verifies the SHA-256); it then installs OpenResty and the `edgeweir-node` package, enrolls the node with the pinned CA fingerprint (the one-time token is handed over in the `EDGEWEIR_TOKEN` environment variable, never on a command line) and starts the service. The console never stores SSH credentials.

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

The package installs `/usr/bin/edgeweir-node`, the Lua modules in `/usr/share/edgeweir-node/lua`, the systemd unit and `/etc/default/edgeweir-node`, creates the unprivileged `edgeweir` user and the state and cache directories owned by it.

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<version>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # paste the one-time token
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

The container starts OpenResty immediately (every host answers `404 unknown-host`), waits for the enrollment, and then follows the console. It runs as uid 10001 and keeps its identity and LKG configuration in the `/var/lib/edgeweir-node` volume.

Release images contain `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb`, the [IPinfo Lite](https://ipinfo.io/lite) database fetched when the image was built (IP address data is powered by [IPinfo](https://ipinfo.io), CC BY-SA 4.0; the `NOTICE` next to it records the download time and sha256). It answers `ip.geoip.country` and `ip.geoip.asnum` without any runtime download; pull a newer image for fresher data, or mount your own copy and set `EDGEWEIR_GEOIP_IPINFO`. To build an image with the data, pass an IPinfo token as a BuildKit secret: `IPINFO_TOKEN=... make docker`. Without the token the image has no bundled data and GeoIP rules stay unavailable until you provide MMDBs. Packages and archives do not bundle the database; point `EDGEWEIR_GEOIP_IPINFO` at your own download.

## Command line

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...   # --token TOKEN also works but shows in ps
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] ...
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node version
```

Every flag can also be set as an environment variable `EDGEWEIR_<FLAG>` (for example `--state-dir` → `EDGEWEIR_STATE_DIR`, `--token` → `EDGEWEIR_TOKEN`, `--token-file` → `EDGEWEIR_TOKEN_FILE`); command-line flags win. `run` waits (polling every 2 s) until the node is enrolled, so `enroll` can be run while `run` is already running.

| `enroll` flag | Default | Purpose |
| --- | --- | --- |
| `--server` | required | console node-channel URL, e.g. `https://console.example.com:8443` |
| `--ca-sha256` | required | SHA-256 of the console's internal CA certificate (DER, hex) from the install command |
| `--token-file` | none | read the one-time token from this file (surrounding whitespace is ignored) |
| `--token` | none | the one-time token itself; visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-node` | state directory for the node identity |
| `--force` | off | replace an existing identity (re-enroll) |
| `--timeout` | `30s` | enrollment RPC timeout |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `text` | `text` or `json` |

| `run` flag | Default | Purpose |
| --- | --- | --- |
| `--manage-nginx` | off | run OpenResty as a supervised child process (the container and the systemd unit set it) |
| `--state-dir` | `/var/lib/edgeweir-node` | state directory (identity, last-known-good configuration) |
| `--nginx-bin` | `openresty` | OpenResty binary |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix directory |
| `--nginx-user` | none | user for the nginx workers when the agent runs as root (better: run the agent as an unprivileged user) |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | directory containing `edgeweir/*.lua` |
| `--cache-dir` | `/var/cache/edgeweir-node` | parent directory of the proxy cache zones |
| `--control-socket` | `/run/edgeweir-node/control.sock` | unix socket of the data plane control API |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | unix socket of the internal origin layer |
| `--origin-socket-noverify` | `origin-noverify.sock` next to the origin socket | unix socket of the origin layer without TLS verification |
| `--edge-socket` | `edge.sock` next to the control socket | local edge listener for prefetches when every listener uses the PROXY protocol |
| `--trusted-ca` | system bundle | CA bundle for verifying HTTPS origins |
| `--resolv-conf` | `/etc/resolv.conf` | resolv.conf to take the nginx resolvers from |
| `--resolver` | none | comma-separated resolver addresses (overrides `--resolv-conf`) |
| `--resolver-ipv6` | `auto` | resolve AAAA records for origins: `auto` (when the host has a global IPv6 address), `on` or `off` |
| `--listen-ipv6` | `auto` | also listen on IPv6: `auto` (when the host can bind IPv6), `on` or `off` |
| `--default-port` | `80` | HTTP port served before any configuration exists |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-ipinfo` | `auto` | IPinfo Lite MMDB (country and ASN): `auto` uses `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb` when the image bundles it, `off` disables it, otherwise a path |
| `--geoip-city` | empty | Operator-provided MMDB; empty disables the capability |
| `--geoip-asn` | empty | Operator-provided MMDB; empty disables the capability |
| `--cosign-bin` | `cosign` | Local signature verifier in supervise mode |
| `--upgrade-source` | official GitHub release download base | Operator-trusted release mirror; tasks cannot change it |
| `--upgrade-public-key` | empty | Local release public key; otherwise pin official GitHub OIDC identity |
| `--upgrade-allow-http` | `false` | Explicitly permit a plaintext local test or air-gap mirror |
| `--purge-dict-mb` | `32` | size of the purge marker store (`lua_shared_dict edgeweir_purge`) in MiB |
| `--purge-markers-per-site` | `1000` | URL and prefix purge markers per site before they collapse into one site-level marker |
| `--prefetch-budget` | `4m` | time the prefetches of one pulled batch may take |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `text` | `text` or `json` |

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | state (0700): `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG, 0700, files 0600), `credentials.json` (S3 origin keys in plain text, 0600), `purge.json` (purge markers, 0600), `nginx/` (prefix, rendered `nginx.conf`) |
| `/var/cache/edgeweir-node` | proxy cache zones |
| `/run/edgeweir-node/control.sock` | local control API of the Lua data plane (unix socket only) |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | local edge listener and the internal origin layers |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `/usr/share/edgeweir-node/geoip` | bundled IPinfo Lite database and its `NOTICE` (container image) |
| `:80` | HTTP listener before any configuration; afterwards the listeners in the config |

Each published site reserves a fixed 256 KiB counter partition; a cluster supports up to 512 published sites. Other sites cannot consume that partition, and adding a site does not resize existing partitions. See [rate-limit storage](docs/rate-limit-storage.md).

## Build and test

Requirements: Go 1.27.1, Docker, and for release work buf, goreleaser and syft.

```sh
make build         # static binary in bin/
make vet test      # go vet ./... && go test ./...
make test-race     # tests with the race detector
make lua-test      # Lua unit tests with resty in the OpenResty image
make docker        # docker build -t edgeweir-node:dev . (IPINFO_TOKEN=... bundles IPinfo Lite)
make e2e           # container smoke test: fake console + node + whoami origins
make proto-check   # regenerate from the proto git tag and fail on drift
make snapshot      # goreleaser release --snapshot --clean (unsigned)
```

`make e2e` publishes host ports on 127.0.0.1, by default 28080 (node), 28081 (PROXY protocol listener) and 28090 (fake console helper). `COMPOSE_PROJECT_NAME` alone only separates the containers, networks and volumes; to run next to another stack (or a second run), also choose free ports with `E2E_NODE_PORT`, `E2E_PP_PORT` and `E2E_HELPER_PORT`:

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the proto regeneration flow and conventions.

## Verify release artifacts

Releases are built in GitHub Actions from the tagged source (reproducible: `-trimpath`, timestamps from the commit). The container image additionally bundles the IPinfo Lite database as of its build day, so a later rebuild of the image carries different data; the sha256 in `/usr/share/edgeweir-node/geoip/NOTICE` identifies the copy. `checksums.txt` covers every archive, package and SBOM and is signed with cosign keyless; each artifact also has a SLSA build provenance attestation.

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/marvinli001/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<version>_linux_amd64.tar.gz --repo marvinli001/edgeweir-node
```

## Security

No vendor phone-home or license checks. The control channel talks to your console; the data plane reaches your configured origins, and enabled OCSP checks reach certificate responders. Use [GitHub private vulnerability reporting](https://github.com/marvinli001/edgeweir-node/security/advisories/new); see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0-only](LICENSE), with commercial use permitted subject to the license. Nodes and the console's organizations, members and isolation remain open source; customer commerce portals, billing, finance and reselling are planned as a separate commercial product. Node operation does not depend on an official commercial license. See [LICENSING.md](LICENSING.md) and [ROADMAP.md](ROADMAP.md). The bundled GeoIP data is [IPinfo Lite](https://ipinfo.io/lite) under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/): IP address data is powered by [IPinfo](https://ipinfo.io).

M6 sampled access logs are available (proto/v0.7.0). Collection is off by default, excludes query strings, headers and bodies, and uses bounded private queues with sequenced acknowledgements. See the [log and storage guide](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/access-logs.md). Signed agent/Lua upgrades, canary promotion and automatic rollback are implemented. See the [upgrade guide](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/node-upgrades.md).
