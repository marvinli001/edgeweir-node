# Edgeweir Node

[简体中文](README.md) | English

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Edge node for [Edgeweir](https://github.com/marvinli001/edgeweir): the `edgeweir-node` Go agent and an OpenResty (Lua) data plane. OpenResty is edgeweir-openresty, built from pinned and verified sources with Brotli, Zstandard and optional ModSecurity with the OWASP CRS.

## Features

| Area | Capabilities |
| --- | --- |
| HTTPS and protocols | SNI HTTPS, HTTP/2, HTTP/3, TLS policy, HSTS, hot certificate rotation |
| Compression | gzip, Brotli, Zstandard; one coding per response by the q-values of `Accept-Encoding` (zstd > br > gzip at equal q, compression rules restrict and order the codings), one uncompressed object in the cache |
| Access policy | IP / GeoIP lists, phased rules (expression functions, dynamic redirects and rewrites, query edits, bulk redirects, origin rules and origin groups, per-request overrides of site settings, compression rules), WAF, rate limits, request / response transforms, all hot-updated; dynamic bans within seconds, platform bans optionally dropped in the kernel with nftables |
| OWASP CRS | Per-site managed rules (ModSecurity v3 + CRS 4.29.0): detect only / block, paranoia level, anomaly threshold, excluded rules, request body inspection limit; cache hits are inspected too, sites without CRS never pass through ModSecurity |
| Challenges and CC mitigation | Four challenge levels (cookie redirect, JS, proof of work, image captcha), signed passes, node-local tiered CC mitigation, JA4 fingerprints |
| Cache and origins | `Host` routing, `proxy_cache`, cache rules with expression conditions and browser TTLs, origin-pool load balancing, passive and active health checks, session affinity (signed cookie), purge (URL, prefix, host, site, Cache-Tag), prefetch (URLs and sitemaps, desktop and mobile variants, HTTP and HTTPS) |
| Layer-4 forwarding | TCP / UDP ports forwarded to origins: weights, backup origins, passive health checks and retries on connect failures, connect and idle timeouts, allow / block lists, per-node concurrent and new-per-second limits; PROXY protocol v1 / v2 towards origins, listeners that accept the PROXY protocol; adding or removing ports reloads without dropping open connections, everything else is hot-updated; per-minute connections, refusals, peak concurrency and bytes |
| Error pages | 403 / 429 / 502 / 503 / 504 from site templates or built-in pages (Chinese and English), optionally replacing origin errors; platform pages for unknown, disabled and suspended sites; `X-Request-Id` |
| Statistics and logs | Per-minute statistics of sites and layer-4 applications (persisted, resumed by sequence), Top URL / IP, sampled access logs (off by default) |
| Probes and host metrics | Regional probes `edgeweir-node probe` (no OpenResty) and nodes that also probe: TCP, HTTP and HTTPS checks of the targets the console names, reporting latency and loss; the edge listeners' health endpoint `/.edgeweir/health`; heartbeats carry CPU, load, memory, egress bandwidth and active connections |
| GeoIP | Local MMDB lookups; release images bundle IPinfo Lite (country, ASN) |
| Configuration reliability | Validated apply, rollback on activation failure, persisted last-known-good (LKG) configuration; serves LKG while the console is unreachable |
| Signed upgrades | `supervise` parent process, locally pinned release source and trust anchor, node-group trials, automatic rollback |

## Architecture

| Component | Role |
| --- | --- |
| `edgeweir-node` agent | Enrollment, mTLS channel (`WatchConfig` push, `GetConfig` fallback poll about every 30 s), configuration validation and apply, tasks, heartbeats (with host metrics) and statistics, signed upgrades; probes the other nodes when the console asks |
| `edgeweir-node probe` | Regional probe: checks the nodes' scheduling addresses and reports over mTLS (`ProbeService`) |
| OpenResty data plane | Routing, caching, origin requests, policy enforcement, layer-4 forwarding (stream); hot updates for sites, origins, certificates, rules and layer-4 applications over a local unix socket |
| [edgeweir](https://github.com/marvinli001/edgeweir) console | Control plane: internal CA, node channel (default `:8443`), `NodeConfig` compilation and delivery |

- Contract: the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService`, `ProbeService`, `NodeConfig`), generated with buf from git tag `proto/v0.19.0`.
- Structural changes (listeners, cache zones, resolver, the set of sites, domains, protocol and compression settings of HTTPS sites, loading the OWASP CRS and its excluded rules, ports, protocols and PROXY protocol settings of layer-4 applications) re-render `nginx.conf` and reload after `openresty -t`, the old workers serving open connections until they end; all other changes are hot-updated without a reload.

| Data-plane behavior | Response |
| --- | --- |
| Cache status | `X-Cache: MISS` / `HIT` / `BYPASS` |
| Unknown host | `404` platform or built-in page, `X-Edgeweir-Error: unknown-host` |
| Host of a disabled / suspended site | `503` platform or built-in page, `X-Edgeweir-Error: site-disabled` / `site-suspended` |
| Request id | `X-Request-Id`: the client's when valid, else generated by the node; error pages and sampled logs show the same id |
| `Cache-Tag` | Not forwarded to clients by default (sites can keep it); the node indexes cached objects by it |
| Forwarding loop | Upstream requests carry `CDN-Loop`; loops end with `508` |
| Origin addresses | Special-purpose ranges (loopback, link-local / cloud metadata, private networks, ...) rejected unless allowed by the platform |
| CRS block | `403` error page, `X-Edgeweir-Error: waf-blocked` |
| Compression | `Content-Encoding: zstd` / `br` / `gzip`, `Vary: Accept-Encoding` |
| Refused layer-4 connection | Lists or connection limits forward nothing: the TCP connection is closed, the UDP datagram dropped |
| Health endpoint | `GET /.edgeweir/health` for any host answers `200 ok` before any site logic (not cached, counted or logged); TLS answers SNI `health.edgeweir.invalid` or no SNI with the node's self-signed health certificate, and such connections reach only the health endpoint (`421` otherwise) |

Details: [ARCHITECTURE.md](ARCHITECTURE.md) (Chinese).

## Install

### Console install command (recommended)

The console generates an install command per node. `install.sh` verifies the SHA-256 and cosign signature of the release artifacts, installs `edgeweir-openresty`, `edgeweir-openresty-modsecurity` and `edgeweir-node`, enrolls with the pinned CA fingerprint and starts the service; the one-time token is passed in `EDGEWEIR_TOKEN`. `--allow-unsigned` is for development only: it skips the signature check and keeps the SHA-256 check.

### deb / rpm

Requirements: glibc 2.34 or later (RHEL / Rocky / AlmaLinux 9, Debian 12, Ubuntu 22.04 and newer), amd64 or arm64. The agent runs OpenResty as a child process; if OpenResty's own packages are installed, disable their service (`sudo systemctl disable --now openresty`).

Artifacts: `edgeweir-node_<version>_<arch>.deb` (`amd64`, `arm64`), `edgeweir-node-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`), `edgeweir-openresty_1.31.1.1-2_<arch>.deb` / `edgeweir-openresty-1.31.1.1-2.<arch>.rpm`, the `edgeweir-openresty-modsecurity` packages named alike, `checksums.txt*`. [Verify](#verify-release-artifacts) before installing.

```sh
sudo apt install ./edgeweir-openresty_1.31.1.1-2_amd64.deb ./edgeweir-openresty-modsecurity_1.31.1.1-2_amd64.deb \
  ./edgeweir-node_<version>_amd64.deb
# or sudo dnf install ./edgeweir-openresty-1.31.1.1-2.x86_64.rpm ./edgeweir-openresty-modsecurity-1.31.1.1-2.x86_64.rpm \
#      ./edgeweir-node-<version>-1.x86_64.rpm
sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
sudo rm /root/edgeweir-token
sudo systemctl enable --now edgeweir-node
```

Package contents: `edgeweir-node` installs `/usr/bin/edgeweir-node`, `/usr/share/edgeweir-node/lua`, the systemd unit and `/etc/default/edgeweir-node`, and creates the unprivileged `edgeweir` user and its state and cache directories; `edgeweir-openresty` installs `/usr/lib/edgeweir-openresty` (OpenResty, LuaJIT, Brotli, Zstandard); the optional `edgeweir-openresty-modsecurity` adds the ModSecurity module and `/usr/share/edgeweir-openresty/crs`, without which sites cannot enable the OWASP CRS on the node. Third-party licenses: `/usr/share/doc/edgeweir-openresty/NOTICE`.

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<version>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

The container runs as uid 10001; before enrollment every host answers `404 unknown-host`. Identity and LKG configuration live in the `/var/lib/edgeweir-node` volume. Layer-4 applications use ports of the cluster's port pools: publish them (e.g. `-p 9000:9000 -p 9000:9000/udp`) or use host networking, and open the pools in the host's firewall.

### Regional probes

A probe checks the nodes from where it runs; it starts no OpenResty and listens on no port. Create the probe in the console for a one-time token; the first start enrolls (the private key is generated locally, 0600), later starts use the stored identity.

Container (the node image with the `probe` entry point):

```yaml
services:
  probe:
    image: ghcr.io/marvinli001/edgeweir-node:<version>
    entrypoint: ["/usr/local/bin/edgeweir-node", "probe"]
    environment:
      EDGEWEIR_STATE_DIR: /var/lib/edgeweir-probe
      EDGEWEIR_SERVER: https://console.example.com:8443
      EDGEWEIR_CA_SHA256: <sha256>
      EDGEWEIR_TOKEN: <probe token>   # used on the first start only
    volumes:
      - probe-state:/var/lib/edgeweir-probe
    healthcheck:
      disable: true
    restart: unless-stopped
volumes:
  probe-state:
```

systemd (the deb / rpm packages include `edgeweir-probe.service`, disabled by default):

```sh
sudo tee /etc/default/edgeweir-probe >/dev/null <<'CONF'
EDGEWEIR_SERVER=https://console.example.com:8443
EDGEWEIR_CA_SHA256=<sha256>
EDGEWEIR_TOKEN=<probe token>
CONF
sudo chmod 600 /etc/default/edgeweir-probe
sudo systemctl enable --now edgeweir-probe
```

A node can probe as well: once the console turns it on for the node, the agent runs the same checks with the node's identity and never checks itself.

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
EDGEWEIR_TOKEN=TOKEN edgeweir-node probe --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR]
edgeweir-node probe [--state-dir DIR]                 # an enrolled probe
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # ban status (JSON); --list adds up to 1000 bans
edgeweir-node security [--control-socket PATH]        # challenge keys, captcha pool, per-site CC levels (JSON)
edgeweir-node version
```

- Every flag can be set as `EDGEWEIR_<FLAG>` (e.g. `--state-dir` → `EDGEWEIR_STATE_DIR`); command-line flags take precedence.
- `run` polls the state directory every 2 s until enrolled and may start before `enroll`.
- `supervise` adds signed upgrades, trials and rollback on top of `run`, and runs OpenResty itself: an upgrade or a restart of the agent process does not restart OpenResty. Upgrade tasks cannot install an older version than the running one (`--upgrade-allow-downgrade` allows it).
- `probe` runs a regional probe: the first run enrolls with a one-time probe token (retrying while the console is unreachable), an enrolled probe ignores the token; missing enrollment settings exit with status 2.

| `enroll` flag | Default | Description |
| --- | --- | --- |
| `--server` | required | Console node-channel URL, e.g. `https://console.example.com:8443` |
| `--ca-sha256` | required | SHA-256 of the console's internal CA certificate (DER, hex) |
| `--token-file` | none | One-time token file (surrounding whitespace ignored) |
| `--token` | none | One-time token; visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory |
| `--force` | off | Replace an existing identity (re-enroll); refused while `run` runs, stop the node first (e.g. `systemctl stop edgeweir-node`) |
| `--timeout` | `30s` | Enrollment RPC timeout |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| `probe` flag | Default | Description |
| --- | --- | --- |
| `--server` | none (required on the first run) | Console node-channel URL |
| `--ca-sha256` | none (required on the first run) | SHA-256 of the console's internal CA certificate (DER, hex) |
| `--token-file` | none | One-time probe token file (first run) |
| `--token` | none | One-time probe token (first run); visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-probe` | Probe identity directory, separate from the node's |
| `--timeout` | `30s` | Timeout of each console RPC |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| `run` flag | Default | Description |
| --- | --- | --- |
| `--manage-nginx` | off | Run OpenResty as a supervised child process (set by the container and the systemd unit) |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory (identity, LKG configuration) |
| `--nginx-bin` | `/usr/lib/edgeweir-openresty/nginx/sbin/nginx` when installed, otherwise `openresty` from `PATH` | OpenResty binary |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix directory |
| `--nginx-user` | none | nginx worker user when the agent runs as root |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | Directory containing `edgeweir/*.lua` |
| `--cache-dir` | `/var/cache/edgeweir-node` | Parent directory of the cache zones |
| `--control-socket` | `/run/edgeweir-node/control.sock` | Data-plane control API socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | Internal origin layer socket |
| `--origin-socket-noverify` | `origin-noverify.sock` next to the origin socket | Origin layer socket without TLS verification |
| `--edge-socket` | `edge.sock` next to the control socket | Local edge listener for prefetches only (`edge-tls.sock` next to it is its TLS twin, while a listener speaks HTTPS); bans, CC, challenges and denying rules do not apply there, nothing is counted in the statistics |
| `--l4-socket` | `l4.sock` next to the control socket | Control relay of the stream subsystem; the control API forwards layer-4 requests to it |
| `--trusted-ca` | system bundle | CA bundle for HTTPS origins (proxying and active health checks) |
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
| `--upgrade-allow-downgrade` | `false` | Let upgrade tasks install an older version than the running one (supervise mode) |
| `--sites-dict-mb` | `64` | Site table store (`lua_shared_dict edgeweir_sites`: the current and the previous site table, error page templates included), MiB |
| `--stats-dict-mb` | `16` | Statistics counters (`lua_shared_dict edgeweir_stats`: per site and minute until the agent drains them), MiB |
| `--purge-dict-mb` | `32` | Purge marker store (`lua_shared_dict edgeweir_purge`), MiB |
| `--purge-markers-per-site` | `1000` | URL and prefix markers per site before collapsing into a site-level marker |
| `--purge-tags-per-site` | `5000` | Tag markers per site before the site's markers collapse into a site-level marker |
| `--prefetch-budget` | `4m` | Time limit per prefetch batch |
| `--ban-capacity` | `100000` | Maximum dynamic bans; oldest automatic bans are evicted first |
| `--ban-dict-mb` | `32` | Ban store (`lua_shared_dict edgeweir_bans`), MiB |
| `--cc-dict-mb` | `32` | CC mitigation store (`lua_shared_dict edgeweir_cc`), MiB |
| `--challenge-dict-mb` | `8` | Challenge store (`lua_shared_dict edgeweir_challenge`), MiB |
| `--tag-dict-mb` | `64` | Cache-Tag index (`lua_shared_dict edgeweir_tags`: tags and key epoch of cached objects, for purges by tag), MiB |
| `--rate-limit-dict-kb` | `256` | Rate-limit counter store of each published site (`lua_shared_dict edgeweir_rate_<hex site id>`), KiB, 64–65536; new counters pass when it is full |
| `--l4-dict-mb` | `32` | Layer-4 table store (`lua_shared_dict edgeweir_l4`: the current and the previous table of layer-4 applications with their IP lists), MiB |
| `--stream-shutdown-timeout` | `0` | After a reload, the old workers close the connections they still serve (long layer-4 connections, WebSockets) after this long (`worker_shutdown_timeout`); `0` serves them until they end |
| `--kernel-bans` | `auto` | Write platform bans into nftables: `auto` (`nft` works and `CAP_NET_ADMIN` granted), `off` |
| `--nft-bin` | `nft` | nftables binary |
| `--modsecurity-module` | `auto` | ModSecurity-nginx dynamic module: `auto` (the `modules/` directory of the edgeweir-openresty that `--nginx-bin` belongs to), a file path, or `off`; loaded only while a site runs the OWASP CRS |
| `--crs-dir` | `/usr/share/edgeweir-openresty/crs` | OWASP CRS directory (`crs-setup.conf`, `rules/`); `unicode.mapping` comes from the sibling `modsecurity/` |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | State (0700): `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG, 0700, files 0600), `credentials.json` (S3 origin keys in plain text, 0600), `purge.json` (purge markers, 0600), `bans.json` (dynamic bans and sequence, 0600), `challenge-keys.json` (challenge pass keys, 0600), `health.crt` / `health.key` (health certificate, 0600), `nginx/` (prefix, `nginx.conf`) |
| `/var/lib/edgeweir-probe` | Probe state (0700): `probe.key` (0600), `probe.crt`, `ca.crt`, `probe.json` |
| `/var/cache/edgeweir-node` | Cache zones |
| `/run/edgeweir-node/control.sock` | Data-plane control API (unix socket only) |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | Local edge listener and internal origin layers |
| `/run/edgeweir-node/l4.sock` | Control relay of the stream subsystem (with layer-4 applications) |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `/usr/share/edgeweir-node/geoip` | IPinfo Lite database and `NOTICE` (container image) |
| `/usr/lib/edgeweir-openresty` | OpenResty (`nginx/sbin/nginx`), the ModSecurity module in `modules/` |
| `/usr/share/edgeweir-openresty/crs` | OWASP CRS |
| `:80` | HTTP listener before any configuration; afterwards as configured |

## Build and test

Requirements: Go 1.27.1, Docker; buf, goreleaser and syft for releases.

```sh
make build         # static binary in bin/
make vet test      # go vet ./... && go test ./...
make test-race     # race detector
make lua-test      # Lua unit tests (resty in the OpenResty image)
make docker        # image (builds edgeweir-openresty too); bundles IPinfo Lite via a BuildKit secret when IPINFO_TOKEN is set
make openresty-packages ARCH=arm64   # edgeweir-openresty deb / rpm and SBOM into out/openresty/
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

Releases are built in GitHub Actions from the tagged source and are reproducible (`-trimpath`, commit timestamps); the IPinfo Lite copy in a container image is identified by the sha256 in its `NOTICE`. The edgeweir-openresty packages are built from the sources pinned in `packaging/openresty/sources.lock`: every source is checked against its SHA-256 and, where upstream signs it, its PGP signature against a pinned key; the same inputs build byte-identical packages. `checksums.txt` covers every archive, package (edgeweir-openresty included) and SBOM and is signed with cosign keyless; each artifact carries a SLSA build provenance attestation.

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

- Sites with the OWASP CRS cost about 0.5 ms of CPU per request; request bodies are read in full before inspection and forwarding, response bodies are not inspected (ARCHITECTURE.md §3.18).
- Certificate materials live in `certificates.json` (0600), readable by host administrators.
- The V2 statistics RPC is incompatible with older consoles; upgrade the console and nodes together.
- Each published site reserves a fixed 256 KiB rate-limit counter partition; up to 512 published sites per cluster. See [rate-limit storage](docs/rate-limit-storage.md).
- Self-update covers the agent and Lua only; the supervisor, cosign and OpenResty are upgraded with system packages or the image, which take precedence over an older self-updated bundle in the state volume.

## Security

- The node key (ECDSA P-256) is generated locally and never leaves the node; enrollment pins the console CA by `--ca-sha256`.
- All RPCs after enrollment use mTLS; the data-plane control API listens on a unix socket only.
- Configuration receipts are persisted before apply; after a console database restore, only console-authenticated higher revisions advance the publication counter.
- Outbound connections: the control channel reaches only the enrolling console; the data plane reaches configured origins, the agent probes origins with active health checks (same address policy) and, with OCSP checks enabled, reaches OCSP responders; probes (and nodes that probe) reach the node addresses the console names.
- Probe keys are generated locally too (0600) and the CA is pinned with `--ca-sha256` before the first enrollment; HTTPS checks do not verify the nodes' self-signed health certificates, they only test reachability.
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
