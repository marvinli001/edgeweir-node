# Edgeweir Node

[简体中文](README.md) | English

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

[![Join the Telegram group](.github/assets/telegram-en.svg)](https://t.me/darkfiber_labs)

Edge node for [Edgeweir](https://github.com/marvinli001/edgeweir): the `edgeweir-node` Go agent and an OpenResty (Lua) data plane. OpenResty is edgeweir-openresty, built from pinned and verified sources with Brotli, Zstandard and optional ModSecurity with the OWASP CRS.

## Features

| Area | Capabilities |
| --- | --- |
| HTTPS and protocols | SNI HTTPS, HTTP/2, HTTP/3, TLS policy, HSTS, hot certificate rotation; up to 4 certificates per site (ECDSA or RSA chosen by the client's ClientHello), visitor client certificates (mTLS), TLS session resumption (a session cache and the cluster's ticket keys, isolated per site), never early data |
| Compression | gzip, Brotli, Zstandard; one coding per response by the q-values of `Accept-Encoding` (zstd > br > gzip at equal q, compression rules restrict and order the codings), one uncompressed object in the cache |
| Access policy | IP / GeoIP lists, phased rules (expression functions, dynamic redirects and rewrites, query edits, bulk redirects, origin rules and origin groups, per-request overrides of site settings, compression rules), WAF (ban, custom responses, closing the connection, skipping later checks; form, multipart and JSON body fields), rate limits (with bans), request / response transforms, all hot-updated; dynamic bans and a greylist (challenge or rate limit) within seconds; platform bans and per-IP connection count / new connection rate limits optionally enforced in the kernel with nftables |
| OWASP CRS | Per-site managed rules (ModSecurity v3 + CRS 4.29.0): detect only / block (rules switch it per request or turn it off), paranoia level, anomaly threshold, excluded rules (site-wide or by path, optionally only for some arguments, cookies or headers), request body inspection limit; cache hits are inspected too, sites without CRS never pass through ModSecurity |
| Challenges and CC mitigation | Four challenge levels (cookie redirect, JS, proof of work, image captcha), signed passes, a site's own challenge page texts, bans after repeated challenge failures, verified search engine crawlers skip challenges, node-local tiered CC mitigation, JA4 fingerprints |
| Cache and origins | `Host` routing, `proxy_cache`, cache rules with expression conditions and browser TTLs, origin-pool load balancing, HTTP/2 to origins and end-to-end gRPC, passive and active health checks, session affinity (signed cookie), purge (URL, prefix, host, site, Cache-Tag), prefetch (URLs and sitemaps, desktop and mobile variants, HTTP and HTTPS) |
| Layer-4 forwarding | TCP / UDP ports forwarded to origins: weights, backup origins, passive health checks and retries on connect failures, connect and idle timeouts, allow / block lists, per-node concurrent and new-per-second limits; PROXY protocol v1 / v2 towards origins, listeners that accept the PROXY protocol; adding or removing ports reloads without dropping open connections, everything else is hot-updated; per-minute connections, refusals, peak concurrency and bytes |
| Error pages | 403 / 429 / 502 / 503 / 504 from site templates or built-in pages (Chinese and English), optionally replacing origin errors; platform pages for unknown and disabled sites; `X-Request-Id` |
| Statistics and logs | Per-minute statistics of sites and layer-4 applications (persisted, resumed by sequence), Top URL / IP and bounded dimensions: countries, networks (ASN), referring hosts, browsers / operating systems / devices, HTTP and TLS versions, block reasons and challenges; sampled access logs (off by default) with User-Agent, Referer, protocol, country, origin and block reason, optionally the query string, request headers and the connection's peer address, and blocked requests logged whatever the sample rate; `edgeweir-node accesslog` shows requests live on the node |
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

- Contract: the protobuf in `edgeweir/proto` (`edgeweir.node.v1.NodeService`, `ProbeService`, `NodeConfig`), generated with buf from git tag `proto/v1.8.0`.
- Structural changes (listeners, cache zones, resolver, the set of sites, domains, protocol and compression settings of HTTPS sites, loading the OWASP CRS and its excluded rules, ports, protocols and PROXY protocol settings of layer-4 applications) re-render `nginx.conf` and reload after `openresty -t`, the old workers serving open connections until they end; all other changes are hot-updated without a reload.

| Data-plane behavior | Response |
| --- | --- |
| Cache status | `X-Cache: MISS` / `HIT` / `BYPASS` |
| Unknown host | `404` platform or built-in page, `X-Edgeweir-Error: unknown-host` |
| Host of a disabled site | `503` platform or built-in page, `X-Edgeweir-Error: site-disabled` |
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

### Unattended installs (SSH)

When the console runs `install.sh` over SSH there is no terminal: `edgeweir-node enroll` never prompts, logs go to stderr only, and it writes exactly one result line to stdout (except for `-h`) for the caller to parse:

```text
EDGEWEIR_RESULT {"v":1,"step":"enroll","status":"enrolled","exit":0,"retry":false,"node_id":"…","node_name":"…","cluster_id":"…","not_after":"2027-01-02T03:04:05Z"}
```

The prefix is followed by JSON on the same line; ignore unknown fields, `message` is English detail, decide by `status`. `retry` tells whether running the same command again (same token) may succeed.

| Exit | `status` | Meaning | `retry` |
| --- | --- | --- | --- |
| 0 | `enrolled` | Enrolled, identity saved | |
| 0 | `already_enrolled` | With `--if-not-enrolled`: already enrolled with the same console (with `node_id`) | |
| 1 | `error` | Anything else; `retry` is true when interrupted by SIGINT/SIGTERM | |
| 2 | `usage` | Invalid flags, missing address, token or fingerprint | no |
| 10 | `already_enrolled` | Already enrolled (with `node_id`), neither `--force` nor `--if-not-enrolled` | no |
| 11 | `enrolled_elsewhere` | With `--if-not-enrolled`: the identity belongs to a console that pins another CA (with `node_id`, `ca_sha256`) | no |
| 12 | `token_rejected` | The console refused the token (unknown, expired or used) | no |
| 13 | `unreachable` | Console not reachable (DNS, connect, timeout, TLS) or it answered Unavailable | yes |
| 14 | `ca_mismatch` | The peer is not the console of `--ca-sha256` (a proxy or CDN terminates TLS, wrong address, certificate without that host name); the token was not sent | no |
| 15 | `state_dir` | The state directory cannot be created or written, saving the identity failed | no |
| 16 | `busy` | Another `enroll` uses the state directory (`retry` true), or `--force` while the agent runs | depends |
| 17 | `console_error` | The console answered with another error or an unusable answer; `retry` true for internal errors | depends |

Re-runs and interruptions:

- One `enroll` per state directory at a time (`enroll.lock`): a retried batch install does not spend a second token while the first attempt still runs.
- The key is written to `enroll.key` (0600) before the token is sent and reused by every retry until an enrollment succeeds (it becomes `node.key`). When the console issued the certificate but the answer was lost (SSH dropped, timeout), the retry sends the same public key, so the console can answer with the node it already created instead of a second one.
- A dropped SSH session (closed stdout/stderr pipes, SIGHUP) does not abort a running enrollment: the certificate may already be issued, so the identity is still saved; SIGINT and SIGTERM still abort it.
- Enrolled hosts: `--if-not-enrolled` succeeds with the node id and fails (11) when the host belongs to another console, never switching identities silently; only `--force` enrolls again.

### Operations without SSH

After the install the console manages the node through the node channel only; SSH credentials are not kept:

| Operation | How |
| --- | --- |
| Upgrade | The console's upgrade task (`supervise` downloads, verifies, trial-runs, rolls back on failure) |
| Console address change | The node follows the address the console names ([Console URL](#console-url)) |
| Certificate renewal | Automatic, before expiry |
| Log collection | Warnings and events are reported continuously; the console pulls the recent logs of every level on demand (`--debug-log-buffer`) |
| Restart, reload | Not needed: configuration changes reload OpenResty, crashed processes are restarted by the supervisor and systemd |
| Decommission | The console's decommission task (`decommission-v1`): the node reports it, stops serving, deletes its identity, configuration and cache, and does not start again (also after a reboot) until it is enrolled anew; the packages stay |
| Still needs SSH | Re-enrolling after the key is lost or the certificate expired while offline, changing local settings (`/etc/default/edgeweir-node`, the kernel-ban drop-in), removing the packages |

### deb / rpm

Requirements: glibc 2.34 or later (RHEL / Rocky / AlmaLinux 9, Debian 12, Ubuntu 22.04 and newer), amd64 or arm64. The agent runs OpenResty as a child process; if OpenResty's own packages are installed, disable their service (`sudo systemctl disable --now openresty`).

Artifacts: `edgeweir-node_<version>_<arch>.deb` (`amd64`, `arm64`), `edgeweir-node-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`), `edgeweir-openresty_1.31.1.1-3_<arch>.deb` / `edgeweir-openresty-1.31.1.1-3.<arch>.rpm`, the `edgeweir-openresty-modsecurity` packages named alike, `checksums.txt*`. [Verify](#verify-release-artifacts) before installing.

```sh
sudo apt install ./edgeweir-openresty_1.31.1.1-3_amd64.deb ./edgeweir-openresty-modsecurity_1.31.1.1-3_amd64.deb \
  ./edgeweir-node_<version>_amd64.deb
# or sudo dnf install ./edgeweir-openresty-1.31.1.1-3.x86_64.rpm ./edgeweir-openresty-modsecurity-1.31.1.1-3.x86_64.rpm \
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

### WebSocket entry

When the console is only reachable over HTTPS (for example on Render), nodes reach the node channel through the WebSocket entry on the console's web port: `--server wss://console.example.com`; `ws://` for a plain-HTTP console.

| Item | Details |
| --- | --- |
| Entry | `<URL>/node-channel`, WebSocket subprotocol `edgeweir-node-channel`; the URL has no path |
| TLS | The node channel's TLS runs inside the WebSocket and is terminated by the console; CA pinning and mTLS are the same as with an `https://` URL. The certificate of a `wss://` URL itself is verified against the system roots |
| Proxy | The WebSocket handshake follows `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` |
| Version | 0.2.0 and later |

### Console URL

Nodes and probes reach the console at the URL in `identity.json` (`probe.json`) and follow the node channel URL the console gives out (capability `channel-follow-v1`, from 1.2.0):

| Item | Details |
| --- | --- |
| Handout | Every heartbeat answer (for probes, every round of targets) carries the console's current URL; only the latest counts, and it only arrives over the authenticated mTLS channel |
| Check | When it differs from the URL in use, the agent first calls `CheckChannel` (probes `CheckProbeChannel`) there with the pinned CA and its own client certificate and checks that the console recognizes it; once that passes it rewrites `identity.json` atomically, keeping the previous URL as its fallback, without a restart or a new enrollment |
| Failure | The agent stays on its URL, reports why in its heartbeats (`unreachable`, `websocket_refused`, `tls_untrusted`, `rejected`, `wrong_identity`, `invalid_address`) and tries again after 1, 5, 15 and 60 minutes |
| Fallback | When no call succeeds on the URL in use for 3 minutes, the agent checks its fallback and uses it for the time being, trying its URL again every 5 minutes; the fallback is never written to the file, and a restart connects to `server_url` first |
| Limits | Only `https://`, `wss://` and `ws://`, without credentials, a path or a query; the agent always trusts the CA pinned at enrollment, the URL only decides which host it connects to and which name it verifies; a new host joins the nftables allow list before the agent connects to it |
| Recovery | `edgeweir-node set-server`, see [Command line](#command-line) |

## Versions

| Item | Rule |
| --- | --- |
| Releases | [GitHub Releases](https://github.com/marvinli001/edgeweir-node/releases): semantic versions `vX.Y.Z` with signed checksums, SBOMs, and build provenance; images `ghcr.io/marvinli001/edgeweir-node:X.Y.Z` and `X.Y`. The install command takes the latest release unless `--version` names one |
| Patch version | Fixes, no new capabilities |
| Minor version | New capability names (`*-vN`), new commands, new optional settings |
| Major version | Removing a capability or proto field, an incompatible state directory or `identity.json`, raised install requirements (glibc floor, distributions), re-enrollment |
| With the console | The console sends configuration by the capabilities a node reports, not by version number; a `stable` console supports every 1.x minor version, and 0.x nodes only use the capabilities they report |
| Proto | The 1.x wire format only grows compatibly; an incompatible change needs proto v2 and node 2.0.0 |

## Command line

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force | --if-not-enrolled]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...            # same flags as run; systemd unit and image entry point
EDGEWEIR_TOKEN=TOKEN edgeweir-node probe --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR]
edgeweir-node probe [--state-dir DIR]                 # an enrolled probe
edgeweir-node set-server --server URL [--server-name NAME] [--probe] [--state-dir DIR]   # change the console URL after a check
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # ban status (JSON); --list adds up to 1000 bans
edgeweir-node security [--control-socket PATH]        # challenge keys, captcha pool, per-site CC levels (JSON)
edgeweir-node accesslog [--site ID] [--json] [--socket PATH]   # this node's requests as they happen; Ctrl-C stops
edgeweir-node diagnose [--state-dir DIR] [--control-socket PATH] [--diag-socket PATH] [--json]   # check this node step by step
edgeweir-node pprof PROFILE [--seconds 30] [--output FILE] [--diag-socket PATH]   # a Go profile of the running agent
edgeweir-node version
```

- Every flag can be set as `EDGEWEIR_<FLAG>` (e.g. `--state-dir` → `EDGEWEIR_STATE_DIR`); command-line flags take precedence.
- `run` polls the state directory every 2 s until enrolled and may start before `enroll`.
- `supervise` adds signed upgrades, trials and rollback on top of `run`, and runs OpenResty itself: an upgrade or a restart of the agent process does not restart OpenResty. Upgrade tasks cannot install an older version than the running one (`--upgrade-allow-downgrade` allows it).
- `probe` runs a regional probe: the first run enrolls with a one-time probe token (retrying while the console is unreachable), an enrolled probe ignores the token; missing enrollment settings exit with status 2.
- `set-server` changes the node channel URL of an enrolled node (`--probe`: a probe), for a node that lost the console because the old address went down first: it makes one mTLS call to the new URL with the node's own identity (pinned CA and client certificate) and only then rewrites `identity.json` (`probe.json`) atomically, keeping the previous URL as the fallback; the identity and certificate stay. A failed check exits with status 1 and changes no file. A running agent moves to the new URL within seconds. Otherwise nodes follow the URL the console gives out on their own (see [Console URL](#console-url)).
- `accesslog` reads the data plane's live view every 250 ms (control socket, the same permissions as `bans` and `security`; `--socket` is short for `--control-socket`), one request per line: time (UTC, milliseconds), client IP, method, Host, path (spaces as `%20`), status, bytes sent, duration, cache status (`-` without one) and `blocked=<reason>` when the node refused or challenged it; `--json` prints JSON Lines (with User-Agent, Referer, protocol, country, ASN, origin, blocking rule and the other fields). Sample rates do not apply, and the data plane records only while someone watches (it stops 5 s after the last call); without `--site` requests of unknown hosts are shown too. Requests missed (expired, or over the rate of 2000 per second and node; those count for the whole node, also with `--site`) are counted on stderr. Query strings, request headers and peer addresses go only into the sampled logs of sites that record them, never here.
- `diagnose` runs one check after the other and prints a line for each (`ok`, `warn`, `fail`, `skip`): identity, the node certificate's lifetime, the console (one mTLS call to the current address with the node's identity), the clock (a second call: the console's time against the middle of the round trip; `warn` from 1 s, `fail` from 30 s), the running agent (diagnostics socket: version, last heartbeat and error), the configuration (applied and the console's latest revision, why an apply failed, certificates that did not load) and the data plane (control socket). It exits with 1 when a check fails; `--json` prints the results and the agent's full status. It reads the state directory and both sockets: run it as root or as the agent's user (`sudo -u edgeweir`).
- `pprof` fetches a Go profile of the running agent from the diagnostics socket: `profile` (CPU, `--seconds` seconds, at most 120), `trace`, `heap`, `allocs`, `goroutine`, `block`, `mutex`, `threadcreate`, written to `--output` or a redirected standard output, for `go tool pprof` / `go tool trace`. The diagnostics socket (`--diag-socket`, default `/run/edgeweir-node/diag.sock`) is a unix socket only the agent's user may use (0600), never TCP; empty disables it, and `diagnose` then fails its agent and configuration checks.

| `enroll` flag | Default | Description |
| --- | --- | --- |
| `--server` | required | Console node-channel URL: the node channel port, `https://console.example.com:8443`, or the WebSocket entry on the console's web port, `wss://console.example.com` (`ws://` for a plain-HTTP console); see [WebSocket entry](#websocket-entry) below |
| `--ca-sha256` | required | SHA-256 of the console's internal CA certificate (DER, hex) |
| `--token-file` | none | One-time token file (surrounding whitespace ignored) |
| `--token` | none | One-time token; visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-node` | State directory |
| `--force` | off | Replace an existing identity (re-enroll); refused while `run` runs, stop the node first (e.g. `systemctl stop edgeweir-node`) |
| `--if-not-enrolled` | off | Succeed when already enrolled with the console of `--ca-sha256` (no token needed, nothing sent); exit 11 when the identity belongs to another console. Excludes `--force` |
| `--timeout` | `30s` | Enrollment RPC timeout |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| `probe` flag | Default | Description |
| --- | --- | --- |
| `--server` | none (required on the first run) | Console node-channel URL, same forms as `enroll` |
| `--ca-sha256` | none (required on the first run) | SHA-256 of the console's internal CA certificate (DER, hex) |
| `--token-file` | none | One-time probe token file (first run) |
| `--token` | none | One-time probe token (first run); visible in the process list, prefer `EDGEWEIR_TOKEN` or `--token-file` |
| `--server-name` | host of `--server` | TLS server name to verify |
| `--state-dir` | `/var/lib/edgeweir-probe` | Probe identity directory, separate from the node's |
| `--timeout` | `30s` | Timeout of each console RPC |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| `set-server` flag | Default | Description |
| --- | --- | --- |
| `--server` | Required | The new console node-channel URL, same format as for `enroll`, without a path |
| `--server-name` | Host of `--server` | TLS server name to verify |
| `--probe` | Off | Change a probe's URL |
| `--state-dir` | `/var/lib/edgeweir-node` (`--probe`: `/var/lib/edgeweir-probe`) | State directory of the identity |
| `--timeout` | `30s` | Timeout of the check |

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
| `--diag-socket` | `/run/edgeweir-node/diag.sock` | Diagnostics socket (0600): `diagnose` reads the agent's status from it, `pprof` its Go profiles; empty disables it |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | Internal origin layer socket; the origin layers for HTTP/2 to origins and gRPC sit next to it (`origin-h2.sock`, `origin-grpc.sock` and their `origin-noverify-*` versions) |
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
| `--cache-usage-interval` | `10m` | How often the disk usage of the cache zones is measured (a walk over the cache directory, reported with the heartbeat) |
| `--stats-interval` | `1m` | How often the statistics of completed minutes are drained from the data plane and uploaded (1s–1m; shortened only in end-to-end tests) |
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
| `--image-workers` | min(4, max(1, CPUs / 2)) | Concurrent WebP / AVIF conversions, each a child process on one CPU; 0 turns conversion off (the node does not announce `image-convert-v1` and cannot serve sites that convert) |
| `--no-extensions` | off | Turns node extensions off: the node does not announce `extensions-v1` and never downloads or loads extension packages; the console cannot override it |
| `--extension-keys` | none | File of publisher keys (Ed25519 JWKs, one per line or a JSON array): extension packages must also be signed with one of them, on top of the console's trust store |
| `--sidecar-mode` | `auto` | Extension sidecars: `auto` runs them when the agent runs as root with `--sidecar-user`, `user` requires that, `off` never runs one |
| `--sidecar-user` | none | Unprivileged user of its own that extension sidecars run as (the agent must run as root) |
| `--sidecar-dir` | state directory + `-sidecar` | The sidecars' package copies, state and data |
| `--image-memory-mb` | `1024` | Memory the running conversions may use together, in MiB; each conversion's need is estimated from its pixels, larger images keep their original |
| `--image-timeout` | `8s` | Longest conversion: the child is killed and the original kept |
| `--markdown-workers` | min(4, max(1, CPUs / 2)) | Concurrent HTML to Markdown conversions (Markdown for Agents), each a child process on one CPU; 0 turns conversion off (the node does not announce `markdown-v1` and cannot serve sites that convert) |
| `--markdown-memory-mb` | `512` | Memory the running Markdown conversions may use together, in MiB; each conversion's need is estimated from the HTML's size, larger documents stay HTML |
| `--markdown-timeout` | `5s` | Longest Markdown conversion: the child is killed and the HTML kept |
| `--debug-log-buffer` | `5000` | Recent log entries of every level kept in memory (at most 4 MiB) for the console to pull from the node's Logs tab; `0` turns it off (the node does not announce `debug-logs-v1`), at most 100000 |
| `--challenge-verify-endpoints` | empty | Replace CAPTCHA providers' verification URLs, comma-separated `kind=URL` (`turnstile`, `recaptcha`, `recaptcha_enterprise`, `tencent`, `aliyun`, `geetest`); for tests against a mock provider only |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `text` | `text`, `json` |

| Path / port | Purpose |
| --- | --- |
| `/var/lib/edgeweir-node` | State (0700): `node.key` (0600), `node.crt`, `ca.crt`, `identity.json`, `config/` (LKG, 0700, files 0600), `credentials.json` (S3 origin keys, PURGE keys and the Basic user hashes and signing keys of access authentication in plain text, 0600), `purge.json` (purge markers, 0600), `bans.json` (dynamic bans and sequence, 0600), `challenge-keys.json` (challenge pass keys, 0600), `session-ticket-keys.json` (TLS session ticket keys, 0600), `health.crt` / `health.key` (health certificate, 0600), `nginx/` (prefix, `nginx.conf`) |
| `/var/lib/edgeweir-probe` | Probe state (0700): `probe.key` (0600), `probe.crt`, `ca.crt`, `probe.json` |
| `/var/cache/edgeweir-node` | Cache zones |
| `/run/edgeweir-node/control.sock` | Data-plane control API (unix socket only) |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock`, `origin[-noverify]-{h2,grpc}.sock` | Local edge listener and internal origin layers |
| `/run/edgeweir-node/l4.sock` | Control relay of the stream subsystem (with layer-4 applications) |
| `/usr/share/edgeweir-node/lua` | Lua modules |
| `/usr/share/edgeweir-node/geoip` | IPinfo Lite database and `NOTICE` (container image) |
| `/usr/lib/edgeweir-openresty` | OpenResty (`nginx/sbin/nginx`), the ModSecurity module in `modules/` |
| `/usr/share/edgeweir-openresty/crs` | OWASP CRS |
| `:80` | HTTP listener before any configuration; afterwards as configured |

## Build and test

Requirements: Go 1.27.2, Docker; buf, goreleaser and syft for releases.

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
make package-check # check the packages in dist/: build tags, NOTICE, LICENSE, Lua modules
make notice        # regenerate NOTICE after changing go.mod
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
- Certificate materials live in `certificates.json` (0600), readable by host administrators; TLS session ticket keys live in `session-ticket-keys.json` and under `conf/tls-tickets/` of the nginx prefix (both 0600).
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
