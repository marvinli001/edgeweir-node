# Edgeweir Node

简体中文 | [English](README.en.md)

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

[Edgeweir](https://github.com/marvinli001/edgeweir) 的边缘节点。Go agent 负责注册、配置同步、任务执行与签名升级；OpenResty（Lua）数据面负责路由、缓存、回源与策略执行。

## 与控制台的关系

| 仓库 | 组成 |
| --- | --- |
| [marvinli001/edgeweir](https://github.com/marvinli001/edgeweir) | 控制台（控制面）：TypeScript，单应用、单镜像。将站点与规则编译为与引擎无关的 `NodeConfig` IR，运行内部 CA 与节点通道（默认 `:8443`）。 |
| **marvinli001/edgeweir-node**（本仓库） | 节点：Go agent `edgeweir-node` + OpenResty（Lua）。 |

两个仓库间唯一的契约为 `edgeweir/proto` 中的 protobuf（`edgeweir.node.v1.NodeService`、`NodeConfig`）。本仓库以 buf 从该目录的 git tag（当前 `proto/v0.10.0`）生成 Go 代码，不复制 `.proto` 文件。

## 功能

| 领域 | 能力 |
| --- | --- |
| HTTPS 与协议 | SNI HTTPS、HTTP/2、HTTP/3、TLS 策略、HSTS、Gzip；证书热轮换 |
| 访问策略 | IP / GeoIP 名单、分阶段规则、WAF、限速、请求 / 响应变换，均为热更新；动态封禁不经 revision、秒级生效，平台封禁可经 nftables 在内核丢包；GeoIP 读取本地 MMDB，不向第三方发送客户端 IP；发布镜像内置 IPinfo Lite（国家、ASN） |
| 缓存与回源 | 按 `Host` 路由、`proxy_cache` 缓存、源站池负载均衡与被动健康检查、清缓存与预热 |
| 统计与日志 | 按站点、按分钟的流量统计（上传前持久化，回执丢失或重启后按序号恢复）、有界 Top URL / IP 估算、采样访问日志（默认关闭，不记录查询参数、请求头与正文） |
| 配置可靠性 | 校验后应用，结构性变更激活失败时恢复原配置；last-known-good（LKG）配置持久化；控制台不可达时按 LKG 持续服务 |
| 签名升级 | `supervise` 监督进程、本机固定发布源与信任锚、agent 与 Lua 同步切换、节点组试运行与显式推进、失败自动回滚 |

## 工作机制

1. **注册**：`edgeweir-node enroll` 在本机生成 ECDSA P-256 私钥（不离开节点），按安装命令中的 SHA-256 固定控制台内部 CA，以一次性 token 与 CSR 换取节点证书。
2. **mTLS 通道**：后续 RPC 均以节点证书认证。`WatchConfig` 服务端流推送 revision 通知；`GetConfig` 约每 30 秒轮询兜底，间隔带 ±20% 随机抖动。
3. **应用配置**：快照与增量 diff 先校验 `content_hash` 与合法性。结构性变更（监听端口、缓存 zone、resolver、已发布站点 ID 集合、带 HTTPS 设置的站点的域名与协议设置）重新渲染 `nginx.conf`，经 `openresty -t` 检查后 reload；既有站点的源站、缓存、证书与策略规则经本地 unix socket 热更新，不 reload。应用成功的配置持久化为 LKG。
4. **服务流量**：Lua 数据面按 `Host` 路由，以 `proxy_cache` 缓存（响应头 `X-Cache: MISS/HIT/BYPASS`），在源站池间负载均衡并做被动健康检查；未知域名返回 `404` 与 `X-Edgeweir-Error: unknown-host`。源站不得指向特殊地址段（回环、链路本地 / 云元数据、私网等），平台管理员放行的除外；回源请求携带 `CDN-Loop`，环路以 `508` 终止。
5. **任务与上报**：清缓存与预热任务、状态心跳（已应用 revision、源站健康状态）、按站点按分钟流量统计、证书自动续期。
6. **配置回执**：回执在应用前持久化，经 mTLS 回传。控制台恢复数据库后，仅经控制台认证的更高 revision 可推进发布序号。

架构细节见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 安装

### 一键安装（推荐）

控制台为每个节点生成安装命令，`install.sh` 由控制台提供，依次执行：

1. 下载发布物（可经控制台镜像转发），执行任何内容前校验 SHA-256 与 cosign 签名。`--allow-unsigned` 仅供开发使用：跳过签名校验，SHA-256 照常校验。
2. 安装 OpenResty 与 `edgeweir-node` 包。
3. 以固定的 CA 指纹完成注册。一次性 token 经 `EDGEWEIR_TOKEN` 环境变量传递，不出现在命令行。
4. 启动服务。

控制台不保存 SSH 凭据。

### 手动安装（deb / rpm）

1. 从 [OpenResty 官方仓库](https://openresty.org/cn/linux-packages.html)安装 OpenResty，并停用其自带服务（agent 以子进程方式运行 OpenResty）：`sudo systemctl disable --now openresty`。
2. 从 Release 页面下载 `edgeweir-node_<版本>_<架构>.deb`（`amd64`、`arm64`）或 `edgeweir-node-<版本>-1.<架构>.rpm`（`x86_64`、`aarch64`）及 `checksums.txt*`，并[验证发布物](#验证发布物)。
3. 安装、注册、启动：

   ```sh
   sudo apt install ./edgeweir-node_<版本>_amd64.deb   # 或：sudo dnf install ./edgeweir-node-<版本>-1.x86_64.rpm
   # token 文件使一次性 token 不出现在进程列表
   sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
   sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
   sudo rm /root/edgeweir-token
   sudo systemctl enable --now edgeweir-node
   ```

安装包内容：`/usr/bin/edgeweir-node`、`/usr/share/edgeweir-node/lua` 下的 Lua 模块、systemd unit、`/etc/default/edgeweir-node`；创建非特权用户 `edgeweir` 及其所属的状态目录与缓存目录。

内核封禁（平台范围的封禁经 nftables 丢包）需要 `nftables` 和 `CAP_NET_ADMIN`，默认 unit 不授予。启用时添加 `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`：

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
```

再执行 `sudo systemctl daemon-reload && sudo systemctl restart edgeweir-node`。没有该权限时封禁只在 L7 执行（`403`）。

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<版本>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # 粘贴一次性 token
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

容器启动即运行 OpenResty（所有域名返回 `404 unknown-host`），注册完成后开始同步控制台配置。容器以 uid 10001 运行，节点身份与 LKG 配置保存在 `/var/lib/edgeweir-node` 卷中。内核封禁需要以 `docker build --build-arg NFT_CAPABILITY=true` 构建的镜像，并以 `--cap-add NET_ADMIN` 启动容器；默认镜像不带任何额外权限，封禁只在 L7 执行。

发布镜像包含构建时下载的 [IPinfo Lite](https://ipinfo.io/lite) 数据库 `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb`（CC BY-SA 4.0，IP address data is powered by [IPinfo](https://ipinfo.io)；同目录 `NOTICE` 记录下载时间与 sha256），在本地回答 `ip.geoip.country` 与 `ip.geoip.asnum`，运行时不下载。更新数据：拉取新镜像，或挂载另行下载的副本并设置 `EDGEWEIR_GEOIP_IPINFO`。安装包与压缩包不内置该数据库，将 `EDGEWEIR_GEOIP_IPINFO` 指向自行下载的文件。一级行政区需另行提供 City MMDB（`EDGEWEIR_GEOIP_CITY`）。

## 命令行

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...   # --token TOKEN 亦可，但会出现在 ps 中
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...   # 参数同 run；systemd unit 与容器镜像的入口
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # 数据面的封禁状态（JSON），--list 另列出最多 1000 条
edgeweir-node security [--control-socket PATH]        # 挑战密钥与验证码池、各站点的 CC 级别（JSON）
edgeweir-node version
```

- 所有参数均可通过环境变量 `EDGEWEIR_<参数名>` 设置（如 `--state-dir` → `EDGEWEIR_STATE_DIR`、`--token` → `EDGEWEIR_TOKEN`、`--token-file` → `EDGEWEIR_TOKEN_FILE`），命令行参数优先。
- `run` 在注册完成前每 2 秒检查一次状态目录，可先启动 `run` 再执行 `enroll`。
- `supervise` 在 `run` 之上负责签名升级、试运行与回滚。

| `enroll` 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--server` | 必填 | 控制台节点通道地址，如 `https://console.example.com:8443` |
| `--ca-sha256` | 必填 | 安装命令中的控制台内部 CA 证书（DER）SHA-256，十六进制 |
| `--token-file` | 无 | 从文件读取一次性 token（忽略首尾空白） |
| `--token` | 无 | 一次性 token；会出现在进程列表中，优先使用 `EDGEWEIR_TOKEN` 或 `--token-file` |
| `--server-name` | `--server` 的主机名 | 校验的 TLS 服务器名 |
| `--state-dir` | `/var/lib/edgeweir-node` | 保存节点身份的状态目录 |
| `--force` | 关 | 替换已有身份（重新注册） |
| `--timeout` | `30s` | 注册 RPC 超时 |
| `--log-level` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | 日志格式：`text`、`json` |

| `run` 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--manage-nginx` | 关 | 以受监管子进程运行 OpenResty（容器与 systemd unit 均开启） |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录（身份、LKG 配置） |
| `--nginx-bin` | `openresty` | OpenResty 可执行文件 |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix 目录 |
| `--nginx-user` | 无 | agent 以 root 运行时 nginx worker 的用户（建议以非特权用户运行 agent） |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | `edgeweir/*.lua` 所在目录 |
| `--cache-dir` | `/var/cache/edgeweir-node` | 缓存 zone 的上级目录 |
| `--control-socket` | `/run/edgeweir-node/control.sock` | 数据面控制 API 的 unix socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | 内部回源层的 unix socket |
| `--origin-socket-noverify` | 回源 socket 同目录的 `origin-noverify.sock` | 不校验 TLS 的回源层 unix socket |
| `--edge-socket` | 控制 socket 同目录的 `edge.sock` | 所有监听均启用 PROXY protocol 时，预热使用的本地边缘监听 |
| `--trusted-ca` | 系统 CA bundle | 校验 HTTPS 源站证书的 CA |
| `--resolv-conf` | `/etc/resolv.conf` | nginx resolver 的来源文件 |
| `--resolver` | 无 | 逗号分隔的 resolver 地址（优先于 `--resolv-conf`） |
| `--resolver-ipv6` | `auto` | 为源站解析 AAAA 记录：`auto`（本机有全局 IPv6 地址时）、`on`、`off` |
| `--listen-ipv6` | `auto` | 同时监听 IPv6：`auto`（本机可绑定 IPv6 时）、`on`、`off` |
| `--default-port` | `80` | 收到配置前的 HTTP 服务端口 |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-ipinfo` | `auto` | IPinfo Lite MMDB（国家、ASN）：`auto` 在镜像内置时使用 `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb`，`off` 关闭，其他值为文件路径 |
| `--geoip-city` | 空 | 运维提供的 City MMDB 路径；为空时不启用 |
| `--geoip-asn` | 空 | 运维提供的 ASN MMDB 路径；为空时不启用 |
| `--cosign-bin` | `cosign` | supervise 模式的本机签名验证程序 |
| `--upgrade-source` | 官方 GitHub Release 下载地址 | 运维指定的发布镜像，升级任务不可修改 |
| `--upgrade-public-key` | 空 | 本机发布公钥；为空时固定官方 GitHub OIDC 身份 |
| `--upgrade-allow-http` | `false` | 允许本地测试或隔离网络镜像使用明文 HTTP |
| `--purge-dict-mb` | `32` | 清缓存标记存储（`lua_shared_dict edgeweir_purge`）大小，单位 MiB |
| `--purge-markers-per-site` | `1000` | 每站点 URL 与前缀标记上限，超出后合并为全站标记 |
| `--prefetch-budget` | `4m` | 单批预热任务的时间上限 |
| `--ban-capacity` | `100000` | 数据面最多保存的动态封禁条数（控制台条目与本机自动封禁）；超出时先淘汰最早的自动封禁，手动封禁写不下时如实上报 |
| `--ban-dict-mb` | `32` | 封禁存储（`lua_shared_dict edgeweir_bans`）大小，单位 MiB |
| `--cc-dict-mb` | `32` | CC 防护存储（`lua_shared_dict edgeweir_cc`：计数、级别、事件）大小，单位 MiB |
| `--challenge-dict-mb` | `8` | 挑战存储（`lua_shared_dict edgeweir_challenge`：密钥、验证码池、已用挑战 nonce）大小，单位 MiB |
| `--kernel-bans` | `auto` | 平台范围的封禁同时写入 nftables：`auto`（`nft` 可用且有 `CAP_NET_ADMIN` 时）、`off` |
| `--nft-bin` | `nft` | 内核封禁使用的 nftables 可执行文件 |
| `--log-level` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | 日志格式：`text`、`json` |

| 路径 / 端口 | 用途 |
| --- | --- |
| `/var/lib/edgeweir-node` | 状态目录（0700）：`node.key`（0600）、`node.crt`、`ca.crt`、`identity.json`、`config/`（LKG，目录 0700，文件 0600）、`credentials.json`（S3 源站密钥明文，0600）、`purge.json`（清缓存标记，0600）、`bans.json`（动态封禁与序号，0600）、`challenge-keys.json`（挑战凭证密钥，0600）、`nginx/`（prefix 与渲染后的 `nginx.conf`） |
| `/var/cache/edgeweir-node` | 缓存 zone |
| `/run/edgeweir-node/control.sock` | Lua 数据面本地控制 API（仅 unix socket） |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | 本地边缘监听与内部回源层 |
| `/usr/share/edgeweir-node/lua` | Lua 模块 |
| `/usr/share/edgeweir-node/geoip` | 内置的 IPinfo Lite 数据库及其 `NOTICE`（容器镜像） |
| `:80` | 收到配置前的 HTTP 监听端口；此后以配置中的监听为准 |

## 构建与测试

环境要求：Go 1.27.1、Docker；发布相关工作另需 buf、goreleaser、syft。

```sh
make build         # 静态二进制，输出至 bin/
make vet test      # go vet ./... && go test ./...
make test-race     # 启用 race detector 运行测试
make lua-test      # 在 OpenResty 镜像中以 resty 运行 Lua 单元测试
make docker        # docker build -t edgeweir-node:dev .；设置 IPINFO_TOKEN 时以 BuildKit secret 下载并内置 IPinfo Lite，未设置时镜像不含 GeoIP 数据
make e2e           # 容器冒烟测试：模拟控制台 + 节点 + whoami 源站
make proto-check   # 从 proto git tag 重新生成，与已提交代码不一致时失败
make snapshot      # goreleaser release --snapshot --clean（不签名）
```

`make e2e` 在 127.0.0.1 上发布宿主机端口，默认 28080（节点）、28081（PROXY protocol 监听）、28090（模拟控制台辅助接口）。`COMPOSE_PROJECT_NAME` 仅隔离容器、网络与卷；与其他 compose 项目并行运行时，须同时以 `E2E_NODE_PORT`、`E2E_PP_PORT`、`E2E_HELPER_PORT` 指定空闲端口：

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

proto 重新生成流程与提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 验证发布物

发布物由 GitHub Actions 从 tag 源码构建，构建可复现（`-trimpath`，时间戳取自提交时间）；容器镜像另含构建当天的 IPinfo Lite 数据，重建后数据不同，所含副本以 `/usr/share/edgeweir-node/geoip/NOTICE` 中的 sha256 标识。`checksums.txt` 覆盖全部压缩包、安装包与 SBOM，以 cosign keyless 签名；每个发布物附带 SLSA 构建来源证明。

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/marvinli001/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<版本>_linux_amd64.tar.gz --repo marvinli001/edgeweir-node
```

## 已知限制

- 当前 OpenResty 引擎不含 Brotli 与 Zstd。
- 证书材料保存在 `certificates.json`（0600），主机管理员可读取。
- 统计 RPC V2 不回退到旧版控制台，控制台与节点须同步升级。
- 每个已发布站点独占固定 256 KiB 限速计数分区，每集群最多 512 个已发布站点；新增站点不调整既有分区。见[限速存储](docs/rate-limit-storage.md)。
- 自升级仅覆盖 agent 与 Lua。监督进程、cosign 与 OpenResty 通过系统包或镜像升级；系统包 / 镜像版本优先于状态卷中较旧的自升级程序。

## 安全

- 无厂商回连，无许可证校验，无遥测。
- 控制通道仅连接注册时指定的控制台；数据面连接已配置的源站，启用 OCSP 检查时连接证书的 OCSP 响应方。
- 漏洞通过 [GitHub 私密漏洞报告](https://github.com/marvinli001/edgeweir-node/security/advisories/new)提交，详见 [SECURITY.md](SECURITY.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 节点架构 |
| [SECURITY.md](SECURITY.md) | 安全模型与漏洞报告 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 开发规范与 proto 生成流程 |
| [HTTPS 与证书](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/https.md) | 证书、协议与 TLS 策略 |
| [规则](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/rules.md) | 规则、IP 名单与 GeoIP |
| [访问日志](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/access-logs.md) | 访问日志采集与存储 |
| [节点升级](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/node-upgrades.md) | 签名升级、试运行与回滚 |

## 许可证

[AGPL-3.0-only](LICENSE)，允许在遵守许可证的前提下商用。

节点及控制台的组织、成员与隔离属于开源核心；客户门户、套餐计费、财务与分销由独立商业产品提供。节点运行不依赖官方商业许可证。详见 [LICENSING.md](LICENSING.md)。

内置 GeoIP 数据为 [IPinfo Lite](https://ipinfo.io/lite)，许可证 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)：IP address data is powered by [IPinfo](https://ipinfo.io)。
