# Edgeweir Node

简体中文 | [English](README.en.md)

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

[Edgeweir](https://github.com/marvinli001/edgeweir) 边缘节点：Go agent `edgeweir-node` 与 OpenResty（Lua）数据面。

## 功能

| 领域 | 能力 |
| --- | --- |
| HTTPS 与协议 | SNI HTTPS、HTTP/2、HTTP/3、TLS 策略、HSTS、Gzip、证书热轮换 |
| 访问策略 | IP / GeoIP 名单、分阶段规则、WAF、限速、请求 / 响应变换，均热更新；秒级动态封禁，平台封禁可经 nftables 内核丢包 |
| 挑战与 CC 防护 | 四级挑战（Cookie 跳转、JS、工作量证明、图片验证码）、签名通行凭证、节点本地分级 CC、JA4 指纹 |
| 缓存与回源 | `Host` 路由、`proxy_cache`、源站池负载均衡、被动健康检查、清缓存、预热 |
| 统计与日志 | 按站点按分钟流量统计（持久化、按序号续传）、Top URL / IP、采样访问日志（默认关闭） |
| GeoIP | 本地 MMDB 查询；发布镜像内置 IPinfo Lite（国家、ASN） |
| 配置可靠性 | 校验后应用、激活失败回退、last-known-good（LKG）持久化；控制台不可达时按 LKG 服务 |
| 签名升级 | `supervise` 监督进程、本机固定发布源与信任锚、节点组试运行、失败自动回滚 |

## 架构

| 组件 | 职责 |
| --- | --- |
| `edgeweir-node` agent | 注册、mTLS 通道（`WatchConfig` 推送，`GetConfig` 约 30 秒轮询兜底）、配置校验与应用、任务、心跳与统计上报、签名升级 |
| OpenResty 数据面 | 路由、缓存、回源、策略执行；经本地 unix socket 接收站点、源站、证书与规则的热更新 |
| [edgeweir](https://github.com/marvinli001/edgeweir) 控制台 | 控制面：内部 CA、节点通道（默认 `:8443`）、`NodeConfig` 编译与下发 |

- 契约：`edgeweir/proto` 中的 protobuf（`edgeweir.node.v1.NodeService`、`NodeConfig`），以 buf 从 git tag `proto/v0.10.1` 生成。
- 结构性变更（监听、缓存 zone、resolver、站点集合、HTTPS 站点的域名与协议设置）重新渲染 `nginx.conf`，经 `openresty -t` 后 reload；其余变更热更新，不 reload。

| 数据面行为 | 响应 |
| --- | --- |
| 缓存状态 | `X-Cache: MISS` / `HIT` / `BYPASS` |
| 未知域名 | `404`，`X-Edgeweir-Error: unknown-host` |
| 回源环路 | 回源请求携带 `CDN-Loop`，环路返回 `508` |
| 源站地址 | 拒绝特殊地址段（回环、链路本地 / 云元数据、私网等），平台放行的除外 |

详见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 安装

### 控制台安装命令（推荐）

控制台为每个节点生成安装命令。`install.sh` 校验发布物 SHA-256 与 cosign 签名后安装 OpenResty 与 `edgeweir-node`，以固定 CA 指纹注册并启动服务；一次性 token 经 `EDGEWEIR_TOKEN` 传递。`--allow-unsigned` 仅用于开发：跳过签名校验，保留 SHA-256 校验。

### deb / rpm

前置条件：从 [OpenResty 官方仓库](https://openresty.org/cn/linux-packages.html)安装 OpenResty 并停用其服务（`sudo systemctl disable --now openresty`），OpenResty 由 agent 以子进程运行。

发布物：`edgeweir-node_<版本>_<架构>.deb`（`amd64`、`arm64`）、`edgeweir-node-<版本>-1.<架构>.rpm`（`x86_64`、`aarch64`）、`checksums.txt*`。安装前[验证发布物](#验证发布物)。

```sh
sudo apt install ./edgeweir-node_<版本>_amd64.deb   # 或 sudo dnf install ./edgeweir-node-<版本>-1.x86_64.rpm
sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
sudo rm /root/edgeweir-token
sudo systemctl enable --now edgeweir-node
```

安装包内容：`/usr/bin/edgeweir-node`、`/usr/share/edgeweir-node/lua`、systemd unit、`/etc/default/edgeweir-node`；创建非特权用户 `edgeweir` 及状态目录、缓存目录。

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<版本>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

容器以 uid 10001 运行；注册前所有域名返回 `404 unknown-host`。身份与 LKG 配置保存在 `/var/lib/edgeweir-node` 卷。

### 内核封禁

平台封禁经 nftables 丢包，需要 `nftables` 与 `CAP_NET_ADMIN`；默认不授予，封禁在 L7 执行（`403`）。

- systemd：添加 `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`，执行 `sudo systemctl daemon-reload && sudo systemctl restart edgeweir-node`。

  ```ini
  [Service]
  AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  ```

- Docker：以 `docker build --build-arg NFT_CAPABILITY=true` 构建镜像，以 `--cap-add NET_ADMIN` 启动容器。

### GeoIP

| 数据库 | 来源 | 参数 |
| --- | --- | --- |
| IPinfo Lite（国家、ASN） | 发布镜像内置 `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb`（构建时下载，同目录 `NOTICE` 记录下载时间与 sha256）；安装包与压缩包不内置 | `--geoip-ipinfo` |
| City（一级行政区） | 自行提供 | `--geoip-city` |
| ASN | 自行提供 | `--geoip-asn` |

查询在本地完成，运行时不下载，不向第三方发送客户端 IP。更新数据：拉取新镜像，或挂载新副本并设置 `EDGEWEIR_GEOIP_IPINFO`。

## 命令行

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...            # 参数同 run；systemd unit 与容器镜像入口
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # 封禁状态（JSON）；--list 列出最多 1000 条
edgeweir-node security [--control-socket PATH]        # 挑战密钥、验证码池、各站点 CC 级别（JSON）
edgeweir-node version
```

- 参数均可由环境变量 `EDGEWEIR_<参数名>` 设置（如 `--state-dir` → `EDGEWEIR_STATE_DIR`），命令行优先。
- `run` 在注册完成前每 2 秒检查状态目录，可先于 `enroll` 启动。
- `supervise` 在 `run` 之上提供签名升级、试运行与回滚。

| `enroll` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--server` | 必填 | 控制台节点通道地址，如 `https://console.example.com:8443` |
| `--ca-sha256` | 必填 | 控制台内部 CA 证书（DER）的 SHA-256，十六进制 |
| `--token-file` | 无 | 一次性 token 文件（忽略首尾空白） |
| `--token` | 无 | 一次性 token；出现在进程列表中，优先用 `EDGEWEIR_TOKEN` 或 `--token-file` |
| `--server-name` | `--server` 的主机名 | 校验的 TLS 服务器名 |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录 |
| `--force` | 关 | 替换已有身份（重新注册） |
| `--timeout` | `30s` | 注册 RPC 超时 |
| `--log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | `text`、`json` |

| `run` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--manage-nginx` | 关 | 以受监管子进程运行 OpenResty（容器与 systemd unit 开启） |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录（身份、LKG 配置） |
| `--nginx-bin` | `openresty` | OpenResty 可执行文件 |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix 目录 |
| `--nginx-user` | 无 | agent 以 root 运行时的 nginx worker 用户 |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | `edgeweir/*.lua` 所在目录 |
| `--cache-dir` | `/var/cache/edgeweir-node` | 缓存 zone 上级目录 |
| `--control-socket` | `/run/edgeweir-node/control.sock` | 数据面控制 API socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | 内部回源层 socket |
| `--origin-socket-noverify` | 回源 socket 同目录的 `origin-noverify.sock` | 不校验 TLS 的回源层 socket |
| `--edge-socket` | 控制 socket 同目录的 `edge.sock` | 本地边缘监听，所有监听启用 PROXY protocol 时供预热使用 |
| `--trusted-ca` | 系统 CA bundle | HTTPS 源站证书的校验 CA |
| `--resolv-conf` | `/etc/resolv.conf` | nginx resolver 来源 |
| `--resolver` | 无 | resolver 地址，逗号分隔；优先于 `--resolv-conf` |
| `--resolver-ipv6` | `auto` | 解析源站 AAAA：`auto`（本机有全局 IPv6 地址时）、`on`、`off` |
| `--listen-ipv6` | `auto` | 监听 IPv6：`auto`（本机可绑定 IPv6 时）、`on`、`off` |
| `--default-port` | `80` | 收到配置前的 HTTP 端口 |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-ipinfo` | `auto` | IPinfo Lite MMDB：`auto`（镜像内置时使用）、`off`、文件路径 |
| `--geoip-city` | 空 | City MMDB 路径 |
| `--geoip-asn` | 空 | ASN MMDB 路径 |
| `--cosign-bin` | `cosign` | supervise 模式的签名验证程序 |
| `--upgrade-source` | 官方 GitHub Release 下载地址 | 发布镜像地址，升级任务不可修改 |
| `--upgrade-public-key` | 空 | 发布公钥；为空时固定官方 GitHub OIDC 身份 |
| `--upgrade-allow-http` | `false` | 允许明文 HTTP 发布镜像（本地测试、隔离网络） |
| `--purge-dict-mb` | `32` | 清缓存标记存储（`lua_shared_dict edgeweir_purge`），MiB |
| `--purge-markers-per-site` | `1000` | 每站点 URL 与前缀标记上限，超出后合并为全站标记 |
| `--prefetch-budget` | `4m` | 单批预热时间上限 |
| `--ban-capacity` | `100000` | 动态封禁条数上限；超出时先淘汰最早的自动封禁 |
| `--ban-dict-mb` | `32` | 封禁存储（`lua_shared_dict edgeweir_bans`），MiB |
| `--cc-dict-mb` | `32` | CC 防护存储（`lua_shared_dict edgeweir_cc`），MiB |
| `--challenge-dict-mb` | `8` | 挑战存储（`lua_shared_dict edgeweir_challenge`），MiB |
| `--kernel-bans` | `auto` | 平台封禁写入 nftables：`auto`（`nft` 可用且有 `CAP_NET_ADMIN` 时）、`off` |
| `--nft-bin` | `nft` | nftables 可执行文件 |
| `--log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | `text`、`json` |

| 路径 / 端口 | 用途 |
| --- | --- |
| `/var/lib/edgeweir-node` | 状态目录（0700）：`node.key`（0600）、`node.crt`、`ca.crt`、`identity.json`、`config/`（LKG，目录 0700，文件 0600）、`credentials.json`（S3 源站密钥明文，0600）、`purge.json`（清缓存标记，0600）、`bans.json`（动态封禁与序号，0600）、`challenge-keys.json`（挑战凭证密钥，0600）、`nginx/`（prefix 与 `nginx.conf`） |
| `/var/cache/edgeweir-node` | 缓存 zone |
| `/run/edgeweir-node/control.sock` | 数据面控制 API（仅 unix socket） |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | 本地边缘监听与内部回源层 |
| `/usr/share/edgeweir-node/lua` | Lua 模块 |
| `/usr/share/edgeweir-node/geoip` | IPinfo Lite 数据库与 `NOTICE`（容器镜像） |
| `:80` | 收到配置前的 HTTP 监听；此后以配置为准 |

## 构建与测试

依赖：Go 1.27.1、Docker；发布另需 buf、goreleaser、syft。

```sh
make build         # 静态二进制，输出至 bin/
make vet test      # go vet ./... && go test ./...
make test-race     # race detector
make lua-test      # Lua 单元测试（OpenResty 镜像内 resty）
make docker        # 镜像；设置 IPINFO_TOKEN 时经 BuildKit secret 内置 IPinfo Lite
make e2e           # 容器冒烟测试：模拟控制台 + 节点 + whoami 源站
make proto-check   # 从 proto tag 重新生成并检查漂移
make snapshot      # goreleaser 本地快照（不签名）
```

`make e2e` 默认占用 127.0.0.1 的 28080、28081、28090。与其他 compose 项目并行时须同时指定项目名与端口：

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

开发规范与 proto 生成流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 验证发布物

发布物由 GitHub Actions 从 tag 构建，可复现（`-trimpath`，时间戳取提交时间）；容器镜像内的 IPinfo Lite 以 `NOTICE` 中的 sha256 标识。`checksums.txt` 覆盖全部压缩包、安装包与 SBOM，经 cosign keyless 签名；每个发布物附 SLSA 构建来源证明。

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

- OpenResty 引擎不含 Brotli 与 Zstd。
- 证书材料保存在 `certificates.json`（0600），主机管理员可读取。
- 统计 RPC V2 不兼容旧版控制台，控制台与节点须同步升级。
- 每个已发布站点占用固定 256 KiB 限速计数分区，每集群最多 512 个已发布站点。见[限速存储](docs/rate-limit-storage.md)。
- 自升级仅覆盖 agent 与 Lua；监督进程、cosign 与 OpenResty 随系统包或镜像升级，且优先于状态卷中较旧的自升级版本。

## 安全

- 节点私钥（ECDSA P-256）在本机生成，不离开节点；注册时按 `--ca-sha256` 固定控制台 CA。
- 注册后所有 RPC 使用 mTLS；数据面控制 API 仅监听 unix socket。
- 配置回执在应用前持久化；控制台恢复数据库后，仅经其认证的更高 revision 可推进发布序号。
- 出站连接：控制通道仅连接注册时的控制台；数据面连接已配置源站，启用 OCSP 检查时连接 OCSP 响应方。
- 控制台不保存 SSH 凭据。
- 无厂商回连，无许可证校验，无遥测。

漏洞通过 [GitHub 私密漏洞报告](https://github.com/marvinli001/edgeweir-node/security/advisories/new)提交，见 [SECURITY.md](SECURITY.md)。

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

[AGPL-3.0-only](LICENSE)，允许合规商用。开源核心与商业产品的边界见 [LICENSING.md](LICENSING.md)。

内置 GeoIP 数据：[IPinfo Lite](https://ipinfo.io/lite)，[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)。IP address data is powered by [IPinfo](https://ipinfo.io).
