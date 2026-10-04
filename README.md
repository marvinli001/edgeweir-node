# Edgeweir Node

简体中文 | [English](README.en.md)

[![CI](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/marvinli001/edgeweir-node/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

[Edgeweir](https://github.com/marvinli001/edgeweir) 边缘节点：Go agent `edgeweir-node` 与 OpenResty（Lua）数据面。OpenResty 为自建的 edgeweir-openresty：从固定并校验过的源码构建，带 Brotli、Zstandard 与可选的 ModSecurity、OWASP CRS。

## 功能

| 领域 | 能力 |
| --- | --- |
| HTTPS 与协议 | SNI HTTPS、HTTP/2、HTTP/3、TLS 策略、HSTS、证书热轮换 |
| 压缩 | gzip、Brotli、Zstandard；按 `Accept-Encoding` 的 q 值为每个响应选一种（同 q 值 zstd > br > gzip，压缩规则可限定并排序），缓存只存一份未压缩对象 |
| 访问策略 | IP / GeoIP 名单、分阶段规则（表达式函数、动态重定向与改写、查询串编辑、批量重定向、Origin 规则与源站组、按请求覆盖站点设置、压缩规则）、WAF、限速、请求 / 响应变换，均热更新；秒级动态封禁，平台封禁可经 nftables 内核丢包 |
| OWASP CRS | 按站点的托管规则（ModSecurity v3 + CRS 4.29.0）：仅检测 / 拦截、paranoia level、异常分数阈值、排除规则、请求体检查上限；缓存命中同样检查，未启用的站点不经过 ModSecurity |
| 挑战与 CC 防护 | 四级挑战（Cookie 跳转、JS、工作量证明、图片验证码）、签名通行凭证、节点本地分级 CC、JA4 指纹 |
| 缓存与回源 | `Host` 路由、`proxy_cache`、表达式条件的缓存规则与浏览器 TTL、源站池负载均衡、HTTP/2 回源与端到端 gRPC、被动与主动健康检查、会话保持（签名 cookie）、清缓存（URL、前缀、Host、站点、Cache-Tag）、预热（URL 与 sitemap，桌面与移动变体，HTTP 与 HTTPS） |
| 四层转发 | TCP / UDP 端口转发到源站：权重、备用源站、被动健康检查与连接失败重试，连接与空闲超时，放行 / 拦截名单，每节点并发与每秒新建上限；向源站发送 PROXY protocol v1 / v2，监听可接受 PROXY protocol；增删端口 reload 时已有连接不断开，其余变更热更新；按分钟统计连接、拒绝、并发峰值与字节数 |
| 错误页 | 403 / 429 / 502 / 503 / 504 使用站点模板或内置页（中英文），可拦截源站错误；未知、停用站点的平台页；`X-Request-Id` |
| 统计与日志 | 按站点与四层应用按分钟统计（持久化、按序号续传）、Top URL / IP、采样访问日志（默认关闭） |
| 探针与主机指标 | 区域探针 `edgeweir-node probe`（不带 OpenResty）与节点兼任探针：按控制台给出的目标做 TCP、HTTP、HTTPS 探测，上报延迟与丢包；边缘监听的健康端点 `/.edgeweir/health`；心跳携带 CPU、负载、内存、出口带宽与活动连接数 |
| GeoIP | 本地 MMDB 查询；发布镜像内置 IPinfo Lite（国家、ASN） |
| 配置可靠性 | 校验后应用、激活失败回退、last-known-good（LKG）持久化；控制台不可达时按 LKG 服务 |
| 签名升级 | `supervise` 监督进程、本机固定发布源与信任锚、节点组试运行、失败自动回滚 |

## 架构

| 组件 | 职责 |
| --- | --- |
| `edgeweir-node` agent | 注册、mTLS 通道（`WatchConfig` 推送，`GetConfig` 约 30 秒轮询兜底）、配置校验与应用、任务、心跳（含主机指标）与统计上报、签名升级；控制台要求时兼任探针 |
| `edgeweir-node probe` | 区域探针：探测各节点的调度地址，经 mTLS 上报（`ProbeService`） |
| OpenResty 数据面 | 路由、缓存、回源、策略执行、四层转发（stream）；经本地 unix socket 接收站点、源站、证书、规则与四层应用的热更新 |
| [edgeweir](https://github.com/marvinli001/edgeweir) 控制台 | 控制面：内部 CA、节点通道（默认 `:8443`）、`NodeConfig` 编译与下发 |

- 契约：`edgeweir/proto` 中的 protobuf（`edgeweir.node.v1.NodeService`、`ProbeService`、`NodeConfig`），以 buf 从 git tag `proto/v0.21.0` 生成。
- 结构性变更（监听、缓存 zone、resolver、站点集合、HTTPS 站点的域名、协议与压缩设置、OWASP CRS 的加载与排除规则、四层应用的端口、协议与 PROXY protocol 设置）重新渲染 `nginx.conf`，经 `openresty -t` 后 reload，已有连接由旧 worker 服务到结束；其余变更热更新，不 reload。

| 数据面行为 | 响应 |
| --- | --- |
| 缓存状态 | `X-Cache: MISS` / `HIT` / `BYPASS` |
| 未知域名 | `404` 平台页或内置页，`X-Edgeweir-Error: unknown-host` |
| 停用站点的域名 | `503` 平台页或内置页，`X-Edgeweir-Error: site-disabled` |
| 请求 ID | `X-Request-Id`：客户端的合法值或节点生成，错误页与采样日志使用同一个 |
| `Cache-Tag` | 默认不转发给客户端（站点可保留），节点按它索引缓存对象 |
| 回源环路 | 回源请求携带 `CDN-Loop`，环路返回 `508` |
| 源站地址 | 拒绝特殊地址段（回环、链路本地 / 云元数据、私网等），平台放行的除外 |
| CRS 拦截 | `403` 错误页，`X-Edgeweir-Error: waf-blocked` |
| 压缩 | `Content-Encoding: zstd` / `br` / `gzip`，`Vary: Accept-Encoding` |
| 四层连接被拒绝 | 名单或连接上限拒绝时不转发任何数据：TCP 连接被关闭，UDP 数据报被丢弃 |
| 健康端点 | 任意 Host 的 `GET /.edgeweir/health` 在站点逻辑之前返回 `200 ok`（不缓存、不计入统计与日志）；TLS 对 SNI `health.edgeweir.invalid` 或无 SNI 使用节点自签名的健康证书，这样的连接只能访问健康端点（其他请求 `421`） |

详见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 安装

### 控制台安装命令（推荐）

控制台为每个节点生成安装命令。`install.sh` 校验发布物 SHA-256 与 cosign 签名后安装 `edgeweir-openresty`、`edgeweir-openresty-modsecurity` 与 `edgeweir-node`，以固定 CA 指纹注册并启动服务；一次性 token 经 `EDGEWEIR_TOKEN` 传递。`--allow-unsigned` 仅用于开发：跳过签名校验，保留 SHA-256 校验。

### deb / rpm

系统要求：glibc 2.34 及以上（RHEL / Rocky / AlmaLinux 9、Debian 12、Ubuntu 22.04 及更新版本），amd64 或 arm64。OpenResty 由 agent 以子进程运行；若装有 OpenResty 官方包，停用其服务（`sudo systemctl disable --now openresty`）。

发布物：`edgeweir-node_<版本>_<架构>.deb`（`amd64`、`arm64`）、`edgeweir-node-<版本>-1.<架构>.rpm`（`x86_64`、`aarch64`）、`edgeweir-openresty_1.31.1.1-2_<架构>.deb` / `edgeweir-openresty-1.31.1.1-2.<架构>.rpm`、同名的 `edgeweir-openresty-modsecurity` 包、`checksums.txt*`。安装前[验证发布物](#验证发布物)。

```sh
sudo apt install ./edgeweir-openresty_1.31.1.1-2_amd64.deb ./edgeweir-openresty-modsecurity_1.31.1.1-2_amd64.deb \
  ./edgeweir-node_<版本>_amd64.deb
# 或 sudo dnf install ./edgeweir-openresty-1.31.1.1-2.x86_64.rpm ./edgeweir-openresty-modsecurity-1.31.1.1-2.x86_64.rpm \
#      ./edgeweir-node-<版本>-1.x86_64.rpm
sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
sudo rm /root/edgeweir-token
sudo systemctl enable --now edgeweir-node
```

安装包内容：`edgeweir-node` 为 `/usr/bin/edgeweir-node`、`/usr/share/edgeweir-node/lua`、systemd unit、`/etc/default/edgeweir-node`，创建非特权用户 `edgeweir` 及状态目录、缓存目录；`edgeweir-openresty` 为 `/usr/lib/edgeweir-openresty`（OpenResty、LuaJIT、Brotli、Zstandard）；`edgeweir-openresty-modsecurity`（可选）为 ModSecurity 模块与 `/usr/share/edgeweir-openresty/crs`，没有它时站点不能在该节点启用 OWASP CRS。第三方组件的许可证见 `/usr/share/doc/edgeweir-openresty/NOTICE`。

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<版本>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

容器以 uid 10001 运行；注册前所有域名返回 `404 unknown-host`。身份与 LKG 配置保存在 `/var/lib/edgeweir-node` 卷。四层应用使用集群端口池里的端口：容器需发布这些端口（如 `-p 9000:9000 -p 9000:9000/udp`）或使用 host 网络，主机防火墙同样放行端口池。

### 区域探针

探针从所在区域探测各节点，不带 OpenResty，不监听端口。在控制台创建探针得到一次性 token，首次启动时注册（私钥在本机生成，0600），之后只用保存的身份。

容器（节点镜像，入口改为 `probe`）：

```yaml
services:
  probe:
    image: ghcr.io/marvinli001/edgeweir-node:<版本>
    entrypoint: ["/usr/local/bin/edgeweir-node", "probe"]
    environment:
      EDGEWEIR_STATE_DIR: /var/lib/edgeweir-probe
      EDGEWEIR_SERVER: https://console.example.com:8443
      EDGEWEIR_CA_SHA256: <sha256>
      EDGEWEIR_TOKEN: <探针 token>   # 只在首次启动时使用
    volumes:
      - probe-state:/var/lib/edgeweir-probe
    healthcheck:
      disable: true
    restart: unless-stopped
volumes:
  probe-state:
```

systemd（deb / rpm 已包含 `edgeweir-probe.service`，默认不启用）：

```sh
sudo tee /etc/default/edgeweir-probe >/dev/null <<'CONF'
EDGEWEIR_SERVER=https://console.example.com:8443
EDGEWEIR_CA_SHA256=<sha256>
EDGEWEIR_TOKEN=<探针 token>
CONF
sudo chmod 600 /etc/default/edgeweir-probe
sudo systemctl enable --now edgeweir-probe
```

节点也可以兼任探针：控制台为节点开启后，agent 以节点身份运行同样的探测，不探测自己。

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

### WebSocket 入口

控制台只能经 HTTPS 访问时（如 Render），节点经控制台 Web 端口上的 WebSocket 入口连接节点通道：`--server wss://console.example.com`；明文 HTTP 的控制台为 `ws://`。

| 项目 | 说明 |
| --- | --- |
| 入口 | `<地址>/node-channel`，WebSocket 子协议 `edgeweir-node-channel`；地址不带路径 |
| TLS | 节点通道的 TLS 在 WebSocket 内运行，由控制台终结；CA 指纹固定与 mTLS 与 `https://` 地址相同。`wss://` 地址本身的证书按系统根证书校验 |
| 代理 | WebSocket 握手遵循 `HTTPS_PROXY`、`HTTP_PROXY`、`NO_PROXY` |
| 版本 | 0.2.0 起 |

## 命令行

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] [--ban-capacity 100000] [--kernel-bans auto] ...
edgeweir-node supervise --manage-nginx ...            # 参数同 run；systemd unit 与容器镜像入口
EDGEWEIR_TOKEN=TOKEN edgeweir-node probe --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR]
edgeweir-node probe [--state-dir DIR]                 # 已注册的探针
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node bans [--control-socket PATH] [--list]   # 封禁状态（JSON）；--list 列出最多 1000 条
edgeweir-node security [--control-socket PATH]        # 挑战密钥、验证码池、各站点 CC 级别（JSON）
edgeweir-node version
```

- 参数均可由环境变量 `EDGEWEIR_<参数名>` 设置（如 `--state-dir` → `EDGEWEIR_STATE_DIR`），命令行优先。
- `run` 在注册完成前每 2 秒检查状态目录，可先于 `enroll` 启动。
- `supervise` 在 `run` 之上提供签名升级、试运行与回滚，并由它运行 OpenResty：升级或重启 agent 进程不重启 OpenResty。升级任务不能安装比当前更旧的版本（`--upgrade-allow-downgrade` 放行）。
- `probe` 运行区域探针：首次运行用一次性探针 token 注册（控制台不可达时退避重试），已注册后忽略 token；缺少注册参数时退出码 2。

| `enroll` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--server` | 必填 | 控制台节点通道地址：节点通道端口 `https://console.example.com:8443`，或控制台 Web 端口上的 WebSocket 入口 `wss://console.example.com`（明文 HTTP 的控制台为 `ws://`），见下方 [WebSocket 入口](#websocket-入口) |
| `--ca-sha256` | 必填 | 控制台内部 CA 证书（DER）的 SHA-256，十六进制 |
| `--token-file` | 无 | 一次性 token 文件（忽略首尾空白） |
| `--token` | 无 | 一次性 token；出现在进程列表中，优先用 `EDGEWEIR_TOKEN` 或 `--token-file` |
| `--server-name` | `--server` 的主机名 | 校验的 TLS 服务器名 |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录 |
| `--force` | 关 | 替换已有身份（重新注册）；`run` 运行时拒绝，先停止节点（如 `systemctl stop edgeweir-node`） |
| `--timeout` | `30s` | 注册 RPC 超时 |
| `--log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | `text`、`json` |

| `probe` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--server` | 无（首次运行必填） | 控制台节点通道地址，格式同 `enroll` |
| `--ca-sha256` | 无（首次运行必填） | 控制台内部 CA 证书（DER）的 SHA-256，十六进制 |
| `--token-file` | 无 | 一次性探针 token 文件（首次运行） |
| `--token` | 无 | 一次性探针 token（首次运行）；出现在进程列表中，优先用 `EDGEWEIR_TOKEN` 或 `--token-file` |
| `--server-name` | `--server` 的主机名 | 校验的 TLS 服务器名 |
| `--state-dir` | `/var/lib/edgeweir-probe` | 探针身份目录，与节点的分开 |
| `--timeout` | `30s` | 每个控制台 RPC 的超时 |
| `--log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | `text`、`json` |

| `run` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--manage-nginx` | 关 | 以受监管子进程运行 OpenResty（容器与 systemd unit 开启） |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录（身份、LKG 配置） |
| `--nginx-bin` | `/usr/lib/edgeweir-openresty/nginx/sbin/nginx`（已安装时），否则 `PATH` 中的 `openresty` | OpenResty 可执行文件 |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix 目录 |
| `--nginx-user` | 无 | agent 以 root 运行时的 nginx worker 用户 |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | `edgeweir/*.lua` 所在目录 |
| `--cache-dir` | `/var/cache/edgeweir-node` | 缓存 zone 上级目录 |
| `--control-socket` | `/run/edgeweir-node/control.sock` | 数据面控制 API socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | 内部回源层 socket；以 HTTP/2 回源与 gRPC 的回源层在同目录（`origin-h2.sock`、`origin-grpc.sock` 及其 `origin-noverify-*` 版本） |
| `--origin-socket-noverify` | 回源 socket 同目录的 `origin-noverify.sock` | 不校验 TLS 的回源层 socket |
| `--edge-socket` | 控制 socket 同目录的 `edge.sock` | 预热专用的本地边缘监听（同目录的 `edge-tls.sock` 是其 TLS 版本，有 HTTPS 监听时启用）；不受封禁、CC、挑战与拒绝规则影响，不计入统计 |
| `--l4-socket` | 控制 socket 同目录的 `l4.sock` | stream 子系统的控制中继；控制 API 把四层应用的请求转给它 |
| `--trusted-ca` | 系统 CA bundle | HTTPS 源站证书的校验 CA（回源与主动健康检查） |
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
| `--upgrade-allow-downgrade` | `false` | 允许升级任务安装比当前更旧的版本（supervise 模式） |
| `--sites-dict-mb` | `64` | 站点表存储（`lua_shared_dict edgeweir_sites`：当前与上一版站点表，含错误页模板），MiB |
| `--stats-dict-mb` | `16` | 统计计数存储（`lua_shared_dict edgeweir_stats`：各站点每分钟计数，agent 取走前保存），MiB |
| `--purge-dict-mb` | `32` | 清缓存标记存储（`lua_shared_dict edgeweir_purge`），MiB |
| `--purge-markers-per-site` | `1000` | 每站点 URL 与前缀标记上限，超出后合并为全站标记 |
| `--purge-tags-per-site` | `5000` | 每站点标签标记上限，超出后该站点的标记合并为全站标记 |
| `--prefetch-budget` | `4m` | 单批预热时间上限 |
| `--ban-capacity` | `100000` | 动态封禁条数上限；超出时先淘汰最早的自动封禁 |
| `--ban-dict-mb` | `32` | 封禁存储（`lua_shared_dict edgeweir_bans`），MiB |
| `--cc-dict-mb` | `32` | CC 防护存储（`lua_shared_dict edgeweir_cc`），MiB |
| `--challenge-dict-mb` | `8` | 挑战存储（`lua_shared_dict edgeweir_challenge`），MiB |
| `--tag-dict-mb` | `64` | Cache-Tag 索引（`lua_shared_dict edgeweir_tags`：缓存对象的标签与键时间，按标签清缓存用），MiB |
| `--rate-limit-dict-kb` | `256` | 每个已发布站点的限速计数存储（`lua_shared_dict edgeweir_rate_<站点 id 十六进制>`），KiB，64–65536；满时新计数放行 |
| `--l4-dict-mb` | `32` | 四层应用表存储（`lua_shared_dict edgeweir_l4`：当前与上一版四层应用表，含所用 IP 名单），MiB |
| `--stream-shutdown-timeout` | `0` | reload 后旧 worker 仍在服务的连接（四层长连接、WebSocket 等）在这段时间后关闭（`worker_shutdown_timeout`）；`0` 表示一直服务到连接结束 |
| `--kernel-bans` | `auto` | 平台封禁写入 nftables：`auto`（`nft` 可用且有 `CAP_NET_ADMIN` 时）、`off` |
| `--nft-bin` | `nft` | nftables 可执行文件 |
| `--modsecurity-module` | `auto` | ModSecurity-nginx 动态模块：`auto`（`--nginx-bin` 所属 edgeweir-openresty 的 `modules/` 目录）、文件路径、`off`；只在有站点启用 OWASP CRS 时加载 |
| `--crs-dir` | `/usr/share/edgeweir-openresty/crs` | OWASP CRS 目录（`crs-setup.conf`、`rules/`），`unicode.mapping` 取自同级 `modsecurity/` |
| `--log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `--log-format` | `text` | `text`、`json` |

| 路径 / 端口 | 用途 |
| --- | --- |
| `/var/lib/edgeweir-node` | 状态目录（0700）：`node.key`（0600）、`node.crt`、`ca.crt`、`identity.json`、`config/`（LKG，目录 0700，文件 0600）、`credentials.json`（S3 源站密钥明文，0600）、`purge.json`（清缓存标记，0600）、`bans.json`（动态封禁与序号，0600）、`challenge-keys.json`（挑战凭证密钥，0600）、`health.crt` / `health.key`（健康证书，0600）、`nginx/`（prefix 与 `nginx.conf`） |
| `/var/lib/edgeweir-probe` | 探针状态目录（0700）：`probe.key`（0600）、`probe.crt`、`ca.crt`、`probe.json` |
| `/var/cache/edgeweir-node` | 缓存 zone |
| `/run/edgeweir-node/control.sock` | 数据面控制 API（仅 unix socket） |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock`、`origin[-noverify]-{h2,grpc}.sock` | 本地边缘监听与内部回源层 |
| `/run/edgeweir-node/l4.sock` | stream 子系统的控制中继（有四层应用时） |
| `/usr/share/edgeweir-node/lua` | Lua 模块 |
| `/usr/share/edgeweir-node/geoip` | IPinfo Lite 数据库与 `NOTICE`（容器镜像） |
| `/usr/lib/edgeweir-openresty` | OpenResty（`nginx/sbin/nginx`），ModSecurity 模块在 `modules/` |
| `/usr/share/edgeweir-openresty/crs` | OWASP CRS |
| `:80` | 收到配置前的 HTTP 监听；此后以配置为准 |

## 构建与测试

依赖：Go 1.27.1、Docker；发布另需 buf、goreleaser、syft。

```sh
make build         # 静态二进制，输出至 bin/
make vet test      # go vet ./... && go test ./...
make test-race     # race detector
make lua-test      # Lua 单元测试（OpenResty 镜像内 resty）
make docker        # 镜像（含 edgeweir-openresty 的构建）；设置 IPINFO_TOKEN 时经 BuildKit secret 内置 IPinfo Lite
make openresty-packages ARCH=arm64   # edgeweir-openresty 的 deb / rpm 与 SBOM，输出至 out/openresty/
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

发布物由 GitHub Actions 从 tag 构建，可复现（`-trimpath`，时间戳取提交时间）；容器镜像内的 IPinfo Lite 以 `NOTICE` 中的 sha256 标识。edgeweir-openresty 的包从 `packaging/openresty/sources.lock` 固定的源码构建：每个源码校验 SHA-256，上游有签名的另按固定公钥校验 PGP 签名，同一输入的构建结果逐字节相同。`checksums.txt` 覆盖全部压缩包、安装包（含 edgeweir-openresty）与 SBOM，经 cosign keyless 签名；每个发布物附 SLSA 构建来源证明。

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

- 启用 OWASP CRS 的站点每个请求约多 0.5 ms CPU，请求体在回源前读完再检查，响应体不检查（见 ARCHITECTURE.md §3.18）。
- 证书材料保存在 `certificates.json`（0600），主机管理员可读取。
- 统计 RPC V2 不兼容旧版控制台，控制台与节点须同步升级。
- 每个已发布站点占用固定 256 KiB 限速计数分区，每集群最多 512 个已发布站点。见[限速存储](docs/rate-limit-storage.md)。
- 自升级仅覆盖 agent 与 Lua；监督进程、cosign 与 OpenResty 随系统包或镜像升级，且优先于状态卷中较旧的自升级版本。

## 安全

- 节点私钥（ECDSA P-256）在本机生成，不离开节点；注册时按 `--ca-sha256` 固定控制台 CA。
- 注册后所有 RPC 使用 mTLS；数据面控制 API 仅监听 unix socket。
- 配置回执在应用前持久化；控制台恢复数据库后，仅经其认证的更高 revision 可推进发布序号。
- 出站连接：控制通道仅连接注册时的控制台；数据面连接已配置源站，agent 探测开启主动健康检查的源站（同一地址策略），启用 OCSP 检查时连接 OCSP 响应方；探针（含兼任探针的节点）连接控制台给出的节点地址。
- 探针私钥同样在本机生成（0600），首次注册前按 `--ca-sha256` 固定 CA；HTTPS 探测不校验节点的自签名健康证书，只判断可达。
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
