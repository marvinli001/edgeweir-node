# Edgeweir 节点

[English](README.md) | 简体中文

`edgeweir-node` 是 [Edgeweir](https://github.com/marvinli001/edgeweir) 的边缘节点。Edgeweir 是一个开源、自托管的 CDN / WAF / 边缘调度平台。每个节点由一个 Go agent 和它管理的 OpenResty 数据面组成：agent 向 Edgeweir 控制台注册，通过双向 TLS 接收配置，OpenResty 为所属集群的站点提供回源和缓存。

> **名字的由来**：Edgeweir 的名字来自「堰」（weir）。公元前 256 年前后，李冰主持修建都江堰，其中的飞沙堰位于内江的边缘：平时它让江水顺畅流向宝瓶口，灌溉成都平原；洪水来时，弯道环流把泥沙和多余的水甩过堰顶、排回外江。Edgeweir 想在网络的边缘做同样的事：放行正常流量，筛掉攻击，按需调度分流。

## 与控制台的关系

| 仓库 | 内容 |
| --- | --- |
| [edgeweir/edgeweir](https://github.com/marvinli001/edgeweir) | 控制台（控制面）：TypeScript，一个应用、一个镜像。把站点和规则编译成与引擎无关的 `NodeConfig` IR，运行内部 CA 和节点通道（默认 `:8443`）。 |
| **edgeweir/edgeweir-node**（本仓库） | 节点：Go agent `edgeweir-node` + OpenResty（Lua）。 |

两个仓库之间唯一的契约是 `edgeweir/proto` 里的 protobuf（`edgeweir.node.v1.NodeService` 和 `NodeConfig`）。本仓库用 buf 从该目录的 git tag（当前为 `proto/v0.6.0`）生成 Go 代码，从不复制 `.proto` 文件。

## 当前状态

M3 已加入 SNI HTTPS、HTTP/2、HTTP/3、TLS 策略、HSTS 和 Gzip。证书轮换热更新；结构性策略变更验证后重载，激活失败会恢复旧配置。当前引擎不提供 Brotli 和 Zstd。证书材料保存在 0600 的 `certificates.json` 中，主机管理员仍可读取。详见 [HTTPS 指南](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/https.md)。

M4 已加入 IP/GeoIP 名单、分阶段规则、WAF、限速及请求/响应变换，均走热更新。GeoIP 读取本地 MMDB，不向第三方发送客户 IP。详见 [规则指南](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/rules.md)。

M5 已加入统计批次持久化、回执丢失和重启后的序号恢复，以及有界的 Top URL/IP 估算。新节点不回退到会重复计数的旧统计 RPC；控制面与节点应一同升级。

目前没有正式二进制发布，下方安装说明描述的是发布流程。当前评估请从源码构建；MVP 尚不适合生产使用。

## 工作方式

1. **注册**：`edgeweir-node enroll` 在本机生成 ECDSA P-256 私钥（私钥从不离开节点），按安装命令里的 SHA-256 固定（pin）控制台的内部 CA，然后用一次性 token 和 CSR 换取节点证书。
2. **mTLS 通道**：之后所有 RPC 都用节点证书认证。`WatchConfig` 服务端流推送 revision 通知，另外约每 30 秒轮询一次 `GetConfig` 兜底（间隔带 ±20% 的随机抖动，避免节点同时轮询）。
3. **应用配置**：快照和增量 diff 都先校验 `content_hash`，再做合法性检查。只有结构性变更（监听端口、缓存 zone、resolver）才重新渲染 `nginx.conf`，经 `openresty -t` 检查后 reload；站点、源站、缓存规则通过本地 unix socket 热更新，不 reload。应用成功的配置作为 last-known-good（LKG）配置落盘。
4. **服务流量**：Lua 数据面按 `Host` 路由，用 `proxy_cache` 缓存（响应头 `X-Cache: MISS/HIT/BYPASS`），在源站池之间负载均衡并做被动健康检查；未知域名返回 `404` 和 `X-Edgeweir-Error: unknown-host`。源站不能指向特殊地址段（回环、链路本地/云元数据、私网等），除非平台管理员放行；发往源站的每个请求都带 `CDN-Loop`，回环请求以 `508` 结束。
5. **任务与回报**：清缓存和预热任务、状态心跳（带已应用的 revision 和源站健康状态）、按站点按分钟的流量统计、证书自动续期。

控制台不可达时，节点继续按 LKG 配置服务。细节见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 安装

### 一键安装（推荐）

控制台会为每个节点生成安装命令。`install.sh` 由你自己的控制台提供。它在执行任何内容之前，先下载发布物（可以由控制台镜像转发，适合访问 GitHub 慢的环境），并同时校验 SHA-256 **和** cosign 签名（唯一的例外是仅供开发使用的 `--allow-unsigned`：它跳过签名校验，SHA-256 照常校验）；然后安装 OpenResty 和 `edgeweir-node` 包，用固定的 CA 指纹完成注册（一次性 token 通过 `EDGEWEIR_TOKEN` 环境变量传递，不出现在命令行上）并启动服务。控制台从不保存 SSH 凭据。

### 手动安装（deb / rpm）

1. 从 [OpenResty 官方仓库](https://openresty.org/cn/linux-packages.html) 安装 OpenResty，并停用它自带的服务（agent 会把 OpenResty 作为子进程运行）：`sudo systemctl disable --now openresty`。
2. 从 release 页面下载 `edgeweir-node_<版本>_<架构>.deb`（`amd64`、`arm64`）或 `edgeweir-node-<版本>-1.<架构>.rpm`（`x86_64`、`aarch64`）和 `checksums.txt*`，并[验证发布物](#验证发布物)。
3. 安装、注册、启动：

   ```sh
   sudo apt install ./edgeweir-node_<版本>_amd64.deb   # 或：sudo dnf install ./edgeweir-node-<版本>-1.x86_64.rpm
   # 用 token 文件，一次性 token 不会出现在进程列表里
   sudo install -m 0600 /dev/stdin /root/edgeweir-token <<< '<token>'
   sudo edgeweir-node enroll --server https://console.example.com:8443 --token-file /root/edgeweir-token --ca-sha256 <sha256>
   sudo rm /root/edgeweir-token
   sudo systemctl enable --now edgeweir-node
   ```

安装包包含 `/usr/bin/edgeweir-node`、`/usr/share/edgeweir-node/lua` 下的 Lua 模块、systemd unit 和 `/etc/default/edgeweir-node`，创建非特权用户 `edgeweir` 以及属于它的状态目录和缓存目录。

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/marvinli001/edgeweir-node:<版本>
read -rs EDGEWEIR_TOKEN && export EDGEWEIR_TOKEN   # 粘贴一次性 token
docker exec -e EDGEWEIR_TOKEN edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --ca-sha256 <sha256>
```

容器启动后立即拉起 OpenResty（所有域名都返回 `404 unknown-host`），等待注册完成后开始跟随控制台。容器以 uid 10001 运行，节点身份和 LKG 配置保存在 `/var/lib/edgeweir-node` 卷里。

## 命令行

```text
EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...   # --token TOKEN 仍可用，但会出现在 ps 里
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80]
                  [--trusted-ca FILE] [--purge-dict-mb 32] [--purge-markers-per-site 1000]
                  [--prefetch-budget 4m] [--edge-socket PATH] ...
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node version
```

每个参数都可以用环境变量 `EDGEWEIR_<参数名>` 设置（例如 `--state-dir` 对应 `EDGEWEIR_STATE_DIR`，`--token` 对应 `EDGEWEIR_TOKEN`，`--token-file` 对应 `EDGEWEIR_TOKEN_FILE`），命令行参数优先。`run` 在节点注册之前每 2 秒检查一次状态目录，所以可以在 `run` 已经运行时再执行 `enroll`。

| `enroll` 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--server` | 必填 | 控制台节点通道地址，例如 `https://console.example.com:8443` |
| `--ca-sha256` | 必填 | 安装命令里的控制台内部 CA 证书（DER）SHA-256，十六进制 |
| `--token-file` | 无 | 从这个文件读取一次性 token（去掉首尾空白） |
| `--token` | 无 | 直接给出一次性 token；会出现在进程列表里，优先用 `EDGEWEIR_TOKEN` 或 `--token-file` |
| `--server-name` | `--server` 的主机名 | 校验的 TLS 服务器名 |
| `--state-dir` | `/var/lib/edgeweir-node` | 保存节点身份的状态目录 |
| `--force` | 关 | 替换已有身份（重新注册） |
| `--timeout` | `30s` | 注册 RPC 的超时 |
| `--log-level` | `info` | 日志级别：`debug`、`info`、`warn` 或 `error` |
| `--log-format` | `text` | 日志格式：`text` 或 `json` |

| `run` 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--manage-nginx` | 关 | 把 OpenResty 作为受监管的子进程运行（容器和 systemd 单元都开启） |
| `--state-dir` | `/var/lib/edgeweir-node` | 状态目录（身份、last-known-good 配置） |
| `--nginx-bin` | `openresty` | OpenResty 可执行文件 |
| `--nginx-prefix` | `<state-dir>/nginx` | nginx prefix 目录 |
| `--nginx-user` | 无 | agent 以 root 运行时 nginx worker 使用的用户（更好的做法是用非特权用户运行 agent） |
| `--lua-dir` | `/usr/share/edgeweir-node/lua` | 存放 `edgeweir/*.lua` 的目录 |
| `--cache-dir` | `/var/cache/edgeweir-node` | 缓存 zone 的上级目录 |
| `--control-socket` | `/run/edgeweir-node/control.sock` | 数据面控制 API 的 unix socket |
| `--origin-socket` | `/run/edgeweir-node/origin.sock` | 内部回源层的 unix socket |
| `--origin-socket-noverify` | 回源 socket 旁的 `origin-noverify.sock` | 不校验 TLS 的回源层 unix socket |
| `--edge-socket` | 控制 socket 旁的 `edge.sock` | 所有监听都要求 PROXY protocol 时，预热使用的本地边缘监听 |
| `--trusted-ca` | 系统 CA bundle | 校验 HTTPS 源站证书用的 CA |
| `--resolv-conf` | `/etc/resolv.conf` | 从中读取 nginx resolver 的 resolv.conf |
| `--resolver` | 无 | 逗号分隔的 resolver 地址（优先于 `--resolv-conf`） |
| `--resolver-ipv6` | `auto` | 为源站解析 AAAA 记录：`auto`（本机有全局 IPv6 地址时）、`on` 或 `off` |
| `--listen-ipv6` | `auto` | 同时监听 IPv6：`auto`（本机能绑定 IPv6 时）、`on` 或 `off` |
| `--default-port` | `80` | 收到配置之前提供服务的 HTTP 端口 |
| `--worker-processes` | `auto` | nginx `worker_processes` |
| `--geoip-city` | empty | 运维者提供的 MMDB 路径；为空时不启用对应能力 |
| `--geoip-asn` | empty | 运维者提供的 MMDB 路径；为空时不启用对应能力 |
| `--purge-dict-mb` | `32` | 清缓存标记存储（`lua_shared_dict edgeweir_purge`）的大小，单位 MiB |
| `--purge-markers-per-site` | `1000` | 每个站点的 URL 与前缀标记上限，超过后合并为一个全站标记 |
| `--prefetch-budget` | `4m` | 一次拉取的预热任务可用的时间 |
| `--log-level` | `info` | 日志级别：`debug`、`info`、`warn` 或 `error` |
| `--log-format` | `text` | 日志格式：`text` 或 `json` |

| 路径 / 端口 | 用途 |
| --- | --- |
| `/var/lib/edgeweir-node` | 状态目录（0700）：`node.key`（0600）、`node.crt`、`ca.crt`、`identity.json`、`config/`（LKG，目录 0700，文件 0600）、`credentials.json`（S3 源站密钥明文，0600）、`purge.json`（清缓存标记，0600）、`nginx/`（prefix 和渲染出的 `nginx.conf`） |
| `/var/cache/edgeweir-node` | 缓存 zone |
| `/run/edgeweir-node/control.sock` | Lua 数据面的本地控制 API（只有 unix socket） |
| `/run/edgeweir-node/{edge,origin,origin-noverify}.sock` | 本地边缘监听和内部回源层 |
| `/usr/share/edgeweir-node/lua` | Lua 模块 |
| `:80` | 收到配置之前的 HTTP 监听端口；之后以配置中的监听端口为准 |

## 构建与测试

需要 Go 1.27.1 和 Docker；做发布相关工作还需要 buf、goreleaser 和 syft。

```sh
make build         # 静态二进制输出到 bin/
make vet test      # go vet ./... && go test ./...
make test-race     # 带 race detector 跑测试
make lua-test      # 在 OpenResty 镜像里用 resty 跑 Lua 单元测试
make docker        # docker build -t edgeweir-node:dev .
make e2e           # 容器冒烟测试：假控制台 + 节点 + whoami 源站
make proto-check   # 从 proto git tag 重新生成，与已提交代码不一致则失败
make snapshot      # goreleaser release --snapshot --clean（不签名）
```

`make e2e` 在 127.0.0.1 上发布宿主机端口，默认 28080（节点）、28081（PROXY protocol 监听）和 28090（假控制台的辅助接口）。`COMPOSE_PROJECT_NAME` 只能隔开容器、网络和卷；要和其他 compose 项目（或另一次运行）同时跑，还要用 `E2E_NODE_PORT`、`E2E_PP_PORT`、`E2E_HELPER_PORT` 换成空闲端口：

```sh
COMPOSE_PROJECT_NAME=node-e2e-2 E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
```

proto 重新生成流程和提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 验证发布物

发布物由 GitHub Actions 从打 tag 的源码构建，构建可复现（`-trimpath`，时间戳取自提交时间）。`checksums.txt` 覆盖所有压缩包、安装包和 SBOM，并用 cosign keyless 签名；每个发布物还带有 SLSA 构建来源证明。

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/marvinli001/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<版本>_linux_amd64.tar.gz --repo marvinli001/edgeweir-node
```

## 安全

没有 phone-home，没有授权校验，没有遥测。节点只和你注册时指定的控制台通信。漏洞请报告到 security@edgeweir.dev，详见 [SECURITY.md](SECURITY.md)。

## 许可证

[AGPL-3.0](LICENSE)。路线图见 [ROADMAP.md](ROADMAP.md)。

M6 采样访问日志已接入（proto/v0.6.0）：默认关闭，不记录查询参数、请求头或正文，使用有界私有队列和持久批次确认。详见[日志与存储指南](https://github.com/marvinli001/edgeweir/blob/master/docs/guide/access-logs.md)。节点签名自升级仍在实施。
