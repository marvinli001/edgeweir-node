# Edgeweir 节点

[English](README.md) | 简体中文

`edgeweir-node` 是 [Edgeweir](https://edgeweir.dev) 的边缘节点。Edgeweir 是一个开源、自托管的 CDN / WAF / 边缘调度平台。每个节点由一个 Go agent 和它管理的 OpenResty 数据面组成：agent 向 Edgeweir 控制台注册，通过双向 TLS 接收配置，OpenResty 为所属集群的站点提供回源和缓存。

> **名字的由来**：Edgeweir 的名字来自「堰」（weir）。公元前 256 年前后，李冰主持修建都江堰，其中的飞沙堰位于内江的边缘：平时它让江水顺畅流向宝瓶口，灌溉成都平原；洪水来时，弯道环流把泥沙和多余的水甩过堰顶、排回外江。Edgeweir 想在网络的边缘做同样的事：放行正常流量，筛掉攻击，按需调度分流。

## 与控制台的关系

| 仓库 | 内容 |
| --- | --- |
| [edgeweir/edgeweir](https://github.com/edgeweir/edgeweir) | 控制台（控制面）：TypeScript，一个应用、一个镜像。把站点和规则编译成与引擎无关的 `NodeConfig` IR，运行内部 CA 和节点通道（默认 `:8443`）。 |
| **edgeweir/edgeweir-node**（本仓库） | 节点：Go agent `edgeweir-node` + OpenResty（Lua）。 |

两个仓库之间唯一的契约是 `edgeweir/proto` 里的 protobuf（`edgeweir.node.v1.NodeService` 和 `NodeConfig`）。本仓库用 buf 从该目录的 git tag（当前为 `proto/v0.1.0`）生成 Go 代码，从不复制 `.proto` 文件。

## 工作方式

1. **注册**：`edgeweir-node enroll` 在本机生成 ECDSA P-256 私钥（私钥从不离开节点），按安装命令里的 SHA-256 固定（pin）控制台的内部 CA，然后用一次性 token 和 CSR 换取节点证书。
2. **mTLS 通道**：之后所有 RPC 都用节点证书认证。`WatchConfig` 服务端流推送 revision 通知，另外每 30 秒轮询一次 `GetConfig` 兜底。
3. **应用配置**：快照和增量 diff 都先校验 `content_hash`，再做合法性检查，然后作为 last-known-good（LKG）配置落盘。只有结构性变更（监听端口、缓存 zone、resolver）才重新渲染 `nginx.conf`，经 `openresty -t` 检查后 reload；站点、源站、缓存规则通过本地 unix socket 热更新，不 reload。
4. **服务流量**：Lua 数据面按 `Host` 路由，用 `proxy_cache` 缓存（响应头 `X-Cache: MISS/HIT`）；未知域名返回 `404` 和 `X-Edgeweir-Error: unknown-host`。
5. **回报**：状态心跳（带已应用的 revision）、按站点按分钟的流量统计、证书自动续期。

控制台不可达时，节点继续按 LKG 配置服务。细节见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 安装

### 一键安装（推荐）

控制台会为每个节点生成安装命令：

```sh
curl -fsSL https://<控制台>/install.sh | sudo bash -s -- --token <一次性token>
```

`install.sh` 由你自己的控制台提供。它在执行任何内容之前，先下载发布物（可以由控制台镜像转发，适合访问 GitHub 慢的环境），并同时校验 SHA-256 **和** cosign 签名；然后安装 OpenResty 和 `edgeweir-node` 包，用固定的 CA 指纹完成注册并启动服务。从控制台通过 SSH 远程安装只是可选的一次性操作：凭据只用一次，不会入库。

### 手动安装（deb / rpm）

1. 从 [OpenResty 官方仓库](https://openresty.org/cn/linux-packages.html) 安装 OpenResty，并停用它自带的服务（agent 会把 OpenResty 作为子进程运行）：`sudo systemctl disable --now openresty`。
2. 从 release 页面下载 `edgeweir-node_<版本>_linux_<架构>.deb`（或 `.rpm`）和 `checksums.txt*`，并[验证发布物](#验证发布物)。
3. 安装、注册、启动：

   ```sh
   sudo apt install ./edgeweir-node_<版本>_linux_amd64.deb   # 或：sudo dnf install ./edgeweir-node-<版本>.x86_64.rpm
   sudo edgeweir-node enroll --server https://console.example.com:8443 --token <token> --ca-sha256 <sha256>
   sudo systemctl enable --now edgeweir-node
   ```

安装包包含 `/usr/bin/edgeweir-node`、`/usr/share/edgeweir-node/lua` 下的 Lua 模块、systemd unit 和 `/etc/default/edgeweir-node`，并创建非特权用户 `edgeweir`。

### Docker

```sh
docker run -d --name edgeweir-node -p 80:80 \
  -v edgeweir-node:/var/lib/edgeweir-node \
  ghcr.io/edgeweir/edgeweir-node:<版本>
docker exec edgeweir-node edgeweir-node enroll \
  --server https://console.example.com:8443 --token <token> --ca-sha256 <sha256>
```

容器启动后立即拉起 OpenResty（所有域名都返回 `404 unknown-host`），等待注册完成后开始跟随控制台。容器以 uid 10001 运行，节点身份和 LKG 配置保存在 `/var/lib/edgeweir-node` 卷里。

## 命令行

```text
edgeweir-node enroll --server URL --token TOKEN --ca-sha256 HEX [--server-name NAME] [--state-dir DIR] [--force]
edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
                  [--lua-dir DIR] [--cache-dir DIR] [--control-socket PATH] [--default-port 80] ...
edgeweir-node healthcheck [--control-socket PATH]
edgeweir-node version
```

每个参数都可以用环境变量 `EDGEWEIR_<参数名>` 设置（例如 `--state-dir` 对应 `EDGEWEIR_STATE_DIR`，`--token` 对应 `EDGEWEIR_TOKEN`），命令行参数优先。`run` 在节点注册之前每 2 秒检查一次状态目录，所以可以在 `run` 已经运行时再执行 `enroll`。

| 路径 / 端口 | 用途 |
| --- | --- |
| `/var/lib/edgeweir-node` | 状态目录：`node.key`（0600）、`node.crt`、`ca.crt`、`identity.json`、`config/`（LKG）、`nginx/`（prefix 和渲染出的 `nginx.conf`） |
| `/var/cache/edgeweir-node` | 缓存 zone |
| `/run/edgeweir-node/control.sock` | Lua 数据面的本地控制 API（只有 unix socket） |
| `/usr/share/edgeweir-node/lua` | Lua 模块 |
| `:80` | 收到配置之前的 HTTP 监听端口；之后以配置中的监听端口为准 |

## 构建与测试

需要 Go 1.27 和 Docker；做发布相关工作还需要 buf、goreleaser 和 syft。

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

proto 重新生成流程和提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 验证发布物

发布物由 GitHub Actions 从打 tag 的源码构建，构建可复现（`-trimpath`，时间戳取自提交时间）。`checksums.txt` 覆盖所有压缩包、安装包和 SBOM，并用 cosign keyless 签名；每个发布物还带有 SLSA 构建来源证明。

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/edgeweir/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify edgeweir-node_<版本>_linux_amd64.tar.gz --repo edgeweir/edgeweir-node
```

## 安全

没有 phone-home，没有授权校验，没有遥测。节点只和你注册时指定的控制台通信。漏洞请报告到 security@edgeweir.dev，详见 [SECURITY.md](SECURITY.md)。

## 许可证

[AGPL-3.0](LICENSE)。路线图见 [ROADMAP.md](ROADMAP.md)。
