# 安全策略

English summary: report vulnerabilities to security@edgeweir.dev; 90-day coordinated disclosure.

本文适用于边缘节点 `edgeweir-node`。控制面 [edgeweir/edgeweir](https://github.com/edgeweir/edgeweir) 遵循同一套信任基线，它的漏洞也请发到同一个邮箱。

## 报告漏洞

请发邮件到 **security@edgeweir.dev**。请不要开公开 issue、PR，也不要在讨论区贴细节。

邮件里请尽量包含：

- 受影响的版本：`edgeweir-node version` 的输出（控制面问题请附控制台版本）
- 复现步骤、相关配置或 PoC
- 影响：攻击者能做到什么，需要什么前提（例如是否需要已注册的节点、是否需要控制台账号）
- 是否希望署名，以及署名方式

处理流程：

1. 我们会尽快确认收到，目标 3 个工作日内。
2. 确认漏洞后，和你一起评估严重程度，商定修复计划。
3. 采用 90 天协调披露：从收到报告起 90 天内公开。如果修复版本提前发布，会提前披露。
4. 安全公告和发布说明中会致谢报告者，除非你希望匿名。

## 支持的版本

| 版本 | 是否提供安全修复 |
|---|---|
| 最新的 minor 版本 | 是 |
| 更早的版本 | 否，请升级 |

Phase 0 阶段只维护 `master` 分支和最新一次 release。

## 信任与安全基线

以下原则同时适用于 `edgeweir` 和 `edgeweir-node`。违反其中任何一条，都按安全问题处理。

- 没有任何形式的 phone-home，代码里没有授权或许可证校验。
- 遥测默认关闭，必须由运维者显式开启。节点目前完全没有遥测：状态和统计只发给运维者自己部署的控制台。
- 私钥、DNS API 密钥、SSH 凭据等敏感数据，由控制面用主密钥做信封加密后才入库。
- 所有管理操作都写审计日志（控制面）。
- 发布物全部签名，并附校验说明，见下文"验证发布物"。
- CI 构建产物与源码一一对应。构建可复现：使用 `-trimpath`，模块文件时间戳固定为提交时间，兼容 `SOURCE_DATE_EPOCH`。

## 节点侧安全设计

**身份与注册**

- 节点私钥（ECDSA P-256）在节点本地生成，保存为 `/var/lib/edgeweir-node/node.key`，权限 `0600`，从不传输。注册时只发送 CSR。
- 注册 token 一次性有效。节点先完成 TLS 握手，确认控制面内部 CA 与安装命令中的 `--ca-sha256` 一致，之后才发送 token。
- `Enroll` 返回的 CA 证书也必须与同一个 sha256 匹配，否则注册失败。
- 注册之后每个 RPC 都走 mTLS，客户端证书 CN 为节点 ID。证书自动续期。
- 控制面不保存 SSH 凭据。SSH 远程安装是可选的一次性操作，凭据用完即丢弃。

**本地攻击面**

- 本地控制 API 只监听 unix socket，从不监听 TCP。
- OpenResty 内层回源层同样只监听 unix socket。
- agent 和 OpenResty 以非特权用户运行：容器内是 `edgeweir` 用户（uid 10001）；deb/rpm 包创建系统用户 `edgeweir`，systemd unit 只授予 `CAP_NET_BIND_SERVICE`（用于监听 80/443），开启 `NoNewPrivileges`、`ProtectSystem=strict` 等文件系统和内核保护选项，详见 `packaging/systemd/edgeweir-node.service` 中的说明。
- 控制 socket 所在目录权限为 `0750`，只有服务用户能连接。

**配置处理**

- 配置在使用前校验 `content_hash`，无效的部分直接拒绝，不会带病应用。
- 从磁盘加载 last-known-good 配置时同样校验哈希。
- 客户端请求中自带的 `X-Edgeweir-*` 头会被删除，防止伪造内部头。
- `nginx.conf` 里只写入经过校验的值（端口、zone 名、大小、路径），站点等可变数据走 unix socket 进入 Lua，不拼进配置文件。

## 验证发布物

每个 release 附带：

- `checksums.txt`：所有发布文件的 sha256
- `checksums.txt.sigstore.json`：`checksums.txt` 的 cosign keyless 签名 bundle
- `*.sbom.json`：syft 生成的 SBOM
- SLSA 构建来源证明（GitHub artifact attestations）

验证步骤：

```bash
# 1. 验证 checksums.txt 的签名（cosign v3）
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/edgeweir/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. 验证下载文件的哈希
sha256sum --ignore-missing -c checksums.txt

# 3. 验证构建来源（GitHub artifact attestations）
gh attestation verify edgeweir-node_<version>_linux_amd64.tar.gz --repo edgeweir/edgeweir-node
```

容器镜像 `ghcr.io/edgeweir/edgeweir-node` 同样用 cosign keyless 签名：

```bash
cosign verify ghcr.io/edgeweir/edgeweir-node:<tag> \
  --certificate-identity-regexp '^https://github\.com/edgeweir/edgeweir-node/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

控制台提供的 `install.sh` 在执行任何内容之前，都会先完成 sha256 和 cosign 校验。控制台可以镜像转发二进制（国内访问 GitHub 较慢），但镜像的文件必须通过同样的校验。

### 为什么这很重要

GoEdge 出过官方二进制投毒事件；它的控制面还保存节点的 SSH root 凭据，2025 年 RingH23 攻击正是借此横向投毒了所有边缘节点。Edgeweir 针对这两点做了设计：发布物可以独立验证签名和来源，控制面不保存 SSH 凭据，节点私钥也从不离开节点。
