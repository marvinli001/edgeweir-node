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

1.0 之前只维护 `master` 分支和最新一次 release。

## 信任与安全基线

以下原则同时适用于 `edgeweir` 和 `edgeweir-node`。违反其中任何一条，都按安全问题处理。

- 没有任何形式的 phone-home，代码里没有授权或许可证校验。
- 遥测默认关闭，必须由运维者显式开启。节点目前完全没有遥测：状态和统计只发给运维者自己部署的控制台。
- 私钥、DNS API 密钥、源站凭据等敏感数据，由控制面用主密钥做信封加密后才入库；控制面从不保存 SSH 凭据。
- 所有管理操作都写审计日志（控制面）。
- 发布物全部签名，并附校验说明，见下文"验证发布物"。
- CI 构建产物与源码一一对应。构建可复现：使用 `-trimpath`，模块文件时间戳固定为提交时间，兼容 `SOURCE_DATE_EPOCH`。

## 节点侧安全设计

**身份与注册**

- 节点私钥（ECDSA P-256）在节点本地生成，保存为 `/var/lib/edgeweir-node/node.key`，权限 `0600`，从不传输。注册时只发送 CSR。
- 注册 token 一次性有效。节点先完成 TLS 握手，确认控制面内部 CA 与安装命令中的 `--ca-sha256` 一致，之后才发送 token。
- token 通过 `EDGEWEIR_TOKEN` 环境变量（`install.sh` 的做法）或 `--token-file` 传给 `edgeweir-node enroll`，不出现在进程列表里；`--token` 仍可用，但同机其他用户能在 `ps` 里看到它，使用时会打印警告。读取后环境变量被删除，不传给子进程。
- `Enroll` 返回的 CA 证书也必须与同一个 sha256 匹配，否则注册失败。
- 注册之后每个 RPC 都走 mTLS，客户端证书 CN 为节点 ID。证书自动续期。
- 控制面绝不保存 SSH 凭据（没有保存的选项），也没有 SSH 远程安装：节点只通过控制台生成的一次性安装命令（或手动安装）接入，由节点主动注册。

**本机保存的敏感文件**

状态目录 `/var/lib/edgeweir-node` 权限 `0700`，属于服务用户。其中：

- `node.key`（0600）：节点私钥。
- `credentials.json`（0600）：当前配置引用的 S3 源站凭据，access key 和 secret key 是**明文**。它让节点在控制面不可达时重启后仍能为 S3 源站签名；凭据只经 mTLS 的 `GetOriginCredentials` 获取，不进入配置和 LKG，不再被引用时从文件中删除。能读取该文件的人可以访问对应的存储桶，请只授予只读的最小权限。
- `purge.json`（0600）：清缓存标记和任务时间，不含敏感数据。文件存在但无法读取或解析时，节点在下一次应用配置时给每个站点加一个全站标记（宁可多刷）；文件缺失则视为没有标记，已清除的内容会重新可见，所以不要删除它。
- `config/`（目录 0700，`current.binpb`、`previous.binpb` 为 0600）：last-known-good 配置及其备份，不含凭据。

**源站与回源**

- 源站不能指向特殊地址段（回环、链路本地/云元数据、私网、CGNAT、文档、基准测试、组播、保留地址，IPv4 映射与 NAT64 地址按内嵌 IPv4 判断），除非平台管理员把它放进允许清单（`origin_allowed_cidrs`）。配置里的 IP 字面量和每个 DNS 解析结果都会检查，租户无法用源站读取云元数据或访问节点所在网络。完整列表见 ARCHITECTURE.md §3.5。
- 发往源站的请求带 `CDN-Loop`（RFC 8586）；带有本节点标识的请求直接返回 508，指向节点自己的源站不会无限递归。
- 回源 HTTPS 默认按源站配置的名称（SNI / Host）用 `--trusted-ca` 或系统 CA 校验证书；关闭了 nginx 1.29.7 起默认开启的、只按地址匹配的上游连接缓存，校验过的连接不会被复用给要校验其他名称的请求。
- S3 源站收不到客户端的 `x-amz-*` 请求头（节点只签名自己的头），客户端也无法伪造 `X-Edgeweir-*` 内部头。
- 带 `Authorization` 的请求默认不查缓存也不存储（RFC 9111 §3.5），只有规则显式设置 `cache_authorized` 才缓存。
- 站点、源站、规则 id 只接受 `[A-Za-z0-9_-]`，避免它们在数据面的键里互相冒充。

**本地攻击面**

- 本地控制 API 只监听 unix socket，从不监听 TCP。
- OpenResty 内层回源层（`origin.sock`、`origin-noverify.sock`）和给预热用的本地边缘监听（`edge.sock`）同样只监听 unix socket。
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

控制台提供的 `install.sh` 在执行任何内容之前，都会先完成 sha256 和 cosign 校验，注册 token 经 `EDGEWEIR_TOKEN` 环境变量交给 `edgeweir-node enroll`。控制台可以镜像转发二进制（国内访问 GitHub 较慢），但镜像的文件必须通过同样的校验。唯一的例外是 `--allow-unsigned`：它只供开发使用（例如安装本地快照构建），会跳过 cosign 签名校验，只剩 SHA-256 校验，而 `checksums.txt` 本身此时未经验证，所以它不能证明发布物来自官方 release；生产环境不要使用。

### 为什么这很重要

GoEdge 出过官方二进制投毒事件；它的控制面还保存节点的 SSH root 凭据，2025 年 RingH23 攻击正是借此横向投毒了所有边缘节点。Edgeweir 针对这两点做了设计：发布物可以独立验证签名和来源，控制面不保存 SSH 凭据，节点私钥也从不离开节点。
