# edgeweir-node 架构

本文描述节点的实现。节点和控制面之间唯一的契约是 `edgeweir/proto`（当前 `proto/v0.10.1`）里的 `edgeweir.node.v1`。

## 1. 组件

本仓库始终是 AGPL-3.0-only 开源节点，不承载官方商业许可证校验或客户账本。客户门户、套餐计费、财务与分销由独立商业运营产品负责；节点只执行运营者控制面的正常配置并上报用量。官方授权故障或到期不影响已有 CDN 流量，完整边界见 [LICENSING.md](LICENSING.md)。

```text
                        控制台 (edgeweir, :8443, 应用自终结 TLS)
                               ▲  Connect 协议 (二进制 protobuf, HTTP/2)
         Enroll: CA pin + token│  其余 RPC: mTLS (证书 CN = node id)
┌──────────────────────────────┴───────────────────────────────────────────────┐
│ edgeweir-node (Go, 静态二进制)                                               │
│  enroll ─ pki ─ identity    controlplane (Connect 客户端, 证书热替换)        │
│  agent: watch / poll / sync / report / renew / stats / logs / tasks /        │
│         dataplane / ocsp / bans / autobans / kernel / captchas / security；  │
│         任务类型: purge / prefetch / upgrade                                 │
│  configir (规范排序, content_hash, diff, 校验 → Plan)   configstore (LKG)    │
│  render (nginx.conf 模板)   engine (openresty -t / reload / 子进程托管)      │
│  dataplane (unix socket JSON 客户端)   geoip (MMDB, unix socket)             │
│  upgrade (supervise 监督进程: 验签 / 试运行 / 回滚)                          │
│  bans (封禁状态、bans.json)   nft (table inet edgeweir，`nft -f -`)          │
│  captcha (验证码图片，标准库)                                                │
└───────────────┬──────────────────────────────────┬───────────────────────────┘
     nginx.conf │ -t / HUP / 子进程                │ /v1/health /v1/status /v1/sites
                │                                  │ /v1/purge /v1/origins/health
                │                                  │ /v1/stats/drain /v1/logs/drain
                │                                  │ /v1/bans /v1/bans/auto/drain
                │                                  │ /v1/challenge /v1/challenge/keys
                ▼                                  ▼ /v1/challenge/captchas /v1/security(/drain)
┌──────────────────────────────────────────────────────────────────────────────┐
│ OpenResty                                                                    │
│  控制 server   unix:/run/edgeweir-node/control.sock  → edgeweir.control      │
│  边缘层 server  每个 listener 一个 + unix:edge.sock   → router + proxy_cache │
│                设置了 Site.tls 的站点在每个 listener 上另有 server 块        │
│  回源层 server  unix:origin.sock / origin-noverify.sock → origin (balancer)  │
│  lua_shared_dict: edgeweir_sites / meta / stats / purge / health /           │
│    policy_logs / topstats / logs / bans / challenge / cc；                   │
│    每个已发布站点一个 edgeweir_rate_<hex(id)>                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

| 包 | 职责 |
| --- | --- |
| `cmd/edgeweir-node` | CLI：`enroll`、`run`、`supervise`、`healthcheck`、`bans`、`security`、`version`；参数可由 `EDGEWEIR_*` 环境变量提供 |
| `internal/pki` | ECDSA P-256 密钥、CSR、PEM、CA pin 校验、mTLS 配置、续期判断 |
| `internal/identity` | 状态目录里的身份文件，原子写入，续期时的密钥对原子替换与崩溃恢复 |
| `internal/enroll` | 注册流程 |
| `internal/controlplane` | Connect 客户端：pin 通道（注册）和 mTLS 通道（可热替换证书） |
| `internal/configir` | 规范排序、content_hash、diff 应用、校验并生成与引擎无关的 `Plan`；源站地址策略（`address.go`） |
| `internal/configstore` | LKG 持久化（current + previous），加载时校验哈希 |
| `internal/render` | 用 Go `text/template` 渲染 `nginx.conf`（含配置 id、每个已发布站点的限速分区、设置了 `Site.tls` 的站点的 `server` 块），解析 resolv.conf |
| `internal/engine` | `openresty -t`、reload、托管模式下的子进程监督 |
| `internal/dataplane` | Lua 控制 API 的 unix socket 客户端，站点表 / 清缓存标记 / 健康状态 / 统计 / 采样访问日志 / 封禁 / 挑战密钥与验证码池 / CC 状态与事件的 JSON 结构 |
| `internal/agent` | 运行时主循环、源站凭据、网站证书与 OCSP、清缓存标记集合、统计与访问日志上报、类型化任务（清缓存、预热、升级）、挑战密钥与验证码池、CC 事件上报；定义引擎接口 `agent.Engine` 与数据面接口 `agent.DataPlane` |
| `internal/captcha` | 验证码图片：内置 5×7 点阵字体，随机位置、缩放、旋转、倾斜、波浪基线、干扰线与噪点，160×60 调色板 PNG；答案取自 crypto/rand |
| `internal/geoip` | 读取本地 MMDB（内置 IPinfo Lite、运维提供的 City / ASN），经 0600 unix socket（默认 `control.sock.geo`）为 Lua 提供查询；`internal/geoip/check` 在镜像构建时校验下载的 IPinfo Lite |
| `internal/upgrade` | `supervise` 监督进程：经 `upgrade.sock` 接收升级任务，按本机信任策略下载并用 cosign 验签发布包，试运行新版本，失败时回滚（§2.6） |
| `internal/hostinfo` | 上报给控制台的 `NodeInfo`（主机名、非回环非链路本地地址、版本），以及渲染用的本机探测：是否有全局 IPv6（resolver 是否查 AAAA）、能否监听 IPv6、打开文件数硬上限（`worker_rlimit_nofile`） |
| `internal/bans` | 控制台动态封禁的状态：校验 `GetBans` 页、应用（reset、upsert、removed_ids）、持久化 `bans.json`、按数据面键分组（slot）、差量与容量排序 |
| `internal/nft` | 内核封禁：管理 `table inet edgeweir`，生成并以 `nft -f -` 执行事务脚本，去除重叠元素；执行器接口 `nft.Executor`（测试用假的执行器） |
| `internal/fsutil` | 崩溃安全的文件操作：`WriteFileAtomic`（临时文件 → fsync → rename → fsync 目录）、`Rename`、`SyncDir`；所有持久化写入都用它 |
| `internal/version` | 构建信息（版本、commit、提交时间），由 `-ldflags -X` 注入，`edgeweir-node version` 和 `NodeInfo.agent_version` 使用 |
| `internal/testutil`、`internal/pki/pkitest` | 只用于测试：假控制台（内存中的 NodeService，也用于容器冒烟测试）、假数据面（控制 API）、临时内部 CA、合成 MMDB（`geofixture`，`test/geoip` 用它生成 e2e 夹具） |
| `lua/edgeweir/*.lua` | 数据面，见 §3 |
| `internal/gen` | 由 buf 从 `edgeweir/proto` 的 git tag 生成，已提交 |

Lua 模块：`router`（边缘层）、`origin`（回源层与 balancer）、`lb`（选源）、`dns`（解析与地址过滤）、`ipaddr`（地址解析与特殊地址段）、`health`（被动健康检查）、`upstreamerr`（区分 TLS 失败）、`rules`（缓存规则）、`cachekey`（缓存键与路径规范化）、`purge`（清缓存标记）、`bans`（动态封禁）、`sigv4`（S3 签名）、`store`（站点表）、`tls`（按 SNI 选证书、最低 TLS 版本、OCSP stapling）、`expressions`（规则表达式编译为闭包）、`policy`（规则阶段与动作）、`ratelimit`（每站点分区的固定窗口计数）、`geoip`（查询 agent 的 GeoIP socket）、`stats`（分钟统计）、`topstats`（Top URL / Top IP）、`accesslogs`（采样访问日志）、`ja4`（TLS 客户端指纹）、`challenge`（挑战、通行凭证、保留前缀）、`cc`（分级 CC）、`control`（控制 API）、`init`。

第三方 Go 依赖（`go.mod` 的直接依赖；版本以 `go.mod` 为准）：

| 模块 | 用途 |
| --- | --- |
| `connectrpc.com/connect` | 与控制台之间的 Connect RPC |
| `google.golang.org/protobuf` | protobuf 编解码，`content_hash` 的确定性编码 |
| `github.com/oschwald/maxminddb-golang/v2` | `internal/geoip` 读取 MMDB |
| `golang.org/x/crypto` | `ocsp` 包：OCSP stapling 的请求与响应校验 |
| `github.com/maxmind/mmdbwriter` | 只用于测试与 e2e 夹具（生成合成 MMDB），不进入 `edgeweir-node` 二进制 |

间接依赖是 `golang.org/x/sys`（maxminddb-golang 使用）和 `go4.org/netipx`（mmdbwriter 使用）。`go.mod` 的 `tool` 指令固定代码生成插件 `protoc-gen-go` 与 `protoc-gen-connect-go`（`buf.gen.yaml` 经 `go tool` 调用）。

## 2. 生命周期

```text
run 启动
  │
  ├─ 准备目录，读取 credentials.json、certificates.json、purge.json、challenge-keys.json
  ├─ 有 LKG 且仍合法 → 按 LKG 渲染并启动 OpenResty、推送标记和站点表
  │            否则 → bootstrap 配置（:80，所有 Host 返回 404 unknown-host）
  ├─ 读取 bans.json，试建 nftables 表，把封禁装入数据面和内核（§2.7）
  │
  ├─ 未注册：每 2s 检查 identity.json（此时数据面已经在服务）
  │     └─ `edgeweir-node enroll`（可在 run 运行时执行，如 docker compose exec）
  │
  ├─ 加载身份，建立 mTLS 通道；首个成功的 mTLS RPC 打印
  │     "switched to mTLS channel node_id=<id>"
  │
  └─ 并行循环
        watch  : WatchConfig 流；REVISION 且比已应用的新 → sync；TASKS → tasks
        poll   : 约每 30s（±20% 抖动）触发一次 sync（不论流是否健康）
        sync   : GetConfig → 校验 → 应用 → 持久化 LKG → 触发 report（串行执行）
        report : 立即、每次应用后、每 report_interval_seconds（默认 15s）
        renew  : 控制台要求或剩余有效期 < 1/3 时续期证书
        stats  : 每 60s 从 Lua 取出已结束分钟的统计，ReportStatsV2 上报
        logs   : 每 10s 从 Lua 取出采样访问日志，ReportLogs 上报
        tasks  : 流通知、心跳 tasks_pending 或约每 30s（抖动）PullTasks
        dataplane: 每 5s 及 nginx (重)启动时检查 GET /v1/status 与 GET /v1/bans，不一致则重推（注册前已运行）
        ocsp   : 每 5 分钟刷新 1 小时内到期的 OCSP 响应，有变化时重推站点表（注册前已运行）
        bans   : 流通知 BANS、约每 30s 的轮询和启动时 GetBans，持久化后推给数据面与内核
        autobans: 每 5s 取出本机自动封禁，ReportBans 上报
        kernel : 封禁或配置变化、被覆盖的封禁需要写入、每 5 分钟刷新受保护地址时同步 nftables（注册前已运行）
        captchas: 配置使用挑战时每 10 分钟生成 256 张验证码装入数据面（注册前已运行）
        security: 每 5s 取出 CC 事件，ReportSecurityEvents 上报
```

### 2.1 注册（`enroll`）

1. token 来源：`EDGEWEIR_TOKEN` 环境变量（`install.sh` 用这种方式）、`--token-file PATH`（或 `EDGEWEIR_TOKEN_FILE`），或 `--token`（会出现在 `ps` 里，使用时打印警告）。命令行参数优先于环境变量；同一层同时给出 token 和 token 文件时报错；文件内容去掉首尾空白，为空则报错。读取后从环境中删除 `EDGEWEIR_TOKEN`，子进程（`openresty -v`）看不到它。
2. 校验参数：`--server` 必须是 https；`--ca-sha256` 为 64 位十六进制（也接受 `sha256:` 前缀和冒号分隔）；已有身份时除非 `--force` 否则拒绝。先确认状态目录可写，避免白白消耗一次性 token。
3. 本地生成 ECDSA P-256 私钥，CSR 的 CN 为主机名（控制台会改成 node id）。
4. 用 pin 通道调用 `Enroll`：`tls.Config` 设置 `InsecureSkipVerify`，由 `VerifyConnection` 做完整校验：服务端证书链中必须有一张证书的 DER SHA-256 等于 pin；以这张证书为唯一根，校验 leaf 的证书链、主机名（默认取 URL 的 host，`--server-name` 可覆盖）和 ServerAuth 用途。校验通过后才发送 token。
5. 校验响应：`ca_certificate_pem` 的哈希必须等于 pin；节点证书必须由该 CA 签发、用于 ClientAuth、公钥与本地私钥一致；CN 与 node_id 不一致时只告警。
6. 原子写入 `node.key`（0600）、`node.crt`、`ca.crt`，最后写 `identity.json`（它是"已注册"的标记）。以 root 执行且状态目录属于服务用户时，文件会交给该用户。`--force` 会先删除旧身份和旧 LKG。

token 用过即失效，重复注册返回 `permission_denied`（或 `unauthenticated`）。

### 2.2 mTLS 通道

- 客户端证书为节点证书，`RootCAs` 只有内部 CA，`ServerName` 同注册时。
- `GetClientCertificate` 每次握手读取当前证书；续期后重建 transport 并重连 watch 流。
- HTTP/2（ALPN），开启 HTTP/2 ping 检测死连接；支持 `HTTPS_PROXY` 等代理环境变量。
- 控制台返回 `unauthenticated` / `permission_denied`（节点被删除、证书吊销或过期）时，节点记录明确的错误日志，继续按 LKG 服务。证书过期后无法续期，需要重新注册。

### 2.3 获取与应用配置

`GetConfig(revision=0, base_revision=<已应用的 revision>)`：

- **snapshot**：直接进入校验。
- **diff**：以本地 LKG 为基础，listeners / cache_zones / certificates / origin_allowed_cidrs 整体替换，按 id upsert 站点，删除 `removed_site_ids`，重新规范排序后计算哈希，与 `diff.content_hash` 比较。基础 revision 不符、哈希不一致或任何错误 → 重新请求快照（`base_revision=0`）。
- LKG 属于其他集群（重新注册到别的集群）时不作为 diff 基础。
- 控制台返回比已应用更旧的 revision（例如从备份恢复）时忽略，继续服务 LKG；控制台恢复备份后凭节点保存的认证回执发布更高的 revision（见 §6「运维」）。

**content_hash**：规范排序后（listeners 按 port，cache_zones 按 name，sites 按 id，certificates 按 id，`origin_allowed_cidrs` 按字节序排序并去重；站点内 domains 按 name，origins 按 id，cache_rules 按 (priority, id)，稳定排序），把 `revision` 置 0、`content_hash` 置空，`proto.MarshalOptions{Deterministic: true}` 编码后取 SHA-256 小写十六进制。控制台用 protobuf-es 的 `toBinary` 计算，两者都按字段号顺序编码并省略 proto3 默认值，NodeConfig 中没有 map 字段，因此字节一致。跨语言测试向量在 `internal/configir/testdata/`：`content_hash_vector.json`（Phase 0）、`content_hash_vector_m2.json`（M2）、`content_hash_vector_v021.json`（v0.2.1：M2 向量加乱序带重复的允许清单和 `cache_authorized`）。

**校验策略**（`configir.Build`）：

| 情况 | 处理 |
| --- | --- |
| 哈希不符（快照或 diff 回退后的快照） | 整个配置拒绝 |
| 任一缓存规则的 `match.expression` 非空 | 整个配置拒绝（旧占位字段；规则表达式用类型化的 `Site.rules`） |
| `cluster_id` 与节点所属集群不同 | 整个配置拒绝 |
| 站点、源站、缓存规则 id 含 `[A-Za-z0-9_-]` 以外的字符或超过 128 个字符 | 整个配置拒绝（id 在数据面里作为分隔符的一部分） |
| listener 端口非法 / 重复 | 跳过该 listener 并告警 |
| HTTPS listener | 支持，证书材料通过 mTLS 单独获取 |
| 没有可用 listener | 使用默认端口（80）并告警 |
| cache zone 名非法或与内部 shared dict 重名 | 跳过并告警；没有 zone 时使用内置 `edgeweir_default` |
| 站点引用不存在的 zone / 未指定 zone | 使用第一个 zone |
| 非法域名、单级顶级泛域名（如 `*.com`）、已被前面站点（按 id 顺序）占用的域名 | 丢弃该域名并告警；站点没有域名则跳过 |
| 非法源站（地址、端口、Host 头、SNI、S3 设置、缺 id） | 丢弃该源站并告警；站点没有源站则跳过 |
| 源站 IP 字面量属于特殊地址段且不在允许清单内（§3.5） | 保留但标记 `forbidden` 并告警，请求得到 502 而不是 404 |
| 允许清单里不是 CIDR 的条目 | 忽略并告警 |
| 缓存键里非法的查询参数、请求头（含 `cookie`、`host`、`x-edgeweir-*`）、Cookie 名 | 忽略该项并告警 |
| 缓存规则 action 未指定、缺 id，或条件列表过滤后变空 | 跳过该规则（绝不放宽成"匹配全部"） |
| `enabled=false` 的站点 | 不对外服务（等同未知域名） |
| 挑战类型、CC 最高级别不是 `cookie302` / `js` / `pow` / `captcha`；通行凭证有效期、PoW 难度、CC 窗口、封禁时长等数值越界（任一站点，含停用站点）；挑战密钥 id 非法、重复、角色未知、同一角色多把或没有 `current` | 整个配置拒绝（数值为 0 取默认值，§3.14） |
| `challenge` 动作不在 `waf-custom` 阶段或类型未知；非 `challenge` 动作带 `challenge` 字段 | 整个配置拒绝 |

跳过项作为告警写入 `ReportStatus.message`（`applied with N warning(s): ...`），状态仍为 `APPLIED`，这样单个坏站点不会拖垮整个集群。整个配置被拒绝时状态为 `APPLY_STATE_FAILED`，`applied_revision` 保持为仍在服务的 LKG revision，message 给出原因（包括 `nginx -t` 的原始输出）。确定性失败（哈希、校验、`nginx -t`、reload 未生效）的同一 revision 在 5 分钟内不重复尝试。

**应用**（`agent.apply` → `agent.applyPlan`），在哈希校验和 `configir.Build` 通过之后按以下顺序执行：

1. **S3 凭据与挑战密钥**：Plan 的 `challenge_keys` 引用了本地没有的密钥时，经 mTLS 调用 `GetChallengeKeys` 获取（密钥 16–256 字节），写入 `challenge-keys.json`（0600）；控制台没有给出的密钥保持缺失，数据面检查每 30 秒再要一次。当前与上一份同集群配置都不再引用的密钥从文件中删除。S3 凭据：Plan 引用了本地没有（或版本过旧）的凭据时，先经 mTLS 调用 `GetOriginCredentials` 补齐，写入 `credentials.json`，不再引用的凭据从文件中删除；再把密钥填进 Plan 的 S3 源站。这一步在渲染和 `nginx -t` 之前：RPC 失败算暂时性错误，本次应用失败，下一次同步重试（不计入 5 分钟的拒绝窗口），仍在服务的配置不受影响。
2. **网站证书**：Plan 引用了本地没有的证书（按证书 id 与 SHA-256 指纹）时，经 mTLS 调用 `GetCertificates` 获取，校验私钥与证书匹配、指纹一致后写入 `certificates.json`（0600）。开启 OCSP stapling 的证书，OCSP 响应在 1 小时内到期时先刷新（最多 30 秒，失败只告警）。证书必须覆盖站点的每个域名，随后附到站点表。获取或校验失败的处理同第 1 步。
3. **渲染** `nginx.conf`，并为每个 cache zone 创建缓存目录；有 HTTPS 监听时先生成 nginx 前缀下的自签名占位证书 `conf/bootstrap.crt`（nginx 加载 TLS 监听需要；握手时 Lua 换成站点证书，未知 SNI 直接拒绝）。渲染结果与当前已安装的内容不同（或引擎未运行）时，写到 `nginx.conf.next`，执行 `openresty -p PREFIX -c nginx.conf.next -e stderr -t -q`，通过后原子改名为 `nginx.conf` 并 reload；内容相同则不 reload。
4. **确认 reload 生效**：每个渲染出的 `nginx.conf` 带一个配置 id（不含 id 时渲染结果的 SHA-256 前 16 位），`init_by_lua` 记下它，`GET /v1/status` 返回 `conf_id`。SIGHUP 只是请求 reload：新文件无法应用（例如端口被占用）时 nginx 记录错误并保留旧 worker。agent 在 reload 后最多等 15 秒，直到 worker 报告新的 id；否则该 revision 记为失败，把旧的 `nginx.conf` 写回（之后重启 nginx 时用的仍是正在运行的配置），LKG 继续服务。
5. **清缓存标记、挑战密钥与站点表**：装入清缓存标记（§3.4；`purge.json` 无法读取时先给每个站点加全站标记），配置使用挑战时装入密钥（`PUT /v1/challenge/keys`，失败只告警，数据面检查重试），再把 Plan 转成站点表 JSON，`PUT /v1/sites` 推给 Lua（数据面刚启动时带退避重试，最长 15s）。标记装不进去不会阻止站点表推送。
6. 原子写入 LKG（current → previous 备份），更新状态并触发 `ReportStatus`。

是否 reload 只取决于渲染出的 `nginx.conf` 是否变化。除监听、cache zone 和 agent 启动参数外，文件里还有两类随站点变化的内容：每个已发布站点（`enabled` 且有有效源站和域名的站点）一个固定大小的限速分区；设置了 `Site.tls`（HTTPS 与压缩策略）的站点自己的 `server` 块，含域名、HTTP/2、HTTP/3、gzip 与密码套件设置。所以新增、删除、启用、停用站点都会 reload，改动带 `Site.tls` 的站点的这些设置也会；站点的其余数据只进站点表，经控制 socket 热更新（完整对照见 §3.9）。

### 2.4 状态回报、续期、统计

- `ReportStatus`：`applied_revision`、`applied_content_hash`、`state`、`message`、`info`（hostname、agent_version、os、arch、engine=`openresty`、`openresty -v` 得到的版本、非回环地址）、`applied_at`、`data_plane_healthy`（最近一次控制 API 探测结果）、`certificate_not_after`、`origin_health`（最多 2000 条，§3.7）、`bans`（`BanStatus`，§2.7）、`security`（级别高于 normal 或有升级路径的站点及其升级路径数，最多 2000 个，§3.15）。能力列表总是带 `challenge-v1` 与 `ja4-v1`。响应中的 `latest_revision` 比已应用的新会触发 sync，`tasks_pending` 触发任务拉取；`report_interval_seconds` 调整心跳间隔（限制在 1s–5min）。
- 续期：响应要求或剩余有效期不足 1/3 时，生成新密钥和 CSR 调用 `RenewCertificate`；新证书必须由已固定的 CA 签发（尚不支持 CA 轮换）。先写 `node.key.new` / `node.crt.new`，再依次改名；启动时若发现密钥和证书不匹配且存在 `node.crt.new`，自动完成中断的替换。随后重建 TLS 客户端。
- 统计：Lua 在边缘层 log 阶段按 `<分钟>|<站点id>|<指标>` 累加（请求数、发送/接收字节、命中/未命中、状态码），另按分钟汇总 Top URL / Top IP。agent 每分钟调用 `POST /v1/stats/drain` 取出已结束的分钟并删除，转换成 `MinuteStats`，每批最多 1000 个分钟桶、带批次序号经 `ReportStatsV2` 上报。未确认的批次保存在 `traffic-spool.json`（0600），总量超过 10000 个分钟桶或 32 MiB 时丢弃最旧的批次。全部批次确认后，agent 用空的游标查询（`batch_sequence` 为 0）上报统计水位 `complete_until`：最近一次成功取出时所在分钟的开始，这之前的分钟都已上报；控制台据此判断用量窗口是否完整（能力 `stats-watermark-v1`）。
- 访问日志：站点设置了采样率（`log_sample_rate`，万分比）时，Lua 在边缘层 log 阶段按请求 id 抽样，记录时间、客户端 IP、方法、Host、改写前的路径（不含查询串）、状态码、发送字节、耗时、缓存状态，站点开启 JA4 日志时还有 JA4（§3.16），放进 `edgeweir_logs` 队列（最多 2000 条，满了计入丢弃数）。agent 每 10 秒调用 `POST /v1/logs/drain`（每次最多取 1000 条），带批次序号经 `ReportLogs` 上报；未确认的批次保存在 `logs-spool.json`（0600），总量超过 10000 条或 32 MiB 时丢弃最旧的批次。

### 2.5 WatchConfig

- 请求带 `known_revision`；首条消息是 `WATCH_EVENT_REVISION`，之后约每 15s 一条 `KEEPALIVE`，有新任务时 `WATCH_EVENT_TASKS`，封禁变化时 `WATCH_EVENT_BANS`（`ban_sequence` 为集群当前的封禁序号，比已应用的新时触发 `GetBans`）。
- 45s 内没有任何消息视为死流，主动断开重连。
- 断线重连退避 1s → 30s，带随机抖动；收到过消息后退避复位。
- 无论流是否健康，约每 30s（0.8–1.2 倍随机）都会 `GetConfig` 与 `GetBans` 轮询一次；已是最新时控制台返回空 diff，开销很小；流恢复后仍保留轮询作为兜底。

### 2.6 类型化任务（清缓存、预热、升级）

控制台只能下发三类任务（`NodeTask` 的 `kind`）：`PurgeTask`、`PrefetchTask` 与 `UpgradeTask`，节点不执行其他任何操作。任务幂等；结果没送到控制台时，控制台 5 分钟后再次交出，节点再执行一次。

- **拉取与顺序**：先重报之前没送到的结果和监督进程保存的升级结果，再拉取任务：每次 `PullTasks` 最多 10 个、最多 10 轮。一批里先执行所有清缓存（很快，且不能排在慢源站后面），然后是升级，最后是预热；这一批预热共享一个从拉取时刻算起的时间预算（`--prefetch-budget`，默认 4 分钟，小于控制台再次交出任务的 5 分钟）。
- **清缓存**：目标转换成标记（URL、前缀、全站，§3.4）。标记时间由节点在第一次执行该任务时分配：`max(当前毫秒, 上一个+1)`，按任务 id 记在 `purge.json` 里，同一任务再次交出时沿用原时间；不采用控制台的 `created_at`（事务乱序提交或多实例时钟偏差会让清除静默无效）。
- **预热**：经本机边缘监听请求 URL（响应像客户端请求一样落进缓存），并发 4，单个 URL 超时 60 秒，2xx/3xx 算成功，重定向不跟随。使用第一个既不是 HTTPS、也不要求 PROXY protocol 的监听（`127.0.0.1:<端口>`）；没有这样的监听时改用本地 unix socket 边缘监听（`--edge-socket`，默认 `edge.sock`）。只支持 http URL，https URL 记为失败（`https_unsupported`）。预算用完时，尚未开始或被中断的 URL 记为失败。
- **升级**：`UpgradeTask` 带 `version`、`archive_url`、`sha256`、`checksums_url`、`signature_url`。执行升级需要监督进程的 socket：`edgeweir-node supervise` 启动 `run` 子进程时经环境变量 `EDGEWEIR_SUPERVISOR_SOCKET` 传入 `<state-dir>/upgrade.sock`（0600）；没有这个 socket 时任务失败（`task_unsupported`，`type=upgrade`）。`created_at` 缺失、早于 30 分钟前或晚于 5 分钟后的任务被拒绝（`upgrade_rejected`）。agent 把任务交给监督进程暂存（最多等 4 分钟）后不回报结果，由监督进程下载、验签并试运行新版本（见下方 M6 记录）：新进程 90 秒内持续健康至少 10 秒才提交（健康指 `ReportStatus` 成功、最新 revision 已应用且数据面健康），否则恢复前一版本和配置快照。结果持久化在 `upgrades/state.json`，由之后运行的 agent 在下次拉取任务前回报，控制台确认后清除。监督进程可用（找得到 cosign；配置了 `--upgrade-public-key` 时该文件存在）时，`ReportStatus` 的能力列表带 `self-upgrade-v1`。
- **结果与错误码**（v0.2.1，`message` 仍按旧格式填写，给旧控制台用）：

| 错误码 | 参数 | 含义 |
| --- | --- | --- |
| `prefetch_failed` | `failed`、`total`、`url`、`reason`、`status` | 第一个失败的 URL；`reason` 为 `status`（带 `status`）、`connect_failed`、`timeout`、`https_unsupported`、`other` |
| `prefetch_timeout` | `done`、`total` | 时间预算用完，剩余 URL 记为失败 |
| `task_unsupported` | `type` | 更新的控制台下发了本版本不认识的任务类型：`field_<字段号>`，没有任何内容时为 `unknown`；没有监督进程时的升级任务为 `upgrade` |
| `purge_failed` | 无 | 目标非法或数据面不可用（标记已持久化，数据面恢复后生效） |
| `upgrade_rejected` | `version` | 任务过期，或监督进程没能准备新版本（下载、签名、校验和、归档内容、版本或架构校验失败） |
| `upgrade_rolled_back` | `version` | 新版本启动失败、试运行中退出或没通过健康窗口，已恢复前一版本和配置快照 |
| `upgrade_interrupted` | `version` | 激活前或结果确认前，基础安装（镜像或系统包）发生了变化 |

### 2.7 动态封禁

封禁不进 `NodeConfig`，不产生 revision，也不 reload。控制台条目有范围（平台 / 站点）、CIDR（IPv4 至少 /16，IPv6 至少 /48）、到期时间（最长 7 天）和来源（手动 / 自动）。

- **拉取**：`GetBans(after_sequence, limit=2000)` 从已应用的序号开始，逐页取到 `more=false`（每轮最多 1000 页）。`after_sequence=0`、序号超过控制台当前值（数据库恢复）或节点重新注册到别的集群时，控制台返回 `reset=true` 的快照，节点先清空全部控制台条目。触发时机：`WATCH_EVENT_BANS` 的 `ban_sequence` 大于已应用序号、配置轮询（约 30s ±20%）、连上控制台时。控制台不支持 `GetBans` 时只记一次日志。
- **校验**：id 与站点 id 只接受 `[A-Za-z0-9_-]`（最长 128），CIDR 规范化（主机位清零，IPv4 映射地址转为 IPv4），前缀短于下限、范围未知、缺到期时间的条目丢弃并告警；到期超过 7 天的缩短为 7 天；已到期的不写入。
- **持久化**：`bans.json`（0600，原子写入）保存集群 id、序号和条目。agent 启动时先读取、剔除到期条目，在连接控制台之前装入数据面和内核；文件损坏时从空集合开始，等控制台重新下发。
- **推送**：同一（范围、站点、CIDR）的条目合并为数据面的一个条目（slot），代表 id 优先取手动封禁，否则取最晚到期的自动封禁，到期时间取最晚的一个。数据面持有的序号等于 agent 之前的序号时 `POST /v1/bans` 增量（先删后写）；否则（nginx 重启、reset、写入失败后、变化超过 10000 条）`PUT /v1/bans` 全量替换，顺序为手动在前（从旧到新）、自动按创建时间从新到旧，超过 `--ban-capacity` 的最早自动条目不发送并计数。数据面检查（每 5s）发现序号不符就全量重推。
- **写不下的手动封禁**：数据面把它们记为未生效并在 `GET /v1/bans` 报告，agent 每分钟重试一次（未生效条目都列得出 id 时增量重写，否则全量替换）。
- **本机自动封禁**：Lua 写入本地字典并排入上报队列（最多 10000 条），agent 每 5 秒 `POST /v1/bans/auto/drain`（每次最多 1000 条），把地址规范化为单地址 CIDR 后经 `ReportBans` 上报；失败的批次留在内存重试，超过 10000 条时丢弃最旧的。
- **状态回报**：`ReportStatus.bans`（`BanStatus`）带数据面已应用的序号、条目数、容量、未生效的手动封禁（最多 100 个 id 与总数）、内核条目数，以及因容量丢弃的自动封禁数（数据面淘汰的与 agent 没有发送的，自 agent 启动起）。
- **能力**：`bans-v1` 总是上报；`kernel-ban-v1` 只在 nftables 表可用时上报（§3.13）。数据面的保存与查找见 §3.12。

### 2.8 挑战密钥与验证码池

- **密钥**：每个集群三把（`next`、`current`、`previous`），IR 只带 id 与角色，明文经 `GetChallengeKeys` 获取（§2.3 第 1 步）。数据面拿到的是配置引用且本机持有的全部密钥，`current` 签名、三把都验证（`PUT /v1/challenge/keys`，body `{id, current, keys: [{id, secret}]}`，secret 为 base64；`id` 是密钥集合的哈希，`GET /v1/challenge` 报告它，不一致时重推）。数据面检查的重推与应用串行，不会用较旧配置的密钥集合覆盖应用刚装入的密钥。控制台每天轮换一次，节点只需获取新的 `next`。启动时先从 `challenge-keys.json` 装入，控制面不可达时已签发的凭证仍然有效。配置不再使用挑战时数据面的密钥被清空。
- **验证码池**：配置带 `challenge_keys`（即集群使用挑战）时，agent 每 10 分钟用 `internal/captcha` 生成 256 张不重复答案的图片（160×60 PNG，字母表 `ABCDEFGHJKMNPQRSTUVWXYZ23456789`，5 个字符），经 `PUT /v1/challenge/captchas` 整池替换；数据面没有池（nginx 重启）或池 id 不符时立即重新生成。答案只存在于本机数据面的字典里。

### 2.9 CC 事件

agent 每 5 秒调用 `POST /v1/security/drain`（每次最多 1000 条，满了继续取），事件 id 由数据面生成（`<启动随机数>-<序号>`），转换后经 `ReportSecurityEvents` 上报（每批最多 500 条，id 幂等）；失败的批次留在内存重试，超过 10000 条时丢弃最旧的。控制台不支持时只记一次日志。`edgeweir-node security` 打印数据面的挑战与 CC 状态（不取出事件）。

## 3. 数据面

### 3.1 双层缓存

`proxy_cache_valid` 是静态指令，改 TTL 就要 reload。为了让缓存规则（含 TTL）可以热更新，同一个 nginx 里分两层：

```text
客户端 ──► 边缘层 (listen :80 ... default_server；PROXY protocol 监听取头部里的客户端地址)
            access_by_lua  edgeweir.router
              · 删除客户端带来的 X-Edgeweir-* 请求头（读取全部请求头）
              · CDN-Loop 已含本节点 cdn-id → 508 loop-detected；否则追加 cdn-id
              · 按 Host 查站点：精确匹配 → 上一级域名的泛域名；查不到 → 404 unknown-host
              · 动态封禁：先平台范围、后站点范围；命中且不在平台 allow 名单 → 403 ip-banned
              · 开启 CC 的站点计数（§3.15）；保留前缀 /.edgeweir/ 在这里应答，永不回源（§3.14）
              · 规则阶段（`challenge` 动作在 waf-custom 中挑战）；CC 单 IP 超限 → 自动封禁并 403 ip-banned
              · Under Attack 与 CC 级别：没有足够级别凭证的请求被挑战；allow 规则或平台 allow 名单命中的请求例外
              · WebSocket（Upgrade: websocket）：原样透传、不缓存；站点关闭时 403
              · 非 GET/HEAD：透传（Range 原样转发）
              · 按规则链判断是否可能缓存（带 Authorization 的请求见 §3.3）
              · 设置 $edgeweir_cache_zone / $edgeweir_cache_key / bypass / no_cache / Range 模式
            proxy_cache $edgeweir_cache_zone; key = cachekey.build(...) [+ slice 范围]
            proxy_cache_lock / background_update / revalidate；stale 由源站层设置的 Cache-Control 扩展决定
            add_header X-Cache $upstream_cache_status always
            内部请求头 X-Edgeweir-Site / -Rules / -Cache-Status（proxy_set_header 设置，覆盖客户端同名头）
                │ keepalive, unix socket（关闭证书校验的站点走 origin-noverify.sock）
                ▼
          回源层 (listen unix:origin.sock / origin-noverify.sock)，外部不可达
            access_by_lua  edgeweir.origin
              · 按站点 id 取源站，lb.order 排序；DNS 解析并按地址策略过滤；S3 源站签名
              · 候选中有 S3 源站时删除客户端的 x-amz-* 请求头
              · 发往源站前清除内部头；忽略源站的 X-Accel-*（防止源站操纵缓存或内部跳转）
            balancer_by_lua（每次尝试一次）
              · set_current_peer(ip, port, sni)，$edgeweir_ssl_name = sni（证书名校验，§3.6）
              · 重试次数、超时、按地址+端口+SNI 的连接池；换到 Host/签名不同的源站时重建请求
            header_filter_by_lua
              · 按规则链与响应状态/大小决定 X-Accel-Expires 和 stale-* 扩展
                （原 Cache-Control 放进 X-Edgeweir-CC，边缘层还原）
              · 源站 5xx 且边缘持有可 stale 的过期副本时断开连接，让边缘层返回 stale
            log_by_lua · 被动健康检查与错误码（§3.7）
                │
                ▼
              源站（请求头带 CDN-Loop）
```

边缘层的 proxy_cache 优先采用 `X-Accel-Expires`，nginx 不会把 `X-Accel-*` 转发给客户端。因此规则 TTL 以请求头的形式传到回源层、再以响应头的形式回到边缘层的缓存，全程不需要 reload。首次请求 `X-Cache: MISS`，第二次 `HIT`；不缓存的请求为 `BYPASS`。按 nginx 默认行为，带 `Set-Cookie` 的响应不缓存。

内部头一览：请求方向 `X-Edgeweir-Site`（站点 id）、`X-Edgeweir-Rules`（边缘选中的规则 id，逗号分隔）、`X-Edgeweir-Cache-Status`（边缘缓存状态，用于 stale-if-error），在回源层清空后才发往源站；响应方向 `X-Edgeweir-CC`（源站层暂存的原 Cache-Control，边缘层还原并删除）；对客户端只有 `X-Cache`、挑战响应的 `X-Edgeweir-Challenge`（§3.14）和错误时的 `X-Edgeweir-Error`（`unknown-host`、`loop-detected`、`ip-banned`、`websocket-disabled`、`no-origin`、`method-not-allowed`、`origin-signing`、`missing-site`、`unknown-site`、`challenge-unavailable`、`not-found`、`too-large`）。

### 3.2 选源（`edgeweir.lb`）

| 策略 | 做法 |
| --- | --- |
| `weighted_random` | 按权重随机，重试按权重顺序 |
| `round_robin` | 平滑加权轮询（nginx 的算法），状态按 worker 和站点表版本保存在解码后的站点对象上 |
| `consistent_hash` | ketama 式哈希环（每单位权重 40 个点），键为请求 URI；某源站下线只移动它自己的键 |

一次请求最多尝试 3 个源站。重试只在健康的主源之间进行；**所有主源都被标记为下线时才用备用源**；全部下线时仍全部尝试（先主源，fail open），尝试成功即提前结束下线。一次请求内不能在 HTTP 和 HTTPS 之间切换（下一个请求可以）。

### 3.3 缓存规则与缓存键

规则按 (priority, id) 排序，首个匹配生效。请求条件（精确路径、路径前缀、扩展名）在边缘层按 nginx 规范化后的 `$uri` 判断，响应条件（状态码、大小）在回源层判断。规则链是请求条件匹配的规则，直到第一个"匹配任何响应"的规则为止；回源层取链中第一个响应条件也匹配的规则。

- **遵循 / 覆盖源站缓存头**：覆盖模式用规则 TTL（没有状态码条件时只缓存 200/203/206/300/301/308）；遵循模式交给 proxy_cache 解析源站头，源站没有 Cache-Control/Expires 时才用规则 TTL。
- **stale**：规则的 stale-while-revalidate / stale-if-error 秒数写成 Cache-Control 扩展交给边缘层的 proxy_cache，原头部经 `X-Edgeweir-CC` 还原给客户端。
- **Range**：站点开启 slice 时按 1 MiB 分片获取并缓存，分片范围进入缓存键；不缓存的请求原样转发 Range；其余情况由缓存获取整个对象。
- **Authorization**（RFC 9111 §3.5）：带 `Authorization` 的请求既不查缓存也不存储，除非生效的规则设置了 `cache_authorized`（v0.2.1）；对这类请求，没有该标记的缓存规则按 bypass 规则处理（即使源站返回 `public`）。
- **缓存键**：

  ```text
  <站点id>:<代际号>:<scheme>://<host><path>[?<query>][|d=<m|d>][|h:<名>=<值>...][|c:<名>=<值>...][#<清缓存时间>]
  ```

  path 是 nginx 规范化后的 `$uri`（解码、去掉点段、合并斜杠），与规则匹配、清缓存匹配用的是同一个路径，`/%73tatic/x` 和 `/static/x` 共用一个键。每个可变部分都做百分号转义（`%`、`|`、`#`、控制字符，按位置还有 `?`、`/`、`:`、`=`），任何值都无法伪装成另一个部分。请求头取自全部请求头（与删除内部头用的是同一张表，没有 100 个的上限），重复字段按 HTTP 语义用 `,` 连接。查询参数可全部 / 忽略 / 白名单并可排序；可按设备类型（`Mobi`、`Android`、`iPhone` 等）、请求头、Cookie 区分，可不含 host。普通 URL 在默认策略下与 Phase 0 的键相同。

### 3.4 清缓存标记

清缓存从不访问磁盘：每个标记带一个时间（毫秒，§2.6），`cachekey` 把匹配请求的最大标记时间追加到缓存键，清除后的下一次请求在新键上 MISS，旧对象由缓存管理器按 inactive / max_size 淘汰。

- **存储**：`lua_shared_dict edgeweir_purge`（`--purge-dict-mb`，默认 32 MiB）。`u|<站点>|<路径>` 为 URL 标记列表 `[[host, query, 时间], ...]`，`p|<站点>` 为前缀标记列表，`s|<站点>` 为全站标记；`#id` 标记集合 id，`#ver` 每次变化递增（让 worker 缓存失效），`#entries` / `#markers` 为计数器，`#lock` 串行化写入。`GET /v1/status` 读计数器，不遍历字典。
- **匹配**：按站点当前的缓存键策略：不含 host 时忽略 host；查询串按与键相同的规范化比较；标记路径按请求时的写法（百分号编码）下发，装入时按 `$uri` 的规则规范化。
- **上限**：每个站点的 URL + 前缀标记超过 `--purge-markers-per-site`（默认 1000）时，合并为一个时间取最大值的全站标记（宁可多刷）。全量替换时某个站点的条目装不下，Lua 把这个站点换成全站标记并在响应的 `collapsed` 里报告，agent 同步合并；整个集合都装不下（507）时 agent 只保留全站标记。
- **集合 id**：`<随机代号>-<序号>`，每次变化序号加一，比较 id 是 O(1)。过期标记（最长 inactive + 1 小时）每分钟最多清理一次。
- **重启**：`purge.json`（0600，格式版本 2，含任务时间）在 agent 和 nginx 重启后保留。nginx 重启后先装标记再推站点表；标记装不进去时退化为"每个有标记的站点一个全站标记"（一分钟后再试完整集合），仍失败也照样推送站点表：站点绝不会因此变成 404。`purge.json` 无法读取时，下一次应用配置给每个站点加一个全站标记。

### 3.5 源站地址策略与 CDN-Loop

源站不能指向节点自己、它所在的网络或云元数据服务。以下地址段禁止用作源站，除非平台管理员把它放进 `NodeConfig.origin_allowed_cidrs`（v0.2.1）：

- IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`
- IPv6：`::/128`、`::1/128`、`100::/64`、`2001:db8::/32`、`fc00::/7`、`fe80::/10`、`ff00::/8`；IPv4 映射（`::ffff:0:0/96`）和 NAT64（`64:ff9b::/96`）地址按内嵌的 IPv4 地址判断

`configir/address.go` 与 `lua/edgeweir/ipaddr.lua` 使用同一张表（控制台也按它校验）。配置里的 IP 字面量由 agent 拒绝（标记 `forbidden`），Lua 对字面量再查一次，并过滤每个 DNS 解析结果（缓存的解析结果也按当前允许清单重新过滤）；什么都不剩时这次尝试失败，错误码 `address_forbidden`。

边缘层发往源站的每个请求都带 `CDN-Loop`（RFC 8586）：收到的值加上本节点的 cdn-id（`edgeweir-` + sha256(node id) 的前 16 个十六进制字符，站点表的 `cdn_id` 字段）。收到的请求里 `CDN-Loop` 已含本节点 cdn-id 时，在任何缓存或回源工作之前返回 `508 Loop Detected`。

### 3.6 回源 HTTPS

- 结论（nginx 与 lua-nginx-module 的文档和源码，并在 `openresty/openresty:1.31.1.1-bookworm-fat`（nginx 1.31.1）里实测）：`proxy_ssl_name` 默认是 `$proxy_host`，对本节点的 balancer upstream 就是 `edgeweir_balancer`。`balancer.set_current_peer(host, port, sni)` 在没有配置 `proxy_ssl_name` 时把 `u->ssl_name` 设为 sni，nginx 把它作为 SNI 发送并用它校验证书名；不传第三个参数时所有源站都按 `edgeweir_balancer` 校验而失败。另外，nginx 1.29.7 起 upstream keepalive 默认开启（`keepalive 32 local`），缓存的连接只按对端地址匹配：为 origin.test 校验过的 TLS 连接会被复用给必须校验 wrong.test 的请求，不握手也不校验（实测返回 200）。
- 做法：`upstream edgeweir_balancer` 设置 `keepalive 0`（官方文档："The zero value disables keepalive connections to upstream servers"），连接池只由 `balancer.enable_keepalive` 提供，它按地址、端口和 SNI 区分连接；回源层设置 `proxy_ssl_name $edgeweir_ssl_name` 与 `proxy_ssl_server_name on`，balancer 每次尝试把 `$edgeweir_ssl_name` 设为传给 `set_current_peer` 的同一个 SNI。
- SNI / 校验名取源站的 `sni`，其次 `host_header`（去掉端口），最后是地址本身。以 IP 配置的 HTTPS 源站需要设置证书覆盖的 SNI 或 Host（nginx 不对 IP 发送 SNI，也不按 IP 校验名称）。
- 校验层（`origin.sock`）用 `--trusted-ca` 或系统 CA bundle 校验（`proxy_ssl_verify on`）；找不到 CA bundle 时需要校验的源站直接失败（fail closed）。站点关闭校验时走 `origin-noverify.sock`，这类连接不进入连接池。

### 3.7 被动健康检查

真实流量就是探测：连接失败、超时、502/503/504、DNS 失败、地址被禁止都计为失败，其他响应清零。连续失败达到 `max_fails`（默认 3）后在 `recovery_seconds`（默认 30）内不再选中；之后流量会再试，再失败一次立即再次下线；成功一次恢复健康。状态在 `lua_shared_dict edgeweir_health`，按"站点 + 源站"区分（同一源站 id 在不同站点互不影响），经 `GET /v1/origins/health` 随心跳上报。

错误码（`last_error_code` / `last_error_params`，v0.2.1；`last_error` 仍为文本）：`connect_failed`、`timeout`、`upstream_status {status}`（源站自己返回 502/503/504）、`dns_failed {host}`、`address_forbidden {address}`、`tls_failed`；其他错误（如缺少 S3 凭据）码为空。TLS 握手或证书校验失败在 nginx 变量里与连接失败完全相同（502，没有响应头时间，字节数为 0）；回源层用 `lua_capture_error_log 64k`（只捕获 error 级别，每个 worker 独立）读取 "while SSL handshaking to upstream" 的日志行，按连接号和上游地址对应到尝试上（`edgeweir.upstreamerr`），对不上的按连接失败处理。

### 3.8 站点表与控制 API

控制 API 只监听 `unix:/run/edgeweir-node/control.sock`（`--control-socket`，目录权限 0750），由 `lua/edgeweir/control.lua` 处理。请求体和响应都是 JSON；未知路径返回 404，方法不符返回 405：

| 方法与路径 | 作用 |
| --- | --- |
| `GET /v1/health` | 存活检查（不检查方法） |
| `GET /v1/status` | `{version, revision, content_hash, site_count, pushed_at, cdn_id, conf_id, purge: {id, entries, markers}, nginx_version, ngx_lua_version, worker_pid}`；`version=0` 表示 nginx 启动后还没收到站点表 |
| `PUT /v1/sites` | 原子替换整张站点表；内容非法 400，另一次替换进行中 409，共享内存不足 507 |
| `POST /v1/stats/drain` | 返回并删除所有已结束分钟的统计（含 Top URL / Top IP） |
| `POST /v1/logs/drain` | 返回并删除最多 1000 条采样访问日志 |
| `PUT /v1/purge` | 替换整个清缓存标记集合 `{id, markers}`（装不下的站点合并为全站标记，见 `collapsed`） |
| `POST /v1/purge` | 合并标记；装不下时 507（agent 随后全量替换） |
| `GET /v1/purge` | 标记集合状态 |
| `GET /v1/origins/health` | 有失败记录的源站 |
| `GET /v1/bans` | 封禁状态 `{sequence, entries, capacity, unapplied, unapplied_ids, auto_evicted, pending_reports}`；`?list=1` 另带 `bans`（最多 1000 条） |
| `PUT /v1/bans` | 全量替换控制台条目 `{sequence, bans: [{id, cidr, scope, site_id, kind, expires_at}]}`，本机自动封禁保留；内容非法 400，另一次写入进行中 409 |
| `POST /v1/bans` | 增量 `{base, sequence, upsert, remove}`：数据面持有的序号不等于 `base` 时 409；`remove` 只删除 id 相同的控制台条目 |
| `POST /v1/bans/auto/drain` | 返回并删除最多 1000 条待上报的本机自动封禁 |
| `GET /v1/challenge` | `{keys_id, current, keys: [id], captchas, captchas_id, nonce_overflow}`；nginx 重启后为空 |
| `PUT /v1/challenge/keys` | 替换挑战密钥 `{id, current, keys: [{id, secret}]}`（secret 为 base64，16–256 字节；`current` 必须在 `keys` 里或为空）；非法 400，内存不足 507 |
| `PUT /v1/challenge/captchas` | 替换验证码池 `{id, images: [{answer, png}]}`（最多 1024 张，png 为 base64，≤ 64 KiB）；非法 400，内存不足 507 |
| `GET /v1/security` | `{sites: [{site_id, level, escalated_paths, paths: [{path, level}], site_qps, error_percent}], pending_events, dropped_events}`：开启 CC 的站点、最近一次求值的速率 |
| `POST /v1/security/drain` | 返回并删除最多 1000 条 CC 事件 `{events: [{id, site_id, time, kind, level, previous_level, path, address, metric, observed, threshold, top_ips, top_paths}]}` |

站点表 JSON（Go 结构见 `dataplane.SiteTable` 和 `configir.Site`，由 agent 从 IR 转换，Lua 不接触 protobuf）：

```json
{
  "revision": "12",
  "content_hash": "…",
  "cdn_id": "edgeweir-0123456789abcdef",
  "origin_allowed_cidrs": ["172.20.0.0/16"],
  "sites": [{
    "id": "site-a", "name": "demo", "cache_zone": "default", "cache_generation": "1",
    "load_balance": "round_robin", "tls_verify": true, "websocket": true, "slice": false,
    "health": {"max_fails": 3, "recovery_seconds": 30},
    "conn": {"connect_timeout_ms": 10000, "send_timeout_ms": 60000, "read_timeout_ms": 60000,
             "keepalive": true, "keepalive_idle": 60, "keepalive_requests": 1000},
    "cache_key": {"query": "all", "headers": ["accept-language"]},
    "domains": [{"name": "demo.test"}, {"name": "example.com", "wildcard": true}],
    "origins": [{"id": "o1", "scheme": "https", "address": "origin.example.com", "port": 443, "weight": 1,
                 "host_header": "www.example.com", "sni": "origin.example.com"}],
    "cache_rules": [{"id": "r1", "action": "cache", "ttl": 60, "mode": "override",
                     "path_prefixes": ["/"], "swr": 30, "sie": 600, "cache_authorized": false}]
  }]
}
```

`revision` 和 `cache_generation` 用字符串传递，因为 Lua 的数字是 double。S3 源站带 `s3`（region、bucket、credential_id，以及 agent 从 `GetOriginCredentials` 取得后填入的密钥）；被地址策略拒绝的源站带 `"forbidden": true`。表级还有 `http_challenges`（HTTP-01 应答）、`ip_lists`、`platform_rules`、`platform_protection`（`{under_attack, challenge}`）；站点还有 `log_sample_rate`、`rules`、`protection`（§3.14、§3.15）、`certificate_id`、`tls`（强制 HTTPS、HSTS、最低 TLS 版本、OCSP stapling 等策略）和 `certificate`（agent 填入的证书链、私钥、指纹与 OCSP 响应）。握手时 `edgeweir.tls` 按 SNI 从站点表取证书，换证书不需要 reload。

`PUT /v1/sites` 在 `edgeweir_sites` 里以版本前缀写入新表（`v<N>:site:<id>`、`v<N>:host:<name>`、`v<N>:wild:<name>`、`v<N>:cfg`（允许清单、cdn-id、HTTP-01 应答、IP 名单与平台规则），使用 `safe_set`，内存不足时整体回滚并返回 507），写完后翻转 `edgeweir_meta` 中的 `version`，请求永远不会看到写了一半的表。上一版本保留到下一次替换，供翻转瞬间仍在处理的请求使用。每个 worker 有三个 lua-resty-lrucache：解码后的站点（含轮询和哈希环状态）与表设置、Host 命中（精确域名；泛域名按上一级域名只缓存一条，随机子域名不增加条目）、Host 未命中（独立的小缓存，1024 条），键里带版本号，翻转即失效；伪造 Host 的洪泛只会冲刷未命中缓存。

shared dict 在 HUP reload 时保留，在 nginx 重启后清空。agent 每 5s（以及收到 nginx 启动事件时）调用 `GET /v1/status`，发现 `version=0`、revision/哈希/cdn-id 与期望不符，或标记集合 id 不同就重新推送。

### 3.9 reload 与热更新

reload 与否只看渲染出的 `nginx.conf` 与已安装的是否不同（§2.3 第 3 步）。

| 变更 | 方式 |
| --- | --- |
| 监听（增删、端口、HTTPS、HTTP/2、HTTP/3、PROXY protocol） | 重新渲染 → `openresty -t` → reload（HUP）→ 确认新配置 id |
| cache zone（增删、大小、inactive） | 同上 |
| 已发布站点集合：新增、删除、启用、停用站点，或站点因没有有效源站或域名被跳过（增删它的固定 256 KiB 限速分区 `edgeweir_rate_<站点 id 的十六进制>`；其他站点的分区名称和大小不变，计数保留） | 同上 |
| 设置了 `Site.tls` 的站点：`Site.tls` 的有无、域名、HTTP/2、HTTP/3、gzip（开关、最小长度、类型）、密码套件档位，以及有没有证书（这些值写在站点自己的 `server` 块里；HTTPS 监听上的块只在站点有证书时生成） | 同上 |
| agent 启动参数：resolver（`--resolver`，或启动时读取的 `--resolv-conf`）、回源 CA bundle（`--trusted-ca` 或系统 bundle）、`--purge-dict-mb`、IPv6 探测、worker 与 nginx 用户设置、socket 与目录 | agent 重启后生效：启动后的第一次应用总会写入、检查并 reload（托管模式下是启动 OpenResty） |
| 站点表里的其他内容：源站与源站池设置、缓存规则与 TTL、缓存键、缓存代际号、所用 cache zone、Range 分片与 WebSocket 开关、边缘规则、日志采样率、证书与私钥（同一站点换证书）、OCSP stapling 开关与 OCSP 响应、强制 HTTPS、HSTS、最低 TLS 版本；表级的源站允许清单、cdn-id、HTTP-01 应答、IP 名单、平台规则 | 热更新：`PUT /v1/sites`，不 reload |
| 清缓存 | 热更新：`POST` / `PUT /v1/purge` |
| 动态封禁 | 热更新：`POST` / `PUT /v1/bans`，平台范围另写 nftables；`--ban-dict-mb` 与 `--ban-capacity` 属于 agent 启动参数 |
| Under Attack、挑战规则、CC 策略、JA4 日志开关、平台 Under Attack | 热更新：站点表（`protection`、`platform_protection`、`rules`） |
| 挑战密钥、验证码池 | 热更新：`PUT /v1/challenge/keys`、`PUT /v1/challenge/captchas`；`--cc-dict-mb` 与 `--challenge-dict-mb` 属于 agent 启动参数 |

`resolver` 取自 `/etc/resolv.conf`（`--resolv-conf`）的 nameserver（Docker 中为 `127.0.0.11`；IPv6 加方括号；带 zone 的链路本地地址跳过；没有时回退到 `127.0.0.1`），`--resolver` 可直接指定；Lua 按 min(TTL, 30s) 缓存结果（失败 5 秒）；主机没有全局 IPv6 地址时不查询 AAAA。

### 3.10 PROXY protocol

配置了 PROXY protocol 的监听，每个连接都以 PROXY 头开始，所以该 server 设置 `set_real_ip_from 0.0.0.0/0`、`set_real_ip_from ::/0`、`real_ip_header proxy_protocol`：`$remote_addr`、发往源站的 `X-Real-IP` 和 `X-Forwarded-For` 都是 PROXY 头里的客户端地址，而不是负载均衡器的地址（ngx_http_realip_module 文档："The proxy_protocol parameter changes the client address to the one from the PROXY protocol header"）。普通监听保持对端地址。agent 的预热请求从不走要求 PROXY protocol 的监听（§2.6）。

### 3.11 进程管理

- **托管模式**（`--manage-nginx`，容器和 systemd 默认）：agent 以子进程运行 `openresty -p PREFIX -c nginx.conf -e stderr -g 'daemon off;'`。首次配置检查通过后才启动；reload 发送 SIGHUP 并确认新配置 id；子进程意外退出时按 1s → 30s 退避重启，重启后自动重推标记和站点表；agent 收到 SIGTERM/SIGINT 时向 OpenResty 发送 SIGQUIT 优雅退出，8s 后仍未退出则 SIGKILL。子进程在独立进程组中，Linux 上设置 `Pdeathsig`，agent 意外死亡时 OpenResty 也会退出。启动前清理残留的 unix socket。nginx 的 stderr 按行转进 agent 日志（`component=nginx`）。
- **非托管模式**：OpenResty 由外部管理，agent 用 `-s reload` 通知，同样确认新配置 id。
- `worker_rlimit_nofile` 取进程的硬上限（os/exec 子进程只继承默认软上限），`worker_connections` 随之调整。

### 3.12 封禁的执行

`edgeweir.bans` 把封禁保存在 `lua_shared_dict edgeweir_bans`（`--ban-dict-mb`，默认 32 MiB），条数上限 `--ban-capacity`（默认 100000，经 `init_by_lua` 传入）：

| 键 | 内容 |
| --- | --- |
| `e\|<范围>\|<4 或 6>/<前缀长度>\|<字节>` | 一条封禁，值为 `<类型>\|<id>\|<到期时间>\|<cidr>`；范围 `*` 为平台、否则为站点 id；字节是掩码后地址的前 ceil(len/8) 个字节；类型 `m`（控制台手动）、`c`（控制台自动）、`a`（本机自动）；TTL 为剩余有效期 |
| `#len\|<范围>` | 该范围控制台条目出现过的前缀长度；全量替换时重算 |
| `#loc\|<范围>` | 该范围有过本机自动封禁（/32、/128） |
| `#ver` | 长度列表变化时递增；worker 按版本缓存各范围的长度列表 |
| `#seq` | 控制台条目的序号（补零到 20 位，更新不需要新内存） |
| `#live`、`#x\|<分钟>` | 条目数；每分钟到期数在分钟结束后从 `#live` 扣除，全量替换时重新计数 |
| `#q`、`#r` | 本机自动封禁的淘汰队列（写入顺序）与上报队列 |
| `#unapplied`、`#unapplied_more` | 写不下的手动封禁（最多 1000 个 id，其余只计数） |
| `#evicted` | 为腾出空间淘汰或丢弃的自动封禁数 |

- **查找**：边缘层解析站点之后、规则之前。每个请求读一次 `#ver`；平台与站点范围都没有长度时到此为止。否则按各长度掩码客户端地址逐个查找（IPv4 映射的 IPv6 地址也按 IPv4 查），先平台后站点。平台 `allow` 名单命中的地址不受封禁，其余返回 `403`、`X-Edgeweir-Error: ip-banned`。
- **容量与内存**：所有写入用 `safe_set` / `safe_add`，共享内存不会自行淘汰封禁。新条目超出容量或内存不足时，先按写入顺序淘汰最早的本机自动封禁；控制台条目从不在数据面被淘汰。仍然写不下时，手动封禁记为未生效并上报，控制台自动封禁丢弃并计数。
- **本机自动封禁**：`bans.add_auto(site_id, ip, ttl_seconds, trigger)` 写入站点范围的单地址封禁（已有控制台条目时只上报），排入上报队列（最多 10000 条，满了丢弃最旧的）。
- **重启**：reload 保留字典，nginx 重启后字典为空、序号为 0，agent 在 5 秒内全量重推；本机自动封禁与未上报队列随之丢失。

### 3.13 内核封禁（nftables）

平台范围的封禁同时写入内核，被封禁的客户端连 TCP 与 TLS 握手都完成不了。站点范围的封禁只在边缘层执行。

```text
table inet edgeweir {
	set ban4 { type ipv4_addr; flags interval, timeout; }     元素带剩余秒数（向上取整）的 timeout
	set ban6 { type ipv6_addr; flags interval, timeout; }
	set allow4 { type ipv4_addr; flags interval; }            受保护地址
	set allow6 { type ipv6_addr; flags interval; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		ip saddr @ban4 drop
		ip6 saddr @ban6 drop
	}
}
```

- **启用**：`--kernel-bans auto`（默认）时 agent 启动即用 `nft -f -` 执行 `add table inet edgeweir`、`delete table inet edgeweir` 再定义整张表（清掉上次留下的表；Debian bookworm 的 nft 1.0.6 没有 `destroy`）。失败（没有 `nft`、没有 `CAP_NET_ADMIN`、内核没有 nf_tables）时只做边缘层封禁，记一次日志，不上报 `kernel-ban-v1`。agent 退出时 `delete table inet edgeweir`；agent 被强制杀掉时残留的元素按 timeout 自行失效，下次启动重建。
- **同步**：每次变化执行一个事务脚本，依次 `flush set` 四个集合再 `add element`（每条语句最多 500 个元素），原子生效；集合写入失败（例如表被别人删除）时重建一次表再写。元素只由 `netip` 解析、格式化后的地址生成，不拼接控制台传来的字符串。示例：

  ```text
  flush set inet edgeweir allow4
  flush set inet edgeweir allow6
  flush set inet edgeweir ban4
  flush set inet edgeweir ban6
  add element inet edgeweir allow4 { 10.0.0.5, 127.0.0.0/8, 192.0.2.10 }
  add element inet edgeweir allow6 { ::1 }
  add element inet edgeweir ban4 { 198.51.100.0/24 timeout 3600s, 203.0.113.7 timeout 60s }
  ```

- **受保护地址**（`allow` 集合，永不丢弃）：回环（`127.0.0.0/8`、`::1`）、本机所有网卡地址、控制台地址（`identity.json` 中控制台 URL 的主机名解析出的全部地址，5 分钟刷新一次，解析失败时沿用上次结果）、已应用配置中平台 `allow` 名单的条目。
- **去重叠**：区间集合不接受重叠元素。被更大前缀覆盖、且到期不晚于它的条目不写入；被覆盖但更晚到期的条目在覆盖条目到期后重新同步写入。`allow` 集合同样去掉被覆盖的前缀。
- **权限**：需要 `CAP_NET_ADMIN`。默认 systemd unit 和默认镜像都不授予（§5）。

### 3.14 挑战与通行凭证

`edgeweir.challenge` 实现四个级别：`cookie302`（1）、`js`（2）、`pow`（3）、`captcha`（4），级别 L 的凭证满足不高于 L 的要求。站点 `protection` 的默认值：Under Attack 类型 `js`，凭证有效期 1800 秒（300–86400），PoW 16 位（8–24），高难度 PoW 20 位（8–26，不低于普通难度）；IR 中为 0 的值取默认值。

- **需要的级别**：平台 Under Attack、站点 Under Attack、站点 CC 级别、该路径的 CC 级别取最大值，在规则阶段之后判断；`waf-custom` 的 `challenge` 规则在命中处判断（凭证级别足够就继续后续规则，否则挑战）。`allow` 规则（平台或站点）或平台 allow 名单命中的请求不受 Under Attack 与 CC 挑战，也不被 CC 自动封禁。CC 到 `captcha` 级且策略设置了高难度 PoW 时改用高难度 PoW。
- **应答**：
  - 没有密钥（节点从未拿到过）：503，`X-Edgeweir-Error: challenge-unavailable`。
  - 非 GET/HEAD：403，`X-Edgeweir-Challenge: required`，不给挑战页。
  - `cookie302`：302 回到原 URL（`Location` 为请求的 scheme、Host 与路径），`Set-Cookie` 1 级凭证，`X-Edgeweir-Challenge: cookie302`。
  - `js` / `pow` / `captcha`：403 挑战页，`X-Edgeweir-Challenge: <类型>`（高难度 PoW 为 `pow`）、`Cache-Control: no-store, private`、`Content-Security-Policy: default-src 'none'; script-src 'nonce-<n>'; style-src 'nonce-<n>'; img-src data:; connect-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`（每个响应一个 nonce）、`X-Content-Type-Options: nosniff`；HEAD 只有头。页面自包含（内联样式与脚本、`data:` 图片），按 `Accept-Language` 选中文或英文（q 值最高者，其次英文），`prefers-reduced-motion` 时进度条不动画。
- **页面**：`js` 用 WebCrypto 计算 `sha256(挑战参数)` 的十六进制，明文 HTTP（非安全上下文，没有 WebCrypto）时用页面内置的 SHA-256；`pow` 用 `/.edgeweir/challenge/worker.js` 的 Web Worker 找 `n`，使 `sha256(挑战参数 ":" n)` 的前导零位数达到难度（Worker 用同步的 SHA-256 并复用参数前缀的中间状态；Worker 不可用时在页面上分片计算）；`captcha` 是图片与输入框，无脚本也能提交，另有「改用计算验证」按钮（带 `alt=pow` 提交到 verify，换成 4 级的高难度 PoW）。三者都自动或手动 POST 到 verify。
- **挑战参数**：`<kid>.<b64url(站点|类型|级别|网段|UA 哈希|签发|到期|nonce|难度|答案)>.<b64url(HMAC-SHA256(密钥, "c1.<kid>.<载荷>"))>`，有效 5 分钟；验证码答案字段为 `HMAC(密钥, "a|<nonce>|<答案大写>")` 的前 32 个十六进制字符，任一持有密钥的节点都能验证。
- **verify**（`POST /.edgeweir/challenge/verify`，字段 `t`、`a`、`r`，请求体 ≤ 4 KiB）：签名、站点、网段、UA 哈希、到期都符合后在 `edgeweir_challenge` 以 `safe_add` 记录 nonce 直到到期（同一挑战只兑换一次；字典满时先清理过期项，仍写不下则放行并计入 `nonce_overflow`：参数绑定网段与 UA，重放得到的与凭证本身相同）。答案正确：303 到 `r`（只接受以单个 `/` 开头、不含反斜杠与空白、不在保留前缀下的本站路径，否则 `/`），`Set-Cookie` 凭证（级别取参数级别与已有凭证的较大者）；答案错误：新的挑战页（403）并提示；参数无效、过期或已兑换：303 到 `r`，由原页面重新挑战。
- **通行凭证**：`__ew_pass=v1.<kid>.<b64url(站点|级别|网段|UA 哈希|签发|到期)>.<b64url(HMAC-SHA256(密钥, "v1.<kid>.<载荷>"))>; Path=/; Max-Age=<有效期>; HttpOnly; SameSite=Lax`，HTTPS 加 `Secure`。网段为 `4:a.b.c`（IPv4 /24，IPv4 映射地址按 IPv4）或 `6:<前 64 位十六进制>`，UA 哈希为 `sha256(User-Agent)` 的前 16 个十六进制字符。验证：kid 属于已装入的密钥、签名、站点、未到期、网段、UA 哈希。每个 worker 按 cookie 值缓存验证过的凭证（最多 1 分钟），网段与 UA 哈希也按地址和 UA 缓存，持有凭证的请求不计算 HMAC。
- **保留前缀**：`/.edgeweir/challenge/verify`（其他方法 405）、`/.edgeweir/challenge/worker.js`（GET/HEAD，缓存 1 小时），前缀下其他路径 404 `not-found`；所有站点都保留，在规则之前应答，永不回源。

### 3.15 分级 CC（节点本地决策）

每个节点独立计数和决策，攻击分散到多个节点时单节点可能达不到阈值：阈值按节点设置。策略字段（0 表示关闭该条件）：最高级别（默认 `captcha`）、窗口 W（默认 10 秒，5–60）、站点 QPS、单 URL QPS、单 IP QPS 与封禁时长（默认 600 秒，60–86400）、源站错误率（百分比）与最小请求数、升级时间 N（默认 10 秒）、冷却 M（默认 60 秒）。

- **计数**（`lua_shared_dict edgeweir_cc`，`--cc-dict-mb`，默认 32 MiB）：两个相邻窗口加权的滑动窗口，`上一窗口 × (1 − 已过比例) + 当前窗口`。每个请求对站点一次 `incr`（站点 QPS 开启时），对客户端地址一次 `incr`（单 IP QPS 开启时；当前窗口计数超过限额一半时才读上一窗口），再读一次站点级别；源站请求与错误（5xx，含全部尝试失败）在 log 阶段计数，缓存命中不计。路径与地址在每个 worker 的有界 Space-Saving（每站点 64 个候选）里计数，每秒把路径计数加到共享字典、提交候选路径和最重的 10 个地址。没有 CC 的站点不做任何额外工作。
- **求值**：每秒由第一个拿到 `#eval|<秒>` 的 worker（不含正在退出的）对每个开启 CC 的站点求值。站点级取站点 QPS 与源站错误率（达到最小请求数才计算）中超出比例最大的条件；条件持续 N 秒升一级（不超过最高级别），全部低于阈值 80% 持续 M 秒降一级，80%–100% 之间两个计时都重置。路径级按单 URL QPS 同样计算，只跟踪 64 条路径（已升级的优先，其次速率最高的），按精确路径（nginx 规范化后的 `$uri`，不含查询串）匹配。请求需要的 CC 级别是站点级与该路径级的较大者。
- **单 IP**：地址的滑动窗口计数超过 `ip_qps × W` 时，经 `bans.add_auto` 写入站点范围的本机自动封禁（原因 `cc_ip_rate`，指标 `ip_qps`），同一地址在封禁期内只封一次，本次请求返回 403 `ip-banned`。allow 规则或平台 allow 名单命中的请求不触发。
- **事件**：站点级变化（`site_level`，升级时指标为触发条件，降级为 `cooldown`）、路径级变化（`path_level`）、自动封禁（`ip_banned`）排入队列（最多 10000 条，满了丢弃最旧的并计数），带当时的 Top IP 与 Top 路径（各 ≤ 10，近似值），agent 上报（§2.9）。
- **状态**：级别、跟踪与升级路径、Top 地址在 reload 和阈值变更后保留；nginx 重启后计数、级别与未上报事件丢失。站点关闭 CC（或被删除）后，下一次求值（1 秒内）清除它的级别、跟踪与升级路径和 Top 地址，重新开启时从 `normal` 开始；窗口计数在 2W + 2 秒后自行过期，已写入的自动封禁按各自时长到期。

### 3.16 JA4

`edgeweir.ja4` 在 `ssl_client_hello_by_lua` 计算 JA4（FoxIO JA4，BSD-3-Clause；不实现 JA4+ 的其他方法），只为读取 `tls.ja4`（规则表达式或限速键）或开启 JA4 日志的站点计算，写入 `ngx.ctx.edgeweir_ja4`，同一连接的请求（HTTP/1.1 与 HTTP/2）继承。

- `a`：`t`（HTTP/3 请求改为 `q`）、版本（`supported_versions` 中最大的非 GREASE 值；没有该扩展时取请求阶段协商出的版本 `$ssl_protocol`，而不是 JA4 规定的 ClientHello legacy 版本，API 不提供后者）、SNI `d`/`i`、密码套件数与扩展数（两位，最多 99）、ALPN 第一个值的首尾字符（非字母数字时取其十六进制的首尾字符，没有为 `00`）。
- `b`、`c`：排序后的密码套件；排序后的扩展（去掉 `0000`、`0010`）接 `_` 与原顺序的签名算法；各取 SHA-256 前 12 个十六进制字符，列表为空时为 `000000000000`。GREASE 值一律忽略。
- 表达式字段 `tls.ja4`：明文 HTTP 为空字符串；可用于 `waf-custom`、`ratelimit`（也可作为限速键）、`challenge` 规则。站点开启 JA4 日志时采样访问日志带 `ja4`（`AccessLog.ja4`）。
- **近似**：ClientHello 来自 lua-resty-core（`ngx.ssl.clienthello`），它只列出 OpenSSL 认识的扩展；OpenSSL 不认识的扩展（例如 ALPS `4469`、ECH `fe0d`）不计入扩展数和哈希，这类客户端（例如 Chromium）的指纹与其他 JA4 工具的结果不同。规则应使用节点采样日志里看到的指纹。HTTP/3 的请求是否继承握手阶段的 `ngx.ctx` 取决于 nginx 的 QUIC 实现；拿不到时 `tls.ja4` 为空。测试向量 `test/lua/ja4-vectors.json`：JA4 规范文档的算例与按规范构造的用例。

## 4. 文件布局

| 路径 | 内容 |
| --- | --- |
| `/var/lib/edgeweir-node/node.key` | 节点私钥，PKCS#8 PEM，0600 |
| `/var/lib/edgeweir-node/node.crt`、`ca.crt` | 节点证书、内部 CA 证书 |
| `/var/lib/edgeweir-node/identity.json` | node_id、cluster_id、node_name、server_url、server_name、ca_sha256、enrolled_at |
| `/var/lib/edgeweir-node/config/current.binpb`、`previous.binpb` | LKG 配置及其备份（二进制 protobuf，0600） |
| `/var/lib/edgeweir-node/credentials.json` | 当前配置引用的 S3 源站凭据（access key 与 secret key 明文，0600），控制台不可达时重启仍能服务 S3 源站 |
| `/var/lib/edgeweir-node/purge.json` | 清缓存标记与任务时间（0600） |
| `/var/lib/edgeweir-node/certificates.json` | 当前与上一份 LKG 引用的网站证书链、私钥与 OCSP 响应（0600） |
| `/var/lib/edgeweir-node/bans.json` | 已应用的控制台动态封禁、序号与集群 id（0600） |
| `/var/lib/edgeweir-node/challenge-keys.json` | 当前与上一份同集群配置引用的挑战凭证密钥（0600） |
| `/var/lib/edgeweir-node/traffic-spool.json`、`logs-spool.json` | 控制台尚未确认的统计批次与采样访问日志批次（0600） |
| `/var/lib/edgeweir-node/upgrade.sock`、`upgrades/` | `supervise` 监督进程的本机 socket（0600）；升级状态 `upgrades/state.json` 与各版本目录 `upgrades/releases/<任务 id>/`（0700） |
| `/var/lib/edgeweir-node/nginx/` | nginx prefix：`conf/nginx.conf`（有 HTTPS 监听时还有占位证书 `conf/bootstrap.crt`、`bootstrap.key`）、`logs/nginx.pid`、`tmp/` |
| `/var/cache/edgeweir-node/<zone>/` | proxy_cache 数据 |
| `/run/edgeweir-node/control.sock`、`control.sock.geo`、`edge.sock`、`origin.sock`、`origin-noverify.sock` | 控制 API、GeoIP 查询（agent 提供）、本地边缘监听、回源层（校验 / 不校验证书） |
| `/usr/share/edgeweir-node/lua/edgeweir/` | Lua 模块 |

所有持久化写入都是：写临时文件 → fsync → rename → fsync 目录。状态目录为 0700。

## 5. 部署形态

- **容器**：`openresty/openresty:1.31.1.1-bookworm` 为基础，agent、nginx master 和 worker 都以 uid 10001 运行（容器网络命名空间内非特权进程可以绑定 80 端口）；`ENTRYPOINT edgeweir-node supervise --manage-nginx`，`STOPSIGNAL SIGTERM`，健康检查为 `edgeweir-node healthcheck`。镜像带 Debian 的 `nftables` 包。内核封禁需要两项：镜像以 `--build-arg NFT_CAPABILITY=true` 构建（给 `/usr/sbin/nft` 加文件能力 `cap_net_admin+ep`），容器以 `--cap-add NET_ADMIN` 启动（compose 中为 `cap_add: [NET_ADMIN]`）。默认镜像不加任何能力；只加了文件能力而容器没有 `NET_ADMIN` 时 `nft` 无法执行，agent 退回边缘层封禁。nftables 规则作用于容器自己的网络命名空间。
- **systemd**：`packaging/systemd/edgeweir-node.service`，服务用户 `edgeweir`，只保留 `CAP_NET_BIND_SERVICE`，`ProtectSystem=strict` 等加固选项；OpenResty 作为 agent 的子进程运行，与发行版自带的 `openresty.service` 互斥。deb/rpm 包含二进制、Lua 模块、unit 和 `/etc/default/edgeweir-node`，推荐安装 `nftables`；preinstall 创建 `edgeweir` 用户，postinstall 创建 `/var/lib/edgeweir-node`（0700）和 `/var/cache/edgeweir-node`（0750）。
- **systemd 下的内核封禁**：默认 unit 不授予 `CAP_NET_ADMIN`。需要时安装 `nftables`，加一个 drop-in `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`：

  ```ini
  [Service]
  AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  ```

  然后执行 `systemctl daemon-reload && systemctl restart edgeweir-node`，日志出现 `kernel bans active` 即生效。环境能力同样被 OpenResty 子进程继承。

## 6. 已知限制

- 旧占位字段 `CacheRuleMatch.expression` 仍拒绝非空值；通用表达式通过 `EdgeRule` 结构化 AST 下发，公共缓存 API 不暴露旧占位字段。
- 不支持内部 CA 轮换。
- 客户端上传大小固定为 100m（IR 暂无对应字段）。
- 访问日志默认关闭，按站点采样，经有界私有队列与持久批次去重上报。
- 预热只预热桌面变体，不支持前缀与全站预热。
- 使用 required_features 协商能力；未知枚举或能力拒绝整份配置，保留 LKG。
- 尚未收到第一份配置时，`ReportStatus.state` 为 `APPLY_STATE_UNSPECIFIED`，message 为 `waiting for the first configuration`。
- 内核封禁在 input 链丢弃被封地址的全部入站包，节点也无法与该地址建立出站连接（例如该地址恰好是源站）；受保护地址不受影响。
- 本机自动封禁只在数据面字典里，nginx 重启后丢失（已上报并由控制台共享的条目会再次下发）。
- CC 计数与级别按节点独立决策，nginx 重启后从正常级别重新开始。
- JA4 看不到 OpenSSL 不认识的 ClientHello 扩展，没有 `supported_versions` 时版本取协商结果（§3.16）。
- 内核按 TCP 连接的源地址丢包。节点在要求 PROXY protocol 的负载均衡器之后时，内核只看到负载均衡器的地址：平台封禁对客户端只在边缘层生效，负载均衡器的地址需要放进平台 `allow` 名单，否则封禁它会丢弃经它转发的全部流量。

## HTTPS 与证书

支持 HTTPS、HTTP/2、HTTP/3 与 SNI 证书热更新。证书材料在 certificates.json（0600）中保存当前与前一份 LKG 的引用；节点身份私钥与网站 TLS 私钥分别管理。激活后推送失败会恢复，配置未持久化不能回报 APPLIED。详情见控制面 docs/guide/https.md。

## 规则与 GeoIP

- `Site.rules`、`NodeConfig.ip_lists/platform_rules` 进入热更新表，Go 验证后 Lua 编译为固定闭包。禁止运行用户 Lua。每阶段平台规则先执行，平台 IP 白名单仅覆盖平台 IP 黑名单；站点放行不能绕过平台 WAF。
- IP 前缀树、有限 PCRE 工作量、不会淘汰现有键的固定窗口限速；规则或依赖数据执行错误时拒绝请求。
- `internal/geoip` 读取本地 MMDB，经 0600 Unix socket 服务同机 worker：发布镜像构建时下载并内置的 IPinfo Lite（国家、ASN，`--geoip-ipinfo auto`），以及运维提供的 City/ASN MMDB。国家和 ASN 优先取 IPinfo，查不到时回落到 City/ASN；一级行政区只来自 City，且仅当其国家与结果一致。数据库通过完整性与类型检查才上报能力；GeoIP 请求不离开节点，运行时不下载数据。
- 缓存和刷新使用改写前路径；配置与列表更新不 reload。`rules-v1`、`geoip-city-v1`（国家；沿用旧名以兼容控制台，来自 IPinfo 或 City）、`geoip-subdivision-v1`（City，一级行政区）、`geoip-asn-v1`（IPinfo 或 ASN）分开上报；`geoip-country-v1` 告知控制台一级行政区已单独上报。控制台对国家和一级行政区规则仍只下发 `geoip-city-v1` 要求，节点逐条表达式校验时一级行政区需要 `geoip-subdivision-v1`，没有 City MMDB 的节点拒绝这类配置。
- 持久化失败在恢复旧配置后退避五分钟或等下一版本，避免每次轮询重新激活未持久化内容。
- `test/lua/expression-vectors.json` 镜像控制面规则包的共享向量（接受向量由 Lua PCRE2 与 Go RE2 执行，拒绝向量由 Go 校验拒绝）；GeoIP MMDB（City、ASN 及 IPinfo Lite 结构）为 `internal/testutil/geofixture` 自行生成的数据。

## 统计

`traffic-spool.json`（0600）在调用 `ReportStatsV2` 之前保存不可变的批次和单调递增的序号；本地状态丢失后用游标查询恢复。队列上限为 10000 个分钟桶或 32 MiB。Lua 的 Space-Saving 摘要（Top URL / Top IP）用单独的共享字典，不含查询串和请求头，是近似值。全部批次确认后上报统计水位 `complete_until`（§2.4）。

## 运维

固定监督进程持独占状态锁，经本机 0600 socket 接收类型化任务。发布来源、cosign 和公钥由节点运维配置；控制面不能选择公钥或任意命令。验证已签名清单和归档哈希、文件布局、ELF 架构与版本后，程序和 Lua 在私有版本目录内切换。原子状态记录准备 / 试运行 / 当前版本，健康窗口失败或中途重启恢复前一版本及配置快照。结果保留到控制面确认；基础安装指纹变化时采用新镜像 / 软件包，避免旧自升级程序掩盖系统更新。

`config/receipts.json` 保存绑定节点、集群、revision、内容哈希的控制台认证回执，权限 0600；与 LKG 一同备份/回滚。控制面恢复后只接受有凭证的领先版本参与跳号，未认证整数不会耗尽发布序号。采样日志默认关闭，无查询参数、头或正文，经持久批次上报；磁盘队列有明确上限和丢弃日志。
