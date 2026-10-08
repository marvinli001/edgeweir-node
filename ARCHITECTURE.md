# edgeweir-node 架构

本文描述节点的实现。节点和控制面之间唯一的契约是 `edgeweir/proto`（当前 `proto/v0.25.0`）里的 `edgeweir.node.v1`。

## 1. 组件

本仓库始终是 AGPL-3.0-only 开源节点，不承载官方商业许可证校验或客户账本。客户门户、套餐计费、财务与分销由独立商业运营产品负责；节点只执行运营者控制面的正常配置并上报用量。官方授权故障或到期不影响已有 CDN 流量，完整边界见 [LICENSING.md](LICENSING.md)。

```text
                        控制台 (edgeweir, :8443, 应用自终结 TLS)
                               ▲  Connect 协议 (二进制 protobuf, HTTP/2)
         Enroll: CA pin + token│  其余 RPC: mTLS (证书 CN = node id 或 probe id)
┌──────────────────────────────┴───────────────────────────────────────────────┐
│ edgeweir-node (Go, 静态二进制)                                               │
│  enroll ─ pki ─ identity    controlplane (Connect 客户端, 证书热替换)        │
│  agent: watch / poll / sync / report / renew / stats / logs / tasks /        │
│         dataplane / activehealth / ocsp / bans / autobans / kernel /         │
│         captchas / security / probe；任务类型: purge / prefetch /            │
│         sitemap / upgrade                                                    │
│  configir (规范排序, content_hash, diff, 校验 → Plan)   configstore (LKG)    │
│  render (nginx.conf 模板)   engine (openresty -t / reload / 子进程托管)      │
│  dataplane (unix socket JSON 客户端)   geoip (MMDB, unix socket)             │
│  upgrade (supervise 监督进程: 验签 / 试运行 / 回滚)                          │
│  bans (封禁状态、bans.json)   nft (table inet edgeweir，`nft -f -`)          │
│  captcha (验证码图片，标准库)   healthcheck (主动健康检查)                   │
│  probe (探测轮次, ProbeService)   metrics (/proc 主机指标)                   │
└───────────────┬──────────────────────────────────┬───────────────────────────┘
     nginx.conf │ -t / HUP / 子进程                │ /v1/health /v1/status /v1/sites
                │                                  │ /v1/purge /v1/origins/health /v1/origins/active
                │                                  │ /v1/stats/drain /v1/logs/drain /v1/l4
                │                                  │ /v1/bans /v1/bans/auto/drain
                │                                  │ /v1/challenge /v1/challenge/keys
                ▼                                  ▼ /v1/challenge/captchas /v1/security(/drain)
┌──────────────────────────────────────────────────────────────────────────────┐
│ OpenResty                                                                    │
│  控制 server   unix:/run/edgeweir-node/control.sock  → edgeweir.control      │
│  边缘层 server  每个 listener 一个 + unix:edge.sock   → router + proxy_cache │
│                设置了 Site.tls 的站点在每个 listener 上另有 server 块        │
│  回源层 server  unix:origin[-noverify][-h2|-grpc].sock → origin (balancer)   │
│  lua_shared_dict: edgeweir_sites / meta / stats / purge / health /           │
│    policy_logs / topstats / logs / bans / challenge / cc / tags；            │
│    每个已发布站点一个 edgeweir_rate_<hex(id)>                                │
│  stream（有四层应用时）每个（端口、协议）一个 server → edgeweir.l4；         │
│    控制中继 unix:l4.sock → edgeweir.l4control；                              │
│    lua_shared_dict（stream 自有）: edgeweir_l4 / l4_state / l4_stats         │
└──────────────────────────────────────────────────────────────────────────────┘
```

| 包 | 职责 |
| --- | --- |
| `cmd/edgeweir-node` | CLI：`enroll`、`run`、`supervise`、`probe`、`healthcheck`、`bans`、`security`、`version`；参数可由 `EDGEWEIR_*` 环境变量提供 |
| `internal/pki` | ECDSA P-256 密钥、CSR、PEM、CA pin 校验、mTLS 配置、续期判断 |
| `internal/identity` | 状态目录里的身份文件（节点布局与探针布局），原子写入，续期时的密钥对原子替换与崩溃恢复 |
| `internal/enroll` | 注册流程（节点 `Enroll`、探针 `EnrollProbe`） |
| `internal/controlplane` | Connect 客户端：pin 通道（注册）和 mTLS 通道（可热替换证书，NodeService 与 ProbeService 共用连接） |
| `internal/configir` | 规范排序、content_hash、diff 应用、校验并生成与引擎无关的 `Plan`（含四层应用，`l4.go`）；源站地址策略（`address.go`） |
| `internal/configstore` | LKG 持久化（current + previous），加载时校验哈希 |
| `internal/render` | 用 Go `text/template` 渲染 `nginx.conf`（含配置 id、每个已发布站点的限速分区、设置了 `Site.tls` 的站点的 `server` 块、OWASP CRS 的位置、四层应用的 `stream {}`）与 ModSecurity 配置，解析 resolv.conf |
| `internal/engine` | `openresty -t`、reload、托管模式下的子进程监督；从 `nginx -V` 读出静态模块（Brotli、Zstandard），汇总 ModSecurity 的拦截日志 |
| `internal/dataplane` | Lua 控制 API 的 unix socket 客户端，站点表 / 清缓存标记 / 健康状态与主动检查标记 / 统计 / 采样访问日志 / 封禁 / 挑战密钥与验证码池 / CC 状态与事件 / 四层应用表与统计的 JSON 结构 |
| `internal/agent` | 运行时主循环、源站凭据、网站证书与 OCSP、清缓存标记集合、统计与访问日志上报、类型化任务（清缓存、预热、sitemap 预热、升级）、挑战密钥与验证码池、CC 事件上报、主动健康检查标记的推送与上报；定义引擎接口 `agent.Engine` 与数据面接口 `agent.DataPlane` |
| `internal/probe` | 区域探针（§2.11）：TCP / HTTP / HTTPS 探测、PROXY protocol v1 头、中位延迟与丢失统计、探测轮次（`edgeweir-node probe` 与节点兼任探针共用）、探针的注册重试与证书续期 |
| `internal/metrics` | 心跳的主机指标（§2.4）：`/proc/stat`、`/proc/loadavg`、`/proc/meminfo`、`/proc/net/dev` 的纯函数解析与两次心跳之间的速率；只在 Linux 上测量 |
| `internal/healthcheck` | 主动健康检查（§2.10）：按应用的 Plan 调度探测，地址策略、请求与 TLS 校验、状态阈值；resolver、dialer 与时钟可替换 |
| `internal/captcha` | 验证码图片：内置 5×7 点阵字体，随机位置、缩放、旋转、倾斜、波浪基线、干扰线与噪点，160×60 调色板 PNG；答案取自 crypto/rand |
| `internal/geoip` | 读取本地 MMDB（内置 IPinfo Lite、运维提供的 City / ASN），经 0600 unix socket（默认 `control.sock.geo`）为 Lua 提供查询；`internal/geoip/check` 在镜像构建时校验下载的 IPinfo Lite |
| `internal/upgrade` | `supervise` 监督进程：经 `upgrade.sock` 接收升级任务，按本机信任策略下载并用 cosign 验签发布包，试运行新版本，失败时回滚（§2.6） |
| `internal/hostinfo` | 上报给控制台的 `NodeInfo`（主机名、非回环非链路本地地址、版本），以及渲染用的本机探测：是否有全局 IPv6（resolver 是否查 AAAA）、能否监听 IPv6、打开文件数硬上限（`worker_rlimit_nofile`） |
| `internal/bans` | 控制台动态封禁的状态：校验 `GetBans` 页、应用（reset、upsert、removed_ids）、持久化 `bans.json`、按数据面键分组（slot）、差量与容量排序 |
| `internal/nft` | 内核封禁：管理 `table inet edgeweir`，生成并以 `nft -f -` 执行事务脚本，去除重叠元素；执行器接口 `nft.Executor`（测试用假的执行器） |
| `internal/retry` | 暂时性失败的重试：指数退避（起始间隔、上限）、总预算、单次尝试的超时；标记为永久的错误立即返回 |
| `internal/fsutil` | 崩溃安全的文件操作：`WriteFileAtomic`（临时文件 → fsync → rename → fsync 目录）、`Rename`、`SyncDir`；所有持久化写入都用它 |
| `internal/version` | 构建信息（版本、commit、提交时间），由 `-ldflags -X` 注入，`edgeweir-node version` 和 `NodeInfo.agent_version` 使用 |
| `internal/testutil`、`internal/pki/pkitest` | 只用于测试：假控制台（内存中的 NodeService，也用于容器冒烟测试）、假数据面（控制 API）、手动时钟（`fakeclock`）、临时内部 CA、合成 MMDB（`geofixture`，`test/geoip` 用它生成 e2e 夹具） |
| `lua/edgeweir/*.lua` | 数据面，见 §3 |
| `internal/gen` | 由 buf 从 `edgeweir/proto` 的 git tag 生成，已提交 |

Lua 模块：`router`（边缘层）、`origin`（回源层与 balancer）、`lb`（选源）、`dns`（解析与地址过滤）、`ipaddr`（地址解析与特殊地址段）、`health`（被动健康检查与主动检查标记）、`upstreamerr`（区分 TLS 失败）、`rules`（缓存规则）、`cachekey`（缓存键与路径规范化）、`purge`（清缓存标记）、`cachetags`（Cache-Tag 解析与索引，§3.4）、`bans`（动态封禁）、`sigv4`（S3 签名）、`store`（站点表）、`tls`（按 SNI 选证书、最低 TLS 版本、OCSP stapling；健康 SNI 与无 SNI 用健康证书）、`probehealth`（探针健康端点，§3.22）、`expressions`（规则表达式与值表达式编译为闭包，函数与派生字段，§3.21）、`policy`（规则阶段与动作、批量重定向、源站覆盖，§3.21）、`ratelimit`（每站点分区的固定窗口计数）、`geoip`（查询 agent 的 GeoIP socket）、`stats`（分钟统计）、`topstats`（Top URL / Top IP）、`accesslogs`（采样访问日志）、`ja4`（TLS 客户端指纹）、`challenge`（挑战、通行凭证、保留前缀）、`affinity`（会话保持，§3.20）、`errorpages`（错误页，§3.19）、`cc`（分级 CC）、`compress`（压缩编码协商）、`waf`（OWASP CRS 的位置与请求上下文）、`control`（控制 API）、`init`；stream 子系统：`l4`（四层应用，§3.23）、`l4control`（stream 侧的控制中继）、`proxyproto`（PROXY protocol v1 / v2 头）。

数据面是 edgeweir-openresty：从固定版本源码构建的 OpenResty 1.31.1.1，带 Brotli、Zstandard 与可选的 ModSecurity 动态模块和 OWASP CRS（§5.1）。

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
  ├─ 检查全部本机参数（路径、resolver、nginx 用户、共享内存大小），有误时退出码 2
  ├─ 取状态目录的运行锁 run.lock（flock；被占用时最多等 30s：enroll --force 或另一个 agent）
  ├─ 准备目录，读取（缺失或将到期时生成）健康证书 health.crt / health.key（§3.22），
  │  读取 credentials.json、certificates.json、purge.json、challenge-keys.json
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
        stats  : 每 60s 从 Lua 取出已结束分钟的统计（有四层应用时含 stream 子系统的），ReportStatsV2 上报
        logs   : 每 10s 从 Lua 取出采样访问日志，ReportLogs 上报
        tasks  : 流通知、心跳 tasks_pending 或约每 30s（抖动）PullTasks
        purges : 同样的时机，只拉取清缓存任务（purge_only）并立即执行
        identity: 每 10s 比较 identity.json 与正在使用的身份，不同（已重新注册）时退出，由监督进程或 systemd 重启
        dataplane: 每 5s 及 nginx (重)启动时检查 GET /v1/status 与 GET /v1/bans，不一致则重推（注册前已运行）
        activehealth: 主动健康检查的判定变化、每次应用、至少每 30s 及 nginx 重启后 PUT /v1/origins/active（注册前已运行，§2.10）
        ocsp   : 每次应用后与每 5 分钟刷新 1 小时内到期的 OCSP 响应，有变化时重推站点表（注册前已运行；应用本身不等 OCSP）
        bans   : 流通知 BANS、约每 30s 的轮询和启动时 GetBans，持久化后推给数据面与内核
        autobans: 每 5s 取出本机自动封禁，ReportBans 上报
        kernel : 封禁或配置变化、被覆盖的封禁需要写入、每 5 分钟刷新受保护地址时同步 nftables（注册前已运行）
        captchas: 配置使用挑战时每 10 分钟生成 256 张验证码装入数据面（注册前已运行）
        security: 每 5s 取出 CC 事件，ReportSecurityEvents 上报
        probe  : 心跳响应 probe=true 时以节点身份运行探测轮次，变为 false 时停止（§2.11）
        supervisor: 有监督进程时每 5s 告知是否健康（最近一次心跳的结论，不早于两个上报间隔，且数据面仍健康）
```

### 2.1 注册（`enroll`）

1. token 来源：`EDGEWEIR_TOKEN` 环境变量（`install.sh` 用这种方式）、`--token-file PATH`（或 `EDGEWEIR_TOKEN_FILE`），或 `--token`（会出现在 `ps` 里，使用时打印警告）。命令行参数优先于环境变量；同一层同时给出 token 和 token 文件时报错；文件内容去掉首尾空白，为空则报错。读取后从环境中删除 `EDGEWEIR_TOKEN`，子进程（`openresty -v`）看不到它。
2. 校验参数：`--server` 必须是 `https://`（节点通道端口）、`wss://` 或 `ws://`（控制台 Web 端口上的 WebSocket 入口，地址不带路径）；`--ca-sha256` 为 64 位十六进制（也接受 `sha256:` 前缀和冒号分隔）；已有身份时除非 `--force` 否则拒绝。`--force` 替换已有身份时取状态目录的运行锁：`run` 正在运行就拒绝（先停止节点），成功后持锁到新身份写完。首次注册不受影响（等待注册的 `run` 本就持锁）。先确认状态目录可写，避免白白消耗一次性 token。
3. 本地生成 ECDSA P-256 私钥，CSR 的 CN 为主机名（控制台会改成 node id）。
4. 用 pin 通道调用 `Enroll`（`wss://` / `ws://` 地址下每个连接先与 `<地址>/node-channel` 完成 WebSocket 握手，子协议 `edgeweir-node-channel`，握手遵循 `HTTPS_PROXY` 等代理变量，`wss://` 本身的证书按系统根证书校验；下面的 TLS 在 WebSocket 内运行，由控制台终结，mTLS 通道同样如此）：`tls.Config` 设置 `InsecureSkipVerify`，由 `VerifyConnection` 做完整校验：服务端证书链中必须有一张证书的 DER SHA-256 等于 pin；以这张证书为唯一根，校验 leaf 的证书链、主机名（默认取 URL 的 host，`--server-name` 可覆盖）和 ServerAuth 用途。校验通过后才发送 token。
5. 校验响应：`ca_certificate_pem` 的哈希必须等于 pin；节点证书必须由该 CA 签发、用于 ClientAuth、公钥与本地私钥一致；CN 与 node_id 不一致时只告警。
6. 原子写入 `node.key`（0600）、`node.crt`、`ca.crt`，最后写 `identity.json`（它是"已注册"的标记）。以 root 执行且状态目录属于服务用户时，文件会交给该用户。`--force` 会先删除旧身份和旧 LKG。
7. 运行中的 agent 只在启动时加载身份；`identity.json` 换成另一个身份时（旧版本的 `enroll --force`、复制来的状态目录）它退出并以新身份重启，续期在交换密钥对前也会核对，绝不把旧节点的证书写到新身份旁。

token 用过即失效，重复注册返回 `permission_denied`（或 `unauthenticated`）。

### 2.2 mTLS 通道

- 客户端证书为节点证书，`RootCAs` 只有内部 CA，`ServerName` 同注册时。
- `GetClientCertificate` 每次握手读取当前证书；续期后重建 transport 并重连 watch 流。
- HTTP/2（ALPN），开启 HTTP/2 ping 检测死连接；支持 `HTTPS_PROXY` 等代理环境变量。
- 控制台返回 `unauthenticated` / `permission_denied`（节点被删除、证书吊销或过期）时，节点记录明确的错误日志，继续按 LKG 服务。证书过期后无法续期，需要重新注册。

### 2.3 获取与应用配置

`GetConfig(revision=0, base_revision=<已应用的 revision>)`：

- **snapshot**：直接进入校验。
- **diff**：以本地 LKG 为基础，listeners / cache_zones / certificates / origin_allowed_cidrs / 平台错误页 / 离线 Host / 四层应用整体替换，按 id upsert 站点，删除 `removed_site_ids`，重新规范排序后计算哈希，与 `diff.content_hash` 比较。基础 revision 不符、哈希不一致或任何错误 → 重新请求快照（`base_revision=0`）。
- LKG 属于其他集群（重新注册到别的集群）时不作为 diff 基础。
- 控制台返回比已应用更旧的 revision（例如从备份恢复）时忽略，继续服务 LKG；控制台恢复备份后凭节点保存的认证回执发布更高的 revision（见 §6「运维」）。

**content_hash**：规范排序后（listeners 按 port，cache_zones 按 name，sites 按 id，certificates 按 id，`origin_allowed_cidrs` 按字节序排序并去重；站点内 domains 按 (name, wildcard, match)（v0.25.0），origins 按 id，cache_rules 按 (priority, id)，稳定排序；`gzip_types`、`brotli_types`、`zstd_types` 与 `excluded_rule_ids` 排序去重；`offline_hosts` 按 (name, wildcard, match) 排序，精确域名在前；站点内 `error_pages.pages` 按状态码；站点内 `bulk_redirects` 按来源，平台与站点规则动作里的 `set_query` 按名称、`remove_query` 按字节序；`l4_apps` 按 id、应用内 `origins` 按 id、`allow_list_ids` / `block_list_ids` 按字节序排序并去重（v0.15.0，与控制台一致：两边都把名单 id 当集合）），把 `revision` 置 0、`content_hash` 置空，`proto.MarshalOptions{Deterministic: true}` 编码后取 SHA-256 小写十六进制。控制台用 protobuf-es 的 `toBinary` 计算，两者都按字段号顺序编码并省略 proto3 默认值，NodeConfig 中没有 map 字段，因此字节一致。跨语言测试向量在 `internal/configir/testdata/`：`content_hash_vector.json`（Phase 0）、`content_hash_vector_m2.json`（M2）、`content_hash_vector_v021.json`（v0.2.1：M2 向量加乱序带重复的允许清单和 `cache_authorized`）、`content_hash_vector_v0110.json`（v0.11.0）、`content_hash_vector_v0120.json`（v0.12.0：M2 向量加 Cache-Tag 保留、乱序的站点错误页、主动健康检查、会话保持、挑战密钥、平台错误页、乱序的离线 Host 与带重复的 required_features；与控制台测试夹具是同一份数据）、`content_hash_vector_v0130.json`（v0.13.0：M2 向量加源站组、带函数与值表达式的规则、乱序的查询参数编辑、config / Origin / compression 动作、浏览器 TTL 与类型化条件的缓存规则、乱序的批量重定向（来源按 UTF-8 字节排序，与 UTF-16 顺序不同）与带乱序 set_query 的平台规则；同样来自控制台）、`content_hash_vector_v0150.json`（v0.15.0：M2 向量加三个乱序的 IP 名单与三个乱序的四层应用，应用与源站 id 超出 ASCII（U+FF01、U+1F600），按 UTF-8 字节与按 UTF-16 排序不同，名单 id 乱序；来自控制台。节点只接受 `[A-Za-z0-9_-]` 的 id，测试另验证换成这类 id 后配置被接受）。

**校验策略**（`configir.Build`）：

| 情况 | 处理 |
| --- | --- |
| 哈希不符（快照或 diff 回退后的快照） | 整个配置拒绝 |
| 任一缓存规则的 `match.expression` 非空 | 整个配置拒绝（旧占位字段；规则表达式用类型化的 `Site.rules` 与 `match.condition`） |
| 规则表达式、值表达式或缓存规则条件不合法（未知 op、字段或函数，参数个数或类型不符，函数嵌套超过 4 层，节点超过 256 个，正则不在子集内，替换串引用不存在的捕获，§3.21）；动作不在其阶段、带别的动作类型的字段或取值越界；带条件的缓存规则同时有路径列表，浏览器 TTL 超过 31536000 秒；批量重定向超过 5000 条、未按来源排序去重或来源 / 目标 / 状态码非法；源站组名不是 `[a-z0-9_-]{1,32}`（任一站点，含停用站点） | 整个配置拒绝 |
| `cluster_id` 与节点所属集群不同 | 整个配置拒绝 |
| 站点、源站、缓存规则 id 含 `[A-Za-z0-9_-]` 以外的字符或超过 128 个字符 | 整个配置拒绝（id 在数据面里作为分隔符的一部分） |
| listener 端口非法 / 重复 | 跳过该 listener 并告警 |
| HTTPS listener | 支持，证书材料通过 mTLS 单独获取 |
| 没有可用 listener | 使用默认端口（80）并告警 |
| cache zone 名非法或与内部 shared dict 重名 | 跳过并告警；没有 zone 时使用内置 `edgeweir_default` |
| 站点引用不存在的 zone / 未指定 zone | 使用第一个 zone |
| 非法域名、单级顶级泛域名（如 `*.com`）、已被前面站点（按 id 顺序）占用的域名（同一写法）；后缀域名是单级顶级域名，正则域名为空、超过 256 字节或 PCRE 编译不过 | 丢弃该域名并告警；站点没有域名则跳过 |
| 非法源站（地址、端口、Host 头、SNI、S3 设置、缺 id） | 丢弃该源站并告警；站点没有源站则跳过 |
| 源站 IP 字面量属于特殊地址段且不在允许清单内（§3.5） | 保留但标记 `forbidden` 并告警，请求得到 502 而不是 404 |
| 允许清单里不是 CIDR 的条目 | 忽略并告警 |
| 缓存键里非法的查询参数、请求头（含 `cookie`、`host`、`x-edgeweir-*`）、Cookie 名 | 忽略该项并告警 |
| 缓存规则 action 未指定、缺 id，或条件列表过滤后变空 | 跳过该规则（绝不放宽成"匹配全部"） |
| `enabled=false` 的站点 | 不对外服务（等同未知域名） |
| 挑战类型、CC 最高级别不是 `cookie302` / `js` / `pow` / `captcha`；通行凭证有效期、PoW 难度、CC 窗口、封禁时长等数值越界（任一站点，含停用站点）；挑战密钥 id 非法、重复、角色未知、同一角色多把或没有 `current` | 整个配置拒绝（数值为 0 取默认值，§3.14） |
| `challenge` 动作不在 `waf-custom` 阶段或类型未知；非 `challenge` 动作带 `challenge` 字段 | 整个配置拒绝 |
| 压缩类型不是小写的 `type/subtype`；Brotli 级别超过 11、Zstandard 级别超过 19（0 取默认值 6、3） | 整个配置拒绝 |
| `Site.waf`（任一站点，含停用站点）：模式不是 `detect` / `block`，paranoia level 不在 1–4，异常分数阈值不在 1–1000，请求体检查上限超过 128 MiB，排除的规则超过 200 条、不在 900000–999999 或未排序去重 | 整个配置拒绝 |
| 已发布站点使用本节点 OpenResty 没有的模块（Brotli、Zstandard、OWASP CRS：`brotli-v1`、`zstd-v1`、`modsecurity-v1`） | 整个配置拒绝，消息写明站点与缺少的能力 |
| 站点错误页（任一站点，含停用站点）：状态码不是 403 / 429 / 502 / 503 / 504、同一状态码出现两次、模板为空或超过 65536 字节；平台错误页超过 65536 字节 | 整个配置拒绝（没有模板时忽略 `intercept_origin_errors`） |
| 离线 Host 的原因不是 `disabled` | 整个配置拒绝 |
| 离线 Host 的名称非法（同域名规则，含后缀与正则写法）、单级顶级泛域名或重复 | 跳过该条并告警 |
| `unknown_hosts`：处理不是 `page` / `close` / `site`，扫描防护的阈值或封禁秒数越界（非 0 时 10–10000、60–86400），`default_certificate` 而未知域名不交给默认网站，或有 `default_site_id` 而没有任何处理交给默认网站 | 整个配置拒绝 |
| `unknown_hosts` 交给的默认网站不在本节点的配置里（停用、删除或未绑定） | 交给它的请求按 `page` 处理并告警 |
| 主动健康检查（任一站点）：路径不是以 `/` 开头的 1–1024 字节可打印 ASCII（不含空格）、方法不是 GET / HEAD、期望状态码不满足 100 ≤ min ≤ max ≤ 599、Host 非法、间隔不在 5–300 秒、超时不在 1–60 秒或超过间隔、阈值不在 1–10；会话保持有效期不在 60–604800 秒 | 整个配置拒绝（数值为 0 取默认值：路径 `/`、GET、200–399、间隔 30 秒、超时 5 秒、阈值 2 / 3、有效期 3600 秒） |
| 已发布站点使用会话保持而配置没有挑战密钥 | 整个配置拒绝 |
| 四层应用（§3.23）：多于 1024 个、未按 id 严格升序（含重复）、id 不是 `[A-Za-z0-9_-]{1,128}`；协议不是 TCP / UDP；端口不在 1024–65535、是任一 listener 的端口（含被跳过的 listener 与 HTTP/3 的 UDP 端口）或同一协议重复；PROXY protocol 版本大于 2，或 UDP 应用接受 / 发送 PROXY protocol；源站不是 1–32 个、id 非法或重复、地址既不是主机名也不是 IP 字面量（含带 zone 的 IPv6）、端口不在 1–65535、权重不在 1–100；`max_fails` 不在 1–100、恢复时间不在 1–3600 秒、连接超时不在 100–60000 毫秒、空闲超时不在 1–86400 秒（都没有默认值）；放行 / 拦截名单引用不存在的 `ip_lists` 或未按字节序排序去重 | 整个配置拒绝 |
| 四层应用的源站 IP 字面量属于特殊地址段且不在允许清单内 | 保留但标记 `forbidden` 并告警，从不连接 |

跳过项作为告警写入 `ReportStatus.message`（`applied with N warning(s): ...`），状态仍为 `APPLIED`，这样单个坏站点不会拖垮整个集群。整个配置被拒绝时状态为 `APPLY_STATE_FAILED`，`applied_revision` 保持为仍在服务的 LKG revision，message 给出原因（包括 `nginx -t` 的原始输出）。确定性失败（哈希、校验、`nginx -t`、reload 未生效、数据面放不下的站点表或四层应用表（507，提示调大 `--sites-dict-mb` / `--l4-dict-mb`））的同一 revision 在 5 分钟内不重复尝试。被截止时间或取消打断的步骤（应用自己的预算、`nginx -t` 的超时、关停）不算确定性失败，下一次同步就重试。获取配置有自己的超时；应用另有预算（凭据、挑战密钥、证书三次 RPC、`nginx -t`（`TestTimeout`，默认 60 秒）、reload 等待与推送各自的超时之和），慢的获取不会挤占它。

**应用**（`agent.apply` → `agent.applyPlan`），在哈希校验和 `configir.Build` 通过之后按以下顺序执行：

1. **S3 凭据与挑战密钥**：Plan 的 `challenge_keys` 引用了本地没有的密钥时，经 mTLS 调用 `GetChallengeKeys` 获取（密钥 16–256 字节），写入 `challenge-keys.json`（0600）；控制台没有给出的密钥保持缺失，数据面检查每 30 秒再要一次。当前与上一份同集群配置都不再引用的密钥从文件中删除。S3 凭据：Plan 引用了本地没有（或版本过旧）的凭据时，先经 mTLS 调用 `GetOriginCredentials` 补齐，写入 `credentials.json`，不再引用的凭据从文件中删除；再把密钥填进 Plan 的 S3 源站。这一步在渲染和 `nginx -t` 之前：RPC 失败算暂时性错误，本次应用失败，下一次同步重试（不计入 5 分钟的拒绝窗口），仍在服务的配置不受影响。
2. **网站证书**：Plan 引用了本地没有的证书（按证书 id 与 SHA-256 指纹）时，经 mTLS 调用 `GetCertificates` 获取，校验私钥与证书匹配、指纹一致后写入 `certificates.json`（0600）。开启 OCSP stapling 的证书使用节点已有的 OCSP 响应；应用完成后 ocsp 循环立即刷新缺失与 1 小时内到期的响应（每次最多 30 秒，失败只告警），有变化时重推站点表。应用从不等待 OCSP 响应方。证书必须覆盖站点的每个域名（带 `tls_pending` 的域名除外：证书尚未覆盖、只走 HTTP 的域名，proto v0.19.0，能力 `tls-pending-domains-v1`；它们不进 HTTPS 监听的 `server_name`，Lua 拒绝它们的 TLS 握手，强制 HTTPS 不跳转），随后附到站点表。获取或校验失败的处理同第 1 步。
3. **渲染** `nginx.conf`，并为每个 cache zone 创建缓存目录；有 HTTPS 监听时先生成 nginx 前缀下的自签名占位证书 `conf/bootstrap.crt`（nginx 加载 TLS 监听需要；握手时 Lua 换成站点证书或健康证书，其他 SNI 直接拒绝）。有站点运行 OWASP CRS 时，ModSecurity 配置写到 `conf/modsecurity-<内容哈希前 16 位>.conf`（文件名随内容变化，正在运行的 nginx 继续用它自己的那份），`nginx.conf` 引用它。渲染结果与当前已安装的内容不同（或引擎未运行）时，写到 `nginx.conf.next`，执行 `openresty -p PREFIX -c nginx.conf.next -e stderr -t -q`，通过后原子改名为 `nginx.conf` 并 reload，之后删除不再引用的 `modsecurity-*.conf`；内容相同则不 reload。
4. **确认 reload 生效**：每个渲染出的 `nginx.conf` 带一个配置 id（不含 id 时渲染结果的 SHA-256 前 16 位），`init_by_lua` 记下它，`GET /v1/status` 返回 `conf_id`。SIGHUP 只是请求 reload：新文件无法应用（例如端口被占用）时 nginx 记录错误并保留旧 worker。agent 在 reload 后最多等 15 秒，直到 worker 报告新的 id；否则该 revision 记为失败，把旧的 `nginx.conf` 写回（之后重启 nginx 时用的仍是正在运行的配置），LKG 继续服务。
5. **清缓存标记、挑战密钥、站点表与四层应用表**：装入清缓存标记（§3.4；`purge.json` 无法读取时先给每个站点加全站标记），配置使用挑战时装入密钥（`PUT /v1/challenge/keys`，失败只告警，数据面检查重试），再把 Plan 转成站点表 JSON，`PUT /v1/sites` 推给 Lua（数据面刚启动时带退避重试：100ms 起翻倍到 2s，最长 15s；内容非法（400）、请求过大（413）或装不下（507）时不再重试；标记、挑战密钥与启动时的封禁同样处理）。标记装不进去不会阻止站点表推送。有四层应用时随后 `PUT /v1/l4` 推送四层应用表（§3.23，同样重试）；应用失败时恢复上一份站点表和四层应用表。
6. 原子写入 LKG（current → previous 备份），更新状态并触发 `ReportStatus`。

是否 reload 只取决于渲染出的 `nginx.conf` 是否变化。除监听、cache zone 和 agent 启动参数外，文件里还有两类随站点变化的内容：每个已发布站点（`enabled` 且有有效源站和域名的站点）一个固定大小的限速分区；设置了 `Site.tls`（HTTPS 与压缩策略）的站点自己的 `server` 块，含域名、HTTP/2、HTTP/3、gzip、Brotli、Zstandard 与密码套件设置。运行 OWASP CRS 的站点另外决定 `nginx.conf` 是否加载 ModSecurity、有哪些请求体上限的 CRS 位置，以及 ModSecurity 配置里的排除规则（§3.18）。所以新增、删除、启用、停用站点都会 reload，改动带 `Site.tls` 的站点的这些设置也会；站点的其余数据只进站点表，经控制 socket 热更新（完整对照见 §3.9）。四层应用的端口、协议与 PROXY protocol 设置决定 `stream {}` 里的 server（§3.23），其余部分热更新。

### 2.4 状态回报、续期、统计

- `ReportStatus`：`applied_revision`、`applied_content_hash`、`state`、`message`、`info`（hostname、agent_version、os、arch、engine=`openresty`、`openresty -v` 得到的版本、非回环地址）、`applied_at`、`data_plane_healthy`（最近一次控制 API 探测结果）、`certificate_not_after`、`origin_health`（被动检查 `source=PASSIVE` 与主动检查 `source=ACTIVE` 的条目，合计最多 2000 条，超出时先保留不健康的，§3.7、§2.10）、`bans`（`BanStatus`，§2.7）、`security`（级别高于 normal 或有升级路径的站点及其升级路径数，最多 2000 个，§3.15）、`metrics`（主机指标，见下）。能力列表总是带 `challenge-v1`、`ja4-v1`、`active-health-v1`（主动健康检查）、`purge-tag-v1`（按 Host 与 Cache-Tag 清缓存）、`prefetch-v2`（设备变体、https URL 与 sitemap 预热）、`probe-health-v1`（探针健康端点，§3.22）、`l4-v1`（四层应用，§3.23）与 `rule-log-v1`（`log` 规则的命中统计，§2.4），Linux 上另带 `metrics-v1`；`brotli-v1`、`zstd-v1` 取自 `nginx -V` 的 configure 参数（`--add-module` 的 ngx_brotli 与 zstd-nginx-module），`modsecurity-v1` 只在 ModSecurity 模块（`--modsecurity-module`，默认在 `--nginx-bin` 所属 edgeweir-openresty 的 `modules/` 下找）与 CRS（`--crs-dir`）都在、并且加载它们的 `nginx -t` 探测通过时上报。这三项在 agent 启动时检测一次，也是站点可以使用的能力（§2.3）。响应中的 `latest_revision` 比已应用的新会触发 sync，`tasks_pending` 触发任务拉取；`report_interval_seconds` 调整心跳间隔（限制在 1s–5min）。
- 主机指标（`metrics`，能力 `metrics-v1`，`internal/metrics`）：每次心跳都带。`cpu_percent` 为整机 CPU 使用率，取 `/proc/stat` 汇总行在两次心跳之间的差（忙碌 = 全部时间减 idle 与 iowait；guest 时间已含在 user / nice 中，不重复计）；`load1` / `load5` / `load15` 取自 `/proc/loadavg`；`memory_total_bytes` 为 `MemTotal`，`memory_used_bytes` 为 `MemTotal − MemAvailable`（没有 `MemAvailable` 的旧内核用 `MemFree + Buffers + Cached`）；`egress_bps` 为非回环网卡（名称 `lo` 或带 loopback 标志）在两次心跳之间发送字节数之差 × 8 / 间隔，取自 agent 所在网络命名空间的 `/proc/net/dev`，计数回退（网卡重建）的网卡计 0；`active_connections` 为数据面 `GET /v1/status` 的 `connections_active`（nginx stub_status 的 `$connections_active` 减去这次查询本身）。第一次心跳的两个速率为 0；两次心跳间隔不足 1 秒时沿用上一次的速率。读不到的文件对应的指标为 0（debug 日志）。非 Linux 构建不带 `metrics`，也不上报 `metrics-v1`。容器内 CPU、负载与内存是宿主机的值，出口带宽是容器网卡的值。
- 续期：响应要求或剩余有效期不足 1/3 时，生成新密钥和 CSR 调用 `RenewCertificate`；节点被停用时控制台以 `permission_denied` 拒绝心跳，剩余有效期不足 1/3 时同样续期（控制台允许停用节点续期，重新启用时证书仍有效）；新证书必须由已固定的 CA 签发（尚不支持 CA 轮换）。先写 `node.key.new` / `node.crt.new`，再依次改名；启动时若发现密钥和证书不匹配且存在 `node.crt.new`，自动完成中断的替换。随后重建 TLS 客户端。
- 统计：Lua 在边缘层 log 阶段按 `<分钟>|<站点id>|<指标>` 累加（请求数、发送/接收字节、命中/未命中、状态码，CRS 站点还有命中的规则 id），另按分钟汇总 Top URL / Top IP。命中的 CRS 规则按次数取每站点每分钟最多的 20 条，上报为 `MinuteStats.waf_rules`（值为规则 id）。`log` 动作的规则（平台与站点规则）命中时，`edgeweir.policy` 在 access 阶段按 `<分钟>|<站点id>|l<规则id>` 计数（本地监听的预热不计），同样每站点每分钟取最多的 20 条，上报为 `MinuteStats.logged_rules`（proto v0.18.0，能力 `rule-log-v1`）；每条规则每 60 秒仍写一行 NOTICE 日志（只含站点与规则 id）。agent 每分钟调用 `POST /v1/stats/drain` 取出已结束的分钟并删除，转换成 `MinuteStats`，每批最多 1000 个分钟桶、带批次序号经 `ReportStatsV2` 上报。未确认的批次保存在 `traffic-spool.json`（0600），总量超过 10000 个分钟桶或 32 MiB 时丢弃最旧的批次。控制台不应答游标查询时照常取出，分钟桶先存为未编号批次（`loose`），读到游标后编号上报（数据面未取出的计数只保留 2 小时）。agent 退出时先以 `{"all": true}` 取出包括当前分钟在内的全部计数存入 `traffic-spool.json`，再停止 nginx。全部批次确认后，agent 用空的游标查询（`batch_sequence` 为 0）上报统计水位 `complete_until`：最近一次成功取出时所在分钟的开始，这之前的分钟都已上报；丢弃过批次时水位停在丢弃的最早一分钟（`lost_from`），24 小时后恢复；控制台据此判断用量窗口是否完整（能力 `stats-watermark-v1`）。Plan 有四层应用时，同一轮还经 `POST /v1/l4/stats/drain` 取出 stream 子系统的已结束分钟（§3.23），转换成 `L4MinuteStats` 放进同一批次（`ReportStatsV2Request.l4_stats`，与站点的分钟桶合计每批最多 1000 个，共用序号与 `traffic-spool.json`）；两次取出都成功才算一次成功的取出（水位才前进）。
- 访问日志：站点设置了采样率（`log_sample_rate`，万分比）时，Lua 在边缘层 log 阶段按 nginx 的请求 id 抽样，记录时间、客户端 IP、方法、Host、改写前的路径（不含查询串）、状态码、发送字节、耗时、缓存状态、响应的 `X-Request-Id`（§3.19，`AccessLog.request_id`），站点开启 JA4 日志时还有 JA4（§3.16），CRS 站点还有命中的规则 id（最多 16 个，`waf_rule_ids`）与是否被 CRS 拦截（`waf_blocked`），放进 `edgeweir_logs` 队列（最多 2000 条，满了计入丢弃数）。agent 每 10 秒调用 `POST /v1/logs/drain`（每次最多取 1000 条），带批次序号经 `ReportLogs` 上报；未确认的批次保存在 `logs-spool.json`（0600），总量超过 10000 条或 32 MiB 时丢弃最旧的批次。

### 2.5 WatchConfig

- 请求带 `known_revision`；首条消息是 `WATCH_EVENT_REVISION`，之后约每 15s 一条 `KEEPALIVE`，有新任务时 `WATCH_EVENT_TASKS`，封禁变化时 `WATCH_EVENT_BANS`（`ban_sequence` 为集群当前的封禁序号，比已应用的新时触发 `GetBans`）。
- 45s 内没有任何消息视为死流，主动断开重连。
- 断线重连退避 1s → 30s，带随机抖动；收到过消息后退避复位。
- 无论流是否健康，约每 30s（0.8–1.2 倍随机）都会 `GetConfig` 与 `GetBans` 轮询一次；已是最新时控制台返回空 diff，开销很小；流恢复后仍保留轮询作为兜底。

### 2.6 类型化任务（清缓存、预热、升级）

控制台只能下发四类任务（`NodeTask` 的 `kind`）：`PurgeTask`、`PrefetchTask`、`SitemapPrefetchTask` 与 `UpgradeTask`，节点不执行其他任何操作。任务幂等；结果没送到控制台时，控制台 5 分钟后再次交出，节点再执行一次。

- **拉取与顺序**：先重报之前没送到的结果和监督进程保存的升级结果，再拉取任务：每次 `PullTasks` 最多 10 个、最多 10 轮。一批里先执行所有清缓存（很快，且不能排在慢源站后面），然后是升级，最后是预热与 sitemap 预热；它们共享一个从拉取时刻算起的时间预算（`--prefetch-budget`，默认 4 分钟，小于控制台再次交出任务的 5 分钟）。清缓存另有一条通道（purges 循环，`PullTasksRequest.purge_only`，proto v0.17.0）：在同样的时机只拉取清缓存任务并立即执行，不必等已经拉取的预热或升级做完；不认识 `purge_only` 的旧控制台在这条通道上也会交出其他任务，它们就在这里照常执行。
- **清缓存**：目标转换成标记（§3.4）：URL、前缀、全站；Host 目标是该 Host 上 `/` 的前缀标记；标签目标是标签标记，标签按控制台的规则校验（1–128 字节可打印 ASCII，不含逗号，首尾不是空格）并按小写比较。URL、前缀与 Host 目标的主机必须是主机名（`*.example.com` 之类的模式不会匹配任何请求）。非法目标（含不合规的站点 id）单独记为失败（`purge_failed`），其余照常生效。标记时间由节点在第一次执行该任务时分配：`max(当前毫秒, 上一个+1)`，按任务 id 记在 `purge.json` 里，同一任务再次交出时沿用原时间；不采用控制台的 `created_at`（事务乱序提交或多实例时钟偏差会让清除静默无效）。
- **预热**：只经本机的本地边缘监听请求 URL（响应像客户端请求一样落进缓存），从不经公开监听：http URL 发往 unix socket `edge.sock`（`--edge-socket`），https URL 经 TLS 发往同目录的 `edge-tls.sock`（有 HTTPS 监听时才渲染），SNI 与 Host 为 URL 的主机名，不校验节点自己的证书。这两个 server 标记为本地（`$edgeweir_local`）：路由层跳过封禁、CC 计数与检查、Under Attack 与 CC 挑战、拒绝类规则（重定向照常）与 CRS，统计、采样日志与 CC 都不计入；客户端地址取 agent 给出的 `127.0.0.1`（`real_ip_header X-Edgeweir-Prefetch-Addr`，即源站看到的 X-Real-IP 与 X-Forwarded-For）。并发 4，单个 URL 超时 60 秒，`Accept-Encoding: gzip, deflate, br, zstd`（浏览器的取值：源站自己压缩的站点缓存浏览器要的那份），Host 头不带端口。2xx/3xx 算成功，源站的重定向原样缓存、不跟随；边缘自己生成的响应带 `X-Edgeweir-Edge-Response`：http URL 被边缘重定向到同一 URL 的 https 形式（强制 HTTPS）时改为预热 https 形式，边缘的其他重定向记为失败（`status`）。缓存键含 scheme：有证书的站点的 http URL 同时预热 https 形式，两者都成功才算成功。没有 HTTPS 监听时 https URL 记为失败（`https_unsupported`），握手失败（节点没有该主机的证书）记为 `other`。设备变体（`PrefetchTarget.variant`）决定 User-Agent：桌面（及未指定）为 `edgeweir-node-prefetch/<版本>`，移动为 `Mozilla/5.0 (Linux; Android 14; Mobile) edgeweir-node-prefetch/<版本>`，它匹配 `edgeweir.cachekey` 的 `MOBILE_RE`（测试从 Lua 文件读出该正则核对两个 User-Agent），缓存键区分设备的站点因此各缓存一份；本版本不认识的变体记为失败（`other`）。预算用完时，尚未开始或被中断的 URL 记为失败。
- **sitemap 预热**（`SitemapPrefetchTask`）：经本机边缘获取 sitemap（与预热相同的连接方式，桌面 User-Agent，重定向不跟随，非 2xx 即失败），每个文档最多 30 秒、解压后最多 50 MiB：以 `1f 8b` 开头的响应体按 gzip 解压，压缩后的大小同样以 50 MiB 为限。`encoding/xml` 流式解析，元素名不看命名空间：`urlset` 取 `url/loc`，`sitemapindex` 取 `sitemap/loc` 并跟随一层（本身是索引的子 sitemap 不跟随）。只保留 Host 按当前 Plan 路由到该站点的绝对 http(s) URL（先查所有站点的精确域名，再查该站点上一级的泛域名，与边缘层选站相同；长度不超过 sitemap 协议的 2048 字节），按文档顺序去重，最多 `max_urls` 个（0 取 1000，上限 10000，够数即停止读取）；子 sitemap 也必须在该站点的 Host 上。随后每个 URL 按每个变体（缺省为桌面）以预热的并发与该批时间预算请求，`succeeded` / `failed` 按 URL × 变体计数。任务的 sitemap 无法使用时直接失败（`sitemap_failed`）；索引中某个子 sitemap 无法使用时，其他子 sitemap 与预热照常进行，结果仍为 `sitemap_failed`（计数为实际的预热）；没有该站点的 URL 时为 `sitemap_empty`；其余与预热的结果相同。
- **升级**：`UpgradeTask` 带 `version`、`archive_url`、`sha256`、`checksums_url`、`signature_url`。执行升级需要监督进程的 socket：`edgeweir-node supervise` 启动 `run` 子进程时经环境变量 `EDGEWEIR_SUPERVISOR_SOCKET` 传入 `<state-dir>/upgrade.sock`（0600）；没有这个 socket 时任务失败（`task_unsupported`，`type=upgrade`）。`created_at` 缺失、早于 30 分钟前或晚于 5 分钟后的任务被拒绝（`upgrade_rejected`）。agent 把任务交给监督进程暂存（最多等 4 分钟）后不回报结果，由监督进程下载、验签并试运行新版本（见下方 M6 记录）：新进程 90 秒内持续健康至少 10 秒才提交（健康指 `ReportStatus` 成功、最新 revision 已应用且数据面健康；agent 每 5 秒告知一次，与心跳间隔无关），否则恢复前一版本和配置快照。监督进程拒绝比当前版本旧的任务（`--upgrade-allow-downgrade` 放行），结果为 `upgrade_rejected`。结果持久化在 `upgrades/state.json`，由之后运行的 agent 在下次拉取任务前回报，控制台确认后清除。监督进程可用（找得到 cosign；配置了 `--upgrade-public-key` 时该文件存在）时，`ReportStatus` 的能力列表带 `self-upgrade-v1`。
- **结果与错误码**（v0.2.1，`message` 仍按旧格式填写，给旧控制台用）：

| 错误码 | 参数 | 含义 |
| --- | --- | --- |
| `prefetch_failed` | `failed`、`total`、`url`、`reason`、`status` | 第一个失败的 URL；`reason` 为 `status`（带 `status`）、`connect_failed`、`timeout`、`https_unsupported`（节点没有可用的 HTTPS 监听）、`other` |
| `prefetch_timeout` | `done`、`total` | 时间预算用完，剩余 URL 记为失败 |
| `task_unsupported` | `type` | 更新的控制台下发了本版本不认识的任务类型：`field_<字段号>`，没有任何内容时为 `unknown`；没有监督进程时的升级任务为 `upgrade` |
| `purge_failed` | 无 | 目标非法或数据面不可用（标记已持久化，数据面恢复后生效） |
| `sitemap_failed` | `url`、`reason`、`status` | 无法使用的 sitemap（任务的 sitemap，或索引中第一个失败的子 sitemap）；`reason` 同 `prefetch_failed`，另有 `invalid`（不是 sitemap：XML 错误、根元素不是 `urlset` / `sitemapindex`、gzip 损坏）与 `too_large`（超过 50 MiB）；站点不在本节点或 sitemap 不在站点的 Host 上为 `other` |
| `sitemap_empty` | `url` | sitemap 中没有该站点的 URL |
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
- **本机自动封禁**：Lua 写入本地字典并排入上报队列（最多 10000 条），agent 每 5 秒 `POST /v1/bans/auto/drain`（每次最多 1000 条），把地址规范化为单地址 CIDR 后经 `ReportBans` 上报；失败的批次留在内存重试，超过 10000 条时丢弃最旧的。未共享的自动封禁在控制台解封后，`GetBans` 的增量页在 `lifted_own_bans` 中带回，agent 经 `POST /v1/bans/release` 删除本机条目，失败时随之后每次拉取重试，直到到期。
- **状态回报**：`ReportStatus.bans`（`BanStatus`）带数据面已应用的序号、条目数、容量、未生效的手动封禁（最多 100 个 id 与总数）、内核条目数，以及因容量丢弃的自动封禁数（数据面淘汰的与 agent 没有发送的，自 agent 启动起）。
- **能力**：`bans-v1` 总是上报；`kernel-ban-v1` 只在 nftables 表可用时上报（§3.13）。数据面的保存与查找见 §3.12。

### 2.8 挑战密钥与验证码池

- **密钥**：每个集群三把（`next`、`current`、`previous`），IR 只带 id 与角色，明文经 `GetChallengeKeys` 获取（§2.3 第 1 步）。数据面拿到的是配置引用且本机持有的全部密钥，`current` 签名、三把都验证（`PUT /v1/challenge/keys`，body `{id, current, keys: [{id, secret}]}`，secret 为 base64；`id` 是密钥集合的哈希，`GET /v1/challenge` 报告它，不一致时重推）。数据面检查的重推与应用串行，不会用较旧配置的密钥集合覆盖应用刚装入的密钥。控制台每天轮换一次，节点只需获取新的 `next`。启动时先从 `challenge-keys.json` 装入，控制面不可达时已签发的凭证仍然有效。配置不再使用挑战时数据面的密钥被清空。
- **验证码池**：配置带 `challenge_keys`（即集群使用挑战）时，agent 每 10 分钟用 `internal/captcha` 生成 256 张不重复答案的图片（160×60 PNG，字母表 `ABCDEFGHJKMNPQRSTUVWXYZ23456789`，5 个字符），经 `PUT /v1/challenge/captchas` 整池替换；数据面没有池（nginx 重启）或池 id 不符时立即重新生成。答案只存在于本机数据面的字典里。

### 2.9 CC 事件

agent 每 5 秒调用 `POST /v1/security/drain`（每次最多 1000 条，满了继续取），事件 id 由数据面生成（`<启动随机数>-<序号>`），转换后经 `ReportSecurityEvents` 上报（每批最多 500 条，id 幂等）；失败的批次留在内存重试，超过 10000 条时丢弃最旧的。未共享的自动封禁在控制台解封后，`GetBans` 的增量页在 `lifted_own_bans` 中带回，agent 经 `POST /v1/bans/release` 删除本机条目，失败时随之后每次拉取重试，直到到期。控制台不支持时只记一次日志。`edgeweir-node security` 打印数据面的挑战与 CC 状态（不取出事件）。

### 2.10 主动健康检查

源站池设置了 `active_health_check` 的站点（能力 `active-health-v1`），agent 按当前应用的 Plan 探测它的每个源站（S3 源站与被地址策略拒绝的源站除外），把判为不健康的源站推给数据面（§3.7）。注册前按 LKG 配置运行。

- **调度**（`internal/healthcheck`）：新检查在间隔内的随机时刻首次探测，之后每个间隔一次，同时最多 64 个探测。每次应用配置都对齐检查集合：参数不变的检查保留状态与时间表，参数变化的从头开始，删除的停止。
- **地址策略**：主机名用系统 resolver 解析（A 记录；没有 A 记录且节点使用 IPv6 时查 AAAA，与数据面相同），丢弃允许清单（`origin_allowed_cidrs`）以外的特殊地址段（§3.5），只连接检查过的地址（按解析顺序，连不上换下一个），不做第二次解析。IP 字面量同样检查。解析失败为 `dns_failed {host}`，全部被拒为 `address_forbidden {address}`。
- **请求**：检查的方法（GET / HEAD）与路径（可带查询串）；Host 取检查的 `host`，其次源站的 `host_header`，最后是源站地址（IPv6 加方括号，非默认端口带端口）；User-Agent `edgeweir-node-healthcheck/<版本>`，`Connection: close`。HTTPS 的 SNI 取源站的 `sni`，其次 `host_header`（去掉端口），最后是地址，按 `--trusted-ca` 或系统 CA bundle 校验（都没有时校验失败，与 nginx 相同），源站池关闭校验时不校验。源站池以 HTTP/2 回源时以 HTTP/2 探测（§3.24）。重定向不跟随，响应体最多读 64 KiB，整个探测的超时为检查的 `timeout_seconds`。
- **判定**：状态码在期望范围内为成功；失败的错误码与被动检查相同：`connect_failed`（连接失败或没有收到响应头）、`timeout`、`tls_failed`、`upstream_status {status}`。源站初始为健康，连续 `unhealthy_threshold` 次失败判为不健康，不健康时连续 `healthy_threshold` 次成功恢复。
- **推送**：判定变化时、每次应用配置后、至少每 30 秒，以及 nginx 重启后（站点表之前），以 `PUT /v1/origins/active` 整体替换不健康源站的集合（最多 10000 个），ttl 为 max(90 秒, 3 × 最长间隔)，agent 停止推送后标记自行过期。没有检查时只在数据面可能还有标记时推送一次空集合。
- **上报**：`ReportStatus.origin_health` 中数据面的条目带 `source=PASSIVE`；主动检查不健康或有连续失败的源站另有一条 `source=ACTIVE`（`healthy`、`consecutive_failures`、`last_failure_at`、`last_error`、`last_error_code` / `last_error_params`，没有 `down_until`）。合计最多 2000 条，超出时先保留不健康的。判定变化时立即上报。
- **合并**：任一检查判为下线的源站不接流量（§3.2）；被动检查的下线持续到它的恢复时间；没有开启主动检查的站点只看被动检查。

### 2.11 区域探针

控制台按区域探测各节点的调度地址（`ProbeService`，proto v0.14.0），用延迟与丢包驱动 DNS 调度。探测由两种进程完成，共用 `internal/probe` 的探测轮次：

- **探针模式**（`edgeweir-node probe`）：不启动 OpenResty，不监听端口。状态目录与节点分开（默认 `/var/lib/edgeweir-probe`，探针布局：`probe.key` 0600、`probe.crt`、`ca.crt`、`probe.json`）。首次运行时没有身份，需要 `--server`、`--ca-sha256` 与一次性探针 token（`EDGEWEIR_TOKEN`、`--token-file` 或 `--token`）：本地生成 ECDSA P-256 私钥与 CSR，以与节点注册相同的 pin 通道调用 `EnrollProbe`（先校验 CA pin 再发送 token；响应的 CA 必须等于 pin，证书须由它签发、用于 ClientAuth、与本地私钥匹配），原子写入身份。控制台不可达或繁忙（`unavailable`、`deadline_exceeded`、`resource_exhausted`、`aborted`）时以 1s → 30s 退避重试同一个 token；token 被拒、pin 不符等其他错误直接退出（状态码 1），缺少注册参数时退出码 2。已有身份时忽略 token，之后全程 mTLS（证书 `CN=<探针 id>`、`O=Edgeweir Probe`，控制台不允许它调用 NodeService）。控制台在 `GetProbeTargets` 中要求续期（`renew_certificate`）或剩余有效期不足 1/3 时，以新密钥调用 `RenewProbeCertificate`（每分钟最多一次），按与节点相同的方式替换 `probe.key` / `probe.crt` 并重建通道。重新注册：删除 `probe.json`（或整个状态目录）后用新 token 启动。
- **节点兼任探针**：`ReportStatus` 响应的 `probe` 为 true 时，agent 以节点自己的 mTLS 身份运行同样的探测轮次，变为 false 时停止（心跳失败时保持现状），agent 退出时一并停止。节点证书照常经 NodeService 续期，`GetProbeTargets` 的 `renew_certificate` 对节点忽略。`node_id` 等于本节点的目标不探测。

**一轮**：`GetProbeTargets`（带 `ProbeInfo`：主机名、版本、os、arch）→ 探测 → `ReportProbeResults`（`started_at` 为开始探测的时间，结果与目标同序；没有目标时也上报空的一轮）。下一轮在本轮开始 `interval_seconds` 之后开始，本轮更久时立即开始。`interval_seconds`、`timeout_ms`、`attempts` 为 0 时取默认值 10 秒、3000 毫秒、3 次，否则限制在 5–60 秒、500–10000 毫秒、1–10 次。RPC 失败（含上报失败，这一轮的结果丢弃）以 1s → 60s 抖动退避重试；凭据被拒时记录错误日志并按最大退避继续。地址不是 IP 字面量（不做 DNS 解析）、端口为 0 或方法未知的目标不探测，记录告警。

**探测**：同时最多 32 个目标，每个目标的 `attempts` 次尝试依次进行，每次尝试从连接开始整体受 `timeout_ms` 限制：

| 方法 | 一次尝试 | 成功 | RTT |
| --- | --- | --- | --- |
| `TCP` | 建立连接后关闭 | 连接建立 | 连接时间 |
| `HTTP` | 连接，`GET /.edgeweir/health`，`Host: health.edgeweir.invalid`，`Connection: close`，User-Agent `edgeweir-probe/<版本>` | 状态码 200 | 发出请求到读到状态行 |
| `HTTPS` | 连接，TLS（SNI `health.edgeweir.invalid`，ALPN `http/1.1`，TLS ≥ 1.2，不校验证书），然后同 HTTP | 状态码 200 | 发出请求到读到状态行 |

`proxy_protocol` 的目标先发送 PROXY protocol v1 头 `PROXY TCP4|TCP6 <本端地址> <对端地址> <本端端口> <对端端口>\r\n`（取自套接字本身的地址，IPv4 映射地址按 IPv4；地址族不一致时 `PROXY UNKNOWN`），TCP 方法也发送后再关闭。HTTP(S) 的 RTT 是已建立连接上的一个往返，与 TCP 的连接时间可比，也反映 nginx 自身的处理延迟。HTTPS 不校验证书：节点用各自生成的自签名健康证书应答（§3.22），探针无从校验；探测只判断可达，不发送机密，只使用响应的状态行。

**结果**：`sent`（实际尝试次数）、`lost`（失败次数：超时、拒绝、重置、TLS 失败、非 200）、`rtt_ms`（成功尝试 RTT 的中位数，偶数个时取中间两个的平均，四舍五入到毫秒且至少为 1；全部失败时为 0）、`error`（最后一次失败的错误码）：

| 错误码 | 含义 |
| --- | --- |
| `timeout` | 连接、TLS 握手、发送或读取在时限内未完成 |
| `refused` | 连接被拒绝 |
| `reset` | 连接被重置或在响应前关闭 |
| `tls` | TLS 握手失败（超时除外），如节点不认识健康 SNI 而中止握手 |
| `status` | 状态码不是 200，或响应不是 HTTP |
| `unreachable` | 其他连接错误（网络或主机不可达等） |

## 3. 数据面

### 3.1 双层缓存

`proxy_cache_valid` 是静态指令，改 TTL 就要 reload。为了让缓存规则（含 TTL）可以热更新，同一个 nginx 里分两层：

```text
客户端 ──► 边缘层 (listen :80 ... default_server；PROXY protocol 监听取头部里的客户端地址)
            access_by_lua  edgeweir.router
              · 删除客户端带来的 X-Edgeweir-* 请求头（读取全部请求头）
              · CDN-Loop 已含本节点 cdn-id → 508 loop-detected；否则追加 cdn-id
              · /.well-known/acme-challenge/<token>：节点自己证书的 token 在这里应答；其他 token
                属于源站自己的证书，照常回源，但不缓存、不挑战（验证服务器解不了挑战）
              · 按 Host 查站点：精确匹配 → 上一级域名的泛域名 → 最长的后缀域名 → 正则域名（按 order，§3.26）；
                查不到 → 离线 Host 503 site-disabled，否则按集群的未知域名处理：404 unknown-host（平台错误页，
                §3.19）、444 关闭连接或交给默认网站，并计入扫描防护
              · 动态封禁：先平台范围、后站点范围；命中且不在平台 allow 名单 → 403 ip-banned
              · 开启 CC 的站点计数（§3.15，IPv4 按地址、IPv6 按 /64）；保留前缀 /.edgeweir/ 在这里应答，永不回源（§3.14）
              · 本地监听（$edgeweir_local，agent 的预热，§2.6）：不查封禁、不计 CC、不挑战，拒绝类规则与 CRS
                不生效（重定向照常），边缘自己生成的响应带 X-Edgeweir-Edge-Response，统计不计入
              · 规则阶段（`challenge` 动作在 waf-custom 中挑战；重定向阶段的规则之后查批量重定向表，§3.21）；
                CC 单 IP（IPv6 为 /64）超限 → 自动封禁并 403 ip-banned（config 规则可为本请求关闭 CC）
              · Under Attack 与 CC 级别：没有足够级别凭证的请求被挑战；allow 规则或平台 allow 名单命中的请求例外
                （config 规则可为本请求开关站点 Under Attack、限制 CC 最高级别）
              · Origin 规则与 config 规则的回源超时写入 $edgeweir_origin_override（X-Edgeweir-Origin）
              · WebSocket（Upgrade: websocket）：原样透传、不缓存；站点关闭时 403（config 规则可覆盖）；
                回源 HTTP/2 的站点也走 HTTP/1.1 回源层
              · 开启 gRPC 的站点的 gRPC 请求（§3.24）：访问阶段末尾转入 @edgeweir_grpc，不缓存、不经 CRS，
                以 grpc_pass 经 HTTP/2 送到 _grpc 回源层；其他请求按站点的回源 HTTP 版本选回源层
              · 非 GET/HEAD：透传（Range 原样转发）
              · 按规则链判断是否可能缓存（带条件的缓存规则按客户端原始请求求值；带 Authorization 的请求见 §3.3）
              · 设置 $edgeweir_cache_zone / $edgeweir_cache_key / bypass / no_cache / Range 模式；
                有标签标记的站点按 Cache-Tag 索引算出键时间（§3.4）
              · 403 / 429 / 503 的拒绝用错误页应答（§3.19）
              · 边缘压缩的站点：回源不带 Accept-Encoding（§3.17）
              · 运行 OWASP CRS 的站点：带 X-Edgeweir-Waf 转入 @edgeweir_waf_<请求体上限>，
                ModSecurity 在该位置检查后再走下面同样的缓存与回源（§3.18）
            proxy_cache $edgeweir_cache_zone; key = cachekey.build(...) [+ slice 范围]
            proxy_cache_lock / background_update / revalidate；stale 由源站层设置的 Cache-Control 扩展决定
            add_header X-Cache $upstream_cache_status always；add_header X-Request-Id（§3.19）
            error_page：nginx 自己的错误（400 / 413 / 414 / 494 / 497 / 500 / 502 / 504）交给 @edgeweir_error，
              换成错误页（§3.19）
            proxy_hide_header X-Request-Id / Cache-Tag / X-Edgeweir-Affinity（缓存命中同样隐藏）
            header_filter_by_lua  edgeweir.router：还原 Cache-Control，记录 Cache-Tag 索引（含 slice
              与后台更新子请求），保留 Cache-Tag 的站点转发它，会话保持的 Set-Cookie（§3.20），
              CRS 拦截换成错误页（只在 CRS 位置有 body filter），缓存规则的浏览器 TTL（§3.3），
              response-transform 与 compression 阶段，选定压缩编码（§3.17）
            内部请求头 X-Edgeweir-Site / -Rules / -Cache-Status / -Origin（proxy_set_header 设置，覆盖客户端同名头）
                │ unix socket，不保持连接（关闭证书校验的站点走 origin-noverify*.sock；回源 HTTP/2 走 *-h2.sock，
                │ gRPC 经 HTTP/2 走 *-grpc.sock，§3.24）
                ▼
          回源层 (listen unix:origin[-noverify][-h2|-grpc].sock)，外部不可达
            access_by_lua  edgeweir.origin
              · 按站点 id 与 X-Edgeweir-Origin 的源站组取源站，lb.order 排序（主动检查标记、会话保持的
                源站在前，§3.2），套用 Origin 规则的 Host、SNI、端口覆盖；DNS 解析并按地址策略过滤；S3 源站签名
              · 候选中有 S3 源站时删除客户端的 x-amz-* 请求头
              · 发往源站前清除内部头；忽略源站的 X-Accel-*（防止源站操纵缓存或内部跳转）
            balancer_by_lua（每次尝试一次）
              · set_current_peer(ip, port, sni)，$edgeweir_ssl_name = sni（证书名校验，§3.6）
              · 重试次数、超时（config 规则可覆盖；WebSocket 等升级连接的读写超时即空闲超时，为 1 小时）、
                按地址+端口+SNI 的连接池（每种回源协议一个 balancer upstream，连接池互不混用，§3.24）；
                换到 Host/签名不同的源站时重建请求
            header_filter_by_lua
              · 源站 5xx 且边缘持有可 stale 的过期副本时断开连接，让边缘层返回 stale（最先判断）。
                边缘到回源层不保持连接：nginx 在复用的连接上失败时会换一条连接重试且不计次数，
                那样一次请求可能把失败的源站请求很多遍（nginx 1.29.7 起 upstream 默认
                `keepalive 32 local`，HTTP/1.1 与 HTTP/2 回源层的 upstream 因此设置 `keepalive 0`，§3.24）
              · nginx 自己生成的回源失败与拦截的源站错误换成错误页（body_filter_by_lua 发送，§3.19）
              · 会话保持：X-Edgeweir-Affinity 告知边缘层要签发的 cookie（§3.20）
              · 按规则链与响应状态/大小决定 X-Accel-Expires 和 stale-* 扩展
                （原 Cache-Control 放进 X-Edgeweir-CC，边缘层还原）
              · 边缘压缩的站点：未编码响应的 Vary 去掉 Accept-Encoding（§3.17）
            log_by_lua · 被动健康检查与错误码（§3.7）
            error_page：nginx 自己的错误（400 / 413 / 414 / 494 / 500）交给 @edgeweir_error：
              边缘可以 stale 时断开连接，否则换成错误页（§3.19）
                │
                ▼
              源站（请求头带 CDN-Loop）
```

边缘层的 proxy_cache 优先采用 `X-Accel-Expires`，nginx 不会把 `X-Accel-*` 转发给客户端。因此规则 TTL 以请求头的形式传到回源层、再以响应头的形式回到边缘层的缓存，全程不需要 reload。首次请求 `X-Cache: MISS`，第二次 `HIT`；不缓存的请求为 `BYPASS`。按 nginx 默认行为，带 `Set-Cookie` 的响应不缓存。

内部头一览：请求方向 `X-Edgeweir-Site`（站点 id）、`X-Edgeweir-Rules`（边缘选中的规则 id，逗号分隔）、`X-Edgeweir-Cache-Status`（边缘缓存状态，用于 stale-if-error）、`X-Edgeweir-Origin`（Origin 规则的源站组、Host、SNI、端口与 config 规则的回源超时，§3.21），在回源层清空后才发往源站；`X-Edgeweir-Waf`（CRS 站点的设置，§3.18）只给 ModSecurity 看，发往回源层之前删除，回源层也清空它；`X-Request-Id`（§3.19）由边缘层设置，回源层与源站看到同一个值；响应方向 `X-Edgeweir-CC`（源站层暂存的原 Cache-Control，边缘层还原并删除）、`X-Edgeweir-Affinity`（回源层要求签发的会话保持 cookie，边缘层隐藏）；对客户端只有 `X-Cache`、`X-Request-Id`、挑战响应的 `X-Edgeweir-Challenge`（§3.14）和错误时的 `X-Edgeweir-Error`（`unknown-host`、`site-disabled`、`loop-detected`、`ip-banned`、`policy-denied`、`policy-unavailable`、`websocket-disabled`、`no-origin`、`origin-unreachable`、`origin-timeout`、`origin-error`、`method-not-allowed`、`origin-signing`、`missing-site`、`unknown-site`、`challenge-unavailable`、`not-found`、`too-large`，nginx 自己的错误的 `bad-request`、`header-too-large`、`uri-too-long`、`body-too-large`、`https-required`、`internal-error`（§3.19），以及 CRS 拦截的 `waf-blocked`）。

### 3.2 选源（`edgeweir.lb`）

| 策略 | 做法 |
| --- | --- |
| `weighted_random` | 按权重随机，重试按权重顺序 |
| `round_robin` | 平滑加权轮询（nginx 的算法），状态按 worker 和站点表版本保存在解码后的站点对象上 |
| `consistent_hash` | ketama 式哈希环（每单位权重 40 个点），键为请求 URI；某源站下线只移动它自己的键 |

源站可以分组（`Origin.group`，空为默认组）。没有 Origin 规则时只用默认组；Origin 规则选中的组单独排序，轮询状态与哈希环按组保存；组里没有源站时 502 `no-origin`（§3.21）。

一次请求最多尝试 3 个源站。重试只在健康的主源之间进行；**所有主源都被标记为下线时才用备用源**；全部下线时仍全部尝试（先主源，fail open），尝试成功即提前结束下线。一次请求内不能在 HTTP 和 HTTPS 之间切换（下一个请求可以）。

"下线"合并两种检查：被动检查（§3.7）标记的源站在恢复时间内不选；源站池开启主动健康检查的站点（站点表 `active_health`），agent 的主动检查标记为不健康的源站同样不选。任一检查判为下线的源站都不接流量；没有开启主动检查的站点只看被动检查，不多读共享内存。会话保持的站点（§3.20）：有效 cookie 指定的源站若在承接流量的那一层（健康的主源；主源全部下线时健康的备用源）里，排在第一个，其余源站按策略排在后面（轮询策略不为这类请求推进轮询状态）；全部下线时不按 cookie 选源。

### 3.3 缓存规则与缓存键

规则按 (priority, id) 排序，首个匹配生效。请求条件（精确路径、路径前缀、扩展名）在边缘层按 nginx 规范化后的 `$uri` 判断；请求条件也可以是一条 `cache` 阶段的类型化表达式（`match.condition`，能力 `rules-v2`，字段与函数同 §3.21），按客户端原始请求（任何改写之前，与缓存键、清缓存一致）求值，这时没有路径列表。响应条件（状态码、大小）在回源层判断。规则链是请求条件匹配的规则，直到第一个"匹配任何响应"的规则为止；回源层取链中第一个响应条件也匹配的规则。

- **遵循 / 覆盖源站缓存头**：覆盖模式用规则 TTL（没有状态码条件时只缓存 200/203/206/300/301/308）；遵循模式交给 proxy_cache 解析源站头，源站没有 Cache-Control/Expires 时才用规则 TTL。
- **stale**：规则的 stale-while-revalidate / stale-if-error 秒数写成 Cache-Control 扩展交给边缘层的 proxy_cache，原头部经 `X-Edgeweir-CC` 还原给客户端。
- **浏览器 TTL**（`browser_ttl_seconds`，最多 31536000）：边缘层 header filter 按规则链、响应状态与大小找出决定该响应的规则；它缓存这个响应时（覆盖模式且 TTL 大于 0；遵循模式且源站的 `Cache-Control` 不含 `no-store`、`no-cache`、`private`），在还原源站头之后把客户端收到的 `Cache-Control` 换成 `max-age=N`，缓存命中同样如此；response-transform 规则仍可改写它。
- **Range**：站点开启 slice 时按 1 MiB 分片获取并缓存，分片范围进入缓存键；不缓存的请求原样转发 Range；其余情况由缓存获取整个对象。
- **Authorization**（RFC 9111 §3.5）：带 `Authorization` 的请求既不查缓存也不存储，除非生效的规则设置了 `cache_authorized`（v0.2.1）；对这类请求，没有该标记的缓存规则按 bypass 规则处理（即使源站返回 `public`）。
- **缓存键**：

  ```text
  <站点id>:<代际号>:<scheme>://<host><path>[?<query>][|d=<m|d>][|h:<名>=<值>...][|c:<名>=<值>...][#<清缓存时间>]
  ```

  path 是 nginx 规范化后的 `$uri`（解码、去掉点段、合并斜杠），与规则匹配、清缓存匹配用的是同一个路径，`/%73tatic/x` 和 `/static/x` 共用一个键。每个可变部分都做百分号转义（`%`、`|`、`#`、控制字符，按位置还有 `?`、`/`、`:`、`=`），任何值都无法伪装成另一个部分。请求头取自全部请求头（与删除内部头用的是同一张表，没有 100 个的上限），重复字段按 HTTP 语义用 `,` 连接。查询参数可全部 / 忽略 / 白名单并可排序；可按设备类型（`Mobi`、`Android`、`iPhone` 等）、请求头、Cookie 区分，可不含 host。Cookie 按源站的方式解析（RFC 6265：只按 `;` 分隔，名称区分大小写，`cachekey.key_cookies`），不用 nginx 的 `$cookie_<名>`（不分大小写、取第一个、还按 `,` 分隔）；键里的 Cookie 重复出现、以别的大小写或百分号编码出现、没有 `=`、或出现在 `,` 之后时，源站各有各的取法，这样的请求不缓存。普通 URL 在默认策略下与 Phase 0 的键相同。

### 3.4 清缓存标记

清缓存从不访问磁盘：每个标记带一个时间（毫秒，§2.6），`cachekey` 把匹配请求的最大标记时间追加到缓存键，清除后的下一次请求在新键上 MISS，旧对象由缓存管理器按 inactive / max_size 淘汰。

- **存储**：`lua_shared_dict edgeweir_purge`（`--purge-dict-mb`，默认 32 MiB）。`u|<站点>|<路径>` 为 URL 标记列表 `[[host, query, 时间], ...]`，`p|<站点>` 为前缀标记列表，`s|<站点>` 为全站标记；`#id` 标记集合 id，`#ver` 每次变化递增（让 worker 缓存失效），`#entries` / `#markers` 为计数器，`#lock` 串行化写入。`GET /v1/status` 读计数器，不遍历字典。
- **匹配**：按站点当前的缓存键策略：不含 host 时忽略 host；查询串按与键相同的规范化、每段百分号解码后比较（`cachekey.purge_query`：控制台按 WHATWG 重新编码输入，客户端各有写法；键本身保留原始查询串，所以只会多清、不会漏清）；标记路径按请求时的写法（百分号编码）下发，装入时按 `$uri` 的规则规范化。
- **上限**：每个站点的 URL + 前缀标记超过 `--purge-markers-per-site`（默认 1000），或标签标记超过 `--purge-tags-per-site`（默认 5000）时，该站点的全部标记合并为一个时间取最大值的全站标记（宁可多刷）。全量替换时某个站点的条目装不下，Lua 把这个站点换成全站标记并在响应的 `collapsed` 里报告，agent 同步合并；整个集合都装不下（507）时 agent 只保留全站标记。
- **集合 id**：`<随机代号>-<序号>`，每次变化序号加一，比较 id 是 O(1)。过期标记（最长 inactive + 1 小时）每分钟最多清理一次。
- **标签标记**：`t|<站点>|<标签>` 为标签标记（标签按小写），`T|<站点>` 为该站点最大的标签标记时间（计入条目数，不计入标记数）；全站合并时标签标记一并换成全站标记，时间取包括标签在内的最大值。标签标记不直接改变缓存键，见下面的 Cache-Tag 索引。
- **重启**：`purge.json`（0600，格式版本 2，含任务时间与标签标记；不认识标签标记的旧 agent 跳过它们）在 agent 和 nginx 重启后保留。nginx 重启后先装标记再推站点表；标记装不进去时退化为"每个有标记的站点一个全站标记"（一分钟后再试完整集合），仍失败也照样推送站点表：站点绝不会因此变成 404。`purge.json` 无法读取时，下一次应用配置给每个站点加一个全站标记。

#### Cache-Tag 索引与键时间

源站以响应头 `Cache-Tag` 给出逗号分隔的标签。标签标记无法像 URL 标记那样在查缓存之前与请求匹配（对象带哪些标签只有缓存时才知道），所以边缘层记录被缓存对象的标签和它所用的键时间，查缓存前据此算出键时间（`edgeweir.cachetags`）：

- **解析**（纯函数）：多个头部值以 `,` 连接；只读前 4096 字节（被截断的最后一个元素丢弃，第 4097 字节恰为 `,` 时保留）；按 `,` 分割，去掉首尾空格和制表符，转小写；丢弃空元素、超过 128 字节的元素和含 0x20–0x7e 以外字节的元素；重复的保留第一次出现。
- **索引**（`lua_shared_dict edgeweir_tags`，`--tag-dict-mb`，默认 64 MiB）：键为缓存键去掉清缓存时间部分（`B`）的 MD5，值为 `<键时间>|<标签>,<标签>,...`（标签总长超过 4096 字节时为 `<键时间>*`，表示该站点的任何标签都会移动它）；`s:<站点>` 表示该站点出现过带标签的响应。有效期为最长的 cache zone `inactive`（站点表 `tag_ttl`），字典满时按 LRU 淘汰。
- **键时间**（边缘层 access，可缓存的请求）：`E_url` 为 URL、前缀、全站标记的时间。站点没有标签标记时（一次共享内存读取 `T|<站点>`），键时间就是 `E_url`，什么都不查。有标签标记时：索引中有该对象 → `max(E_url, 记录的键时间, 对象各标签的标记时间)`；没有（被淘汰、nginx 重启后）→ `max(E_url, 该站点最大的标签标记时间)`，未知对象多回源一次。缓存键为 `B` 或 `B#<键时间>`，与 URL 清除相同：被清除的对象及其所有 slice 不再被查找，既不会以新鲜也不会以 stale 返回。
- **写入**（边缘层 header filter，主请求与子请求）：为缓存取回的响应（`$upstream_cache_status` 为 MISS 或 EXPIRED）在响应有标签、站点标志已设置或站点有标签标记时写入（不带标签的对象因此在无关标签被清除时保留原键）。slice 与后台更新（stale-while-revalidate）的子请求共享主请求的 nginx 变量（不共享 `ngx.ctx`），从 `$edgeweir_cache_key` 取出 `B` 与键时间，用 `$upstream_http_cache_tag` 写入：在 openresty 1.31.1.1 中实测，header filter 在两种子请求中都运行，`$upstream_cache_status` 为子请求自己的 MISS / EXPIRED，`$upstream_http_cache_tag` 为子请求响应的值；缓存命中时它是缓存对象保存的值。重新验证（REVALIDATED）沿用缓存对象的头部，不写入。记录只增不减：更高的键时间替换，相同键时间合并标签（同一对象在不同时间取回的 slice），更低的（比更新的取回先开始的响应）不改变。
- **正确性**：标记时间由节点分配，按应用顺序严格递增。算出键时间 E 的请求看到了它开始前应用的所有标记；它没看到的标签标记 m 应用得更晚，因此 m > E。对象的记录列出其标签后，下一个请求算出的键时间 ≥ m；没有记录时算出 `max(E_url, 最大标签标记时间)` ≥ m。被清除的对象都不会再被查找。同一对象在同一键时间的两次取回恰好同时完成且标签不同时，各 worker 对同一记录的写入不是原子的，可能只保留其中一次新增的标签。
- **对客户端**：边缘层 `proxy_hide_header Cache-Tag`（缓存命中同样适用）；`keep_cache_tag` 的站点由 header filter 从 `$upstream_http_cache_tag` 补回。

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

主动健康检查由 agent 执行（§2.10），结果以 `PUT /v1/origins/active` 推给数据面：`{"ttl": <秒>, "down": [{"site_id", "origin_id"}]}` 是当前被主动检查判为不健康的全部源站，写成 `a|<站点>|<源站>`（带 ttl，agent 停止推送后自行过期）并删除上一次推送中不再出现的条目（`a#keys`）。只有站点表 `active_health` 的站点计入这些标记（§3.2）；`GET /v1/origins/health` 只报告被动检查。

错误码（`last_error_code` / `last_error_params`，v0.2.1；`last_error` 仍为文本）：`connect_failed`、`timeout`、`upstream_status {status}`（源站自己返回 502/503/504）、`dns_failed {host}`、`address_forbidden {address}`、`tls_failed`；其他错误（如缺少 S3 凭据）码为空。TLS 握手或证书校验失败在 nginx 变量里与连接失败完全相同（502，没有响应头时间，字节数为 0）；回源层用 `lua_capture_error_log 64k`（只捕获 error 级别，每个 worker 独立）读取 "while SSL handshaking to upstream" 的日志行，按连接号和上游地址对应到尝试上（`edgeweir.upstreamerr`），对不上的按连接失败处理。

### 3.8 站点表与控制 API

控制 API 只监听 `unix:/run/edgeweir-node/control.sock`（`--control-socket`，目录权限 0750），由 `lua/edgeweir/control.lua` 处理。请求体和响应都是 JSON；未知路径返回 404，方法不符返回 405：

| 方法与路径 | 作用 |
| --- | --- |
| `GET /v1/health` | 存活检查（不检查方法） |
| `GET /v1/status` | `{version, revision, content_hash, site_count, pushed_at, cdn_id, conf_id, purge: {id, entries, markers}, nginx_version, ngx_lua_version, worker_pid, connections_active}`；`version=0` 表示 nginx 启动后还没收到站点表；`connections_active` 为 `$connections_active` 减去这次请求 |
| `PUT /v1/sites` | 原子替换整张站点表；内容非法 400，另一次替换进行中 409，共享内存不足 507 |
| `POST /v1/stats/drain` | 返回并删除所有已结束分钟的统计（含 Top URL / Top IP） |
| `POST /v1/logs/drain` | 返回并删除最多 1000 条采样访问日志 |
| `PUT /v1/purge` | 替换整个清缓存标记集合 `{id, markers}`（装不下的站点合并为全站标记，见 `collapsed`）；标记 `{site_id, type, host, path, query, tag, epoch}`，`type` 为 `url`、`prefix`、`site` 或 `tag` |
| `POST /v1/purge` | 合并标记；装不下时 507（agent 随后全量替换） |
| `GET /v1/purge` | 标记集合状态 |
| `GET /v1/origins/health` | 有失败记录的源站（被动检查） |
| `PUT /v1/origins/active` | 替换主动检查判为不健康的源站集合 `{ttl, down: [{site_id, origin_id}]}`（ttl 1–86400 秒，最多 10000 个）；返回 `{down}`；非法 400，另一次写入进行中 409，内存不足 507 |
| `GET /v1/bans` | 封禁状态 `{sequence, entries, capacity, unapplied, unapplied_ids, auto_evicted, pending_reports}`；`?list=1` 另带 `bans`（最多 1000 条） |
| `PUT /v1/bans` | 全量替换控制台条目 `{sequence, bans: [{id, cidr, scope, site_id, kind, expires_at}]}`，本机自动封禁保留；内容非法 400，另一次写入进行中 409 |
| `POST /v1/bans` | 增量 `{base, sequence, upsert, remove}`：数据面持有的序号不等于 `base` 时 409；`remove` 只删除 id 相同的控制台条目 |
| `POST /v1/bans/auto/drain` | 返回并删除最多 1000 条待上报的本机自动封禁 |
| `POST /v1/bans/release` | 删除控制台解封的本机自动封禁 `{bans: [{site_id, cidr, expires_at}]}`（平台范围的 `site_id` 为 `*`）；到期晚于 `expires_at` 的（解封后再次封禁）保留 |
| `GET /v1/challenge` | `{keys_id, current, keys: [id], captchas, captchas_id, nonce_overflow}`；nginx 重启后为空 |
| `PUT /v1/challenge/keys` | 替换挑战密钥 `{id, current, keys: [{id, secret}]}`（secret 为 base64，16–256 字节；`current` 必须在 `keys` 里或为空）；非法 400，内存不足 507 |
| `PUT /v1/challenge/captchas` | 替换验证码池 `{id, images: [{answer, png}]}`（最多 1024 张，png 为 base64，≤ 64 KiB）；非法 400，内存不足 507 |
| `GET /v1/security` | `{sites: [{site_id, level, escalated_paths, paths: [{path, level}], site_qps, error_percent}], pending_events, dropped_events}`：开启 CC 的站点、最近一次求值的速率 |
| `POST /v1/security/drain` | 返回并删除最多 1000 条 CC 事件 `{events: [{id, site_id, time, kind, level, previous_level, path, address, metric, observed, threshold, top_ips, top_paths}]}` |
| `GET /v1/l4` | 四层应用表状态 `{version, revision, content_hash, apps, pushed_at, down: [{app_id, origin_id, down_until}]}`（§3.23）；`nginx.conf` 没有四层应用时 404，stream 侧不应答时 503 |
| `PUT /v1/l4` | 替换四层应用表 `{revision, content_hash, apps, ip_lists, origin_allowed_cidrs}`；非法 400，另一次替换进行中 409，内存不足 507 |
| `POST /v1/l4/stats/drain` | 返回并删除四层应用已结束分钟的统计 `{stats: [{minute, app_id, connections, refused, peak_concurrent, bytes_received, bytes_sent}]}` |

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
                     "path_prefixes": ["/"], "swr": 30, "sie": 600, "cache_authorized": false}],
    "keep_cache_tag": true,
    "error_pages": {"pages": {"403": "<h1>{{status}}</h1>", "503": "…"}, "intercept": true},
    "active_health": true,
    "affinity": {"ttl": 3600}
  }],
  "tag_ttl": 86400,
  "platform_error_pages": {"unknown_host": "…", "site_disabled": "…"},
  "offline_hosts": [{"name": "old.example.com", "reason": "disabled"},
                    {"name": "example.org", "wildcard": true, "reason": "disabled"}],
  "health_certificate": {"chain_pem": "…", "private_key_pem": "…", "fingerprint": "…"}
}
```

`revision` 和 `cache_generation` 用字符串传递，因为 Lua 的数字是 double。S3 源站带 `s3`（region、bucket、credential_id，以及 agent 从 `GetOriginCredentials` 取得后填入的密钥）；被地址策略拒绝的源站带 `"forbidden": true`。`keep_cache_tag`、`error_pages`（状态码到模板，`intercept` 为拦截源站错误）、`active_health`（计入主动检查标记；检查参数只在 agent 的 `Plan` 里）、`affinity`（cookie 有效期）只在设置了时出现。表级还有 `tag_ttl`（Cache-Tag 索引的有效期：最长的 cache zone `inactive`）、`platform_error_pages`（空模板不出现）、`offline_hosts`、`http_challenges`（HTTP-01 应答）、`ip_lists`、`platform_rules`、`platform_protection`（`{under_attack, challenge}`）；站点还有 `log_sample_rate`、`rules`、`protection`（§3.14、§3.15）、`certificate_id`、`tls`（强制 HTTPS、HSTS、最低 TLS 版本、OCSP stapling 等策略）和 `certificate`（agent 填入的证书链、私钥、指纹与 OCSP 响应）。握手时 `edgeweir.tls` 按 SNI 从站点表取证书，换证书不需要 reload。

`PUT /v1/sites` 在 `edgeweir_sites` 里以版本前缀写入新表（`v<N>:site:<id>`、`v<N>:host:<name>`、`v<N>:wild:<name>`、`v<N>:cfg`（允许清单、cdn-id、HTTP-01 应答、IP 名单与平台规则），使用 `safe_set`，内存不足时整体回滚并返回 507），写完后翻转 `edgeweir_meta` 中的 `version`，请求永远不会看到写了一半的表。上一版本保留到下一次替换，供翻转瞬间仍在处理的请求使用。每个 worker 有三个 lua-resty-lrucache：解码后的站点（含轮询和哈希环状态）与表设置、Host 命中（精确域名；泛域名按上一级域名只缓存一条，随机子域名不增加条目）、Host 未命中（独立的小缓存，1024 条），键里带版本号，翻转即失效；伪造 Host 的洪泛只会冲刷未命中缓存。

shared dict 在 HUP reload 时保留，在 nginx 重启后清空。agent 每 5s（以及收到 nginx 启动事件时）调用 `GET /v1/status`，发现 `version=0`、revision/哈希/cdn-id 与期望不符，或标记集合 id 不同就重新推送。

### 3.9 reload 与热更新

reload 与否只看渲染出的 `nginx.conf` 与已安装的是否不同（§2.3 第 3 步）。

| 变更 | 方式 |
| --- | --- |
| 监听（增删、端口、HTTPS、HTTP/2、HTTP/3、PROXY protocol） | 重新渲染 → `openresty -t` → reload（HUP）→ 确认新配置 id |
| cache zone（增删、大小、inactive） | 同上 |
| 已发布站点集合：新增、删除、启用、停用站点，或站点因没有有效源站或域名被跳过（增删它的固定大小限速分区 `edgeweir_rate_<站点 id 的十六进制>`，`--rate-limit-dict-kb`，默认 256 KiB；其他站点的分区名称和大小不变，计数保留） | 同上 |
| 设置了 `Site.tls` 的站点：`Site.tls` 的有无、域名、HTTP/2、HTTP/3、gzip、Brotli、Zstandard（开关、级别、最小长度、类型）、密码套件档位，以及有没有证书（这些值写在站点自己的 `server` 块里；HTTPS 监听上的块只在站点有证书时生成） | 同上 |
| OWASP CRS：第一个站点开启（加载 ModSecurity 与 CRS）、最后一个站点关闭（卸载）、出现或不再使用某个请求体上限（CRS 位置）、站点排除的规则（ModSecurity 配置） | 同上 |
| 站点的 gRPC 开关（`grpc`：明文监听是否接受 h2c、该站点的 `server` 块是否开启 HTTP/2，§3.24） | 同上 |
| agent 启动参数：resolver（`--resolver`，或启动时读取的 `--resolv-conf`）、回源 CA bundle（`--trusted-ca` 或系统 bundle）、`--sites-dict-mb`、`--purge-dict-mb`、`--tag-dict-mb`、IPv6 探测、worker 与 nginx 用户设置、socket 与目录 | agent 重启后生效：启动后的第一次应用总会写入、检查并 reload（托管模式下是启动 OpenResty） |
| 站点表里的其他内容：源站与源站池设置、缓存规则与 TTL、缓存键、缓存代际号、所用 cache zone、Range 分片与 WebSocket 开关、边缘规则、日志采样率、证书与私钥（同一站点换证书）、OCSP stapling 开关与 OCSP 响应、强制 HTTPS、HSTS、最低 TLS 版本；表级的源站允许清单、cdn-id、HTTP-01 应答、IP 名单、平台规则 | 热更新：`PUT /v1/sites`，不 reload |
| 清缓存（含标签标记） | 热更新：`POST` / `PUT /v1/purge` |
| Cache-Tag 保留、站点与平台错误页、离线 Host、会话保持、主动健康检查的开关 | 热更新：站点表（`keep_cache_tag`、`error_pages`、`platform_error_pages`、`offline_hosts`、`affinity`、`active_health`） |
| 回源 HTTP 版本 | 热更新：站点表（`origin_http2`）；各协议的回源层总是存在 |
| 主动健康检查结果 | 热更新：`PUT /v1/origins/active` |
| 动态封禁 | 热更新：`POST` / `PUT /v1/bans`，平台范围另写 nftables；`--ban-dict-mb` 与 `--ban-capacity` 属于 agent 启动参数 |
| Under Attack、挑战规则、CC 策略、JA4 日志开关、平台 Under Attack | 热更新：站点表（`protection`、`platform_protection`、`rules`） |
| 批量重定向、源站组、缓存规则条件与浏览器 TTL、Origin 与 compression 规则 | 热更新：站点表（`bulk_redirects`、`origins[].group`、`cache_rules`、`rules`） |
| OWASP CRS 的模式、paranoia level、异常分数阈值；请求体上限已有 CRS 位置、没有排除规则的站点开启或关闭 CRS | 热更新：站点表（`waf`） |
| 挑战密钥、验证码池 | 热更新：`PUT /v1/challenge/keys`、`PUT /v1/challenge/captchas`；`--cc-dict-mb` 与 `--challenge-dict-mb` 属于 agent 启动参数 |
| 四层应用的端口、协议、是否接受 PROXY protocol、向源站发送的 PROXY protocol 版本；第一个应用（出现 `stream {}`）与最后一个应用（去掉它） | 重新渲染 → `openresty -t` → reload；已有连接留在旧 worker 直到结束（§3.23） |
| 四层应用的其余部分：源站（地址、端口、权重、备用）、被动健康检查参数、连接与空闲超时、放行 / 拦截名单与名单内容、并发与新建速率上限、端口归属哪个应用 | 热更新：`PUT /v1/l4`；`--l4-dict-mb`、`--l4-socket` 与 `--stream-shutdown-timeout` 属于 agent 启动参数 |

`resolver` 取自 `/etc/resolv.conf`（`--resolv-conf`）的 nameserver（Docker 中为 `127.0.0.11`；IPv6 加方括号；带 zone 的链路本地地址跳过；没有时回退到 `127.0.0.1`），`--resolver` 可直接指定；Lua 按 min(TTL, 30s) 缓存结果（失败 5 秒）；主机没有全局 IPv6 地址时不查询 AAAA。

### 3.10 PROXY protocol

配置了 PROXY protocol 的监听，每个连接都以 PROXY 头开始，所以该 server 设置 `set_real_ip_from 0.0.0.0/0`、`set_real_ip_from ::/0`、`real_ip_header proxy_protocol`：`$remote_addr`、发往源站的 `X-Real-IP` 和 `X-Forwarded-For` 都是 PROXY 头里的客户端地址，而不是负载均衡器的地址（ngx_http_realip_module 文档："The proxy_protocol parameter changes the client address to the one from the PROXY protocol header"）。普通监听保持对端地址。agent 的预热请求从不走要求 PROXY protocol 的监听（§2.6）。

### 3.11 进程管理

- **托管模式**（`--manage-nginx`，容器和 systemd 默认）：`supervise` 时由监督进程运行 OpenResty（§运维），agent 经监督进程的 socket 测试与重载；单独 `run` 时 agent 以子进程运行 `openresty -p PREFIX -c nginx.conf -e stderr -g 'daemon off;'`。首次配置检查通过后才启动；reload 发送 SIGHUP 并确认新配置 id；子进程意外退出时按 1s → 30s 退避重启，重启后自动重推标记和站点表；agent 收到 SIGTERM/SIGINT 时向 OpenResty 发送 SIGQUIT 优雅退出，8s 后仍未退出则 SIGKILL。子进程在独立进程组中，Linux 上设置 `Pdeathsig`，agent 意外死亡时 OpenResty 也会退出。启动前清理残留的 unix socket。nginx 的 stderr 按行转进 agent 日志（`component=nginx`）。
- **非托管模式**：OpenResty 由外部管理，agent 用 `-s reload` 通知，同样确认新配置 id。
- `worker_rlimit_nofile` 取进程的硬上限（os/exec 子进程只继承默认软上限），`worker_connections` 随之调整。

### 3.12 封禁的执行

`edgeweir.bans` 把封禁保存在 `lua_shared_dict edgeweir_bans`（`--ban-dict-mb`，默认 32 MiB），条数上限 `--ban-capacity`（默认 100000，经 `init_by_lua` 传入）：

| 键 | 内容 |
| --- | --- |
| `e\|<范围>\|<4 或 6>/<前缀长度>\|<字节>` | 一条封禁，值为 `<类型>\|<id>\|<到期时间>\|<cidr>`；范围 `*` 为平台、否则为站点 id；字节是掩码后地址的前 ceil(len/8) 个字节；类型 `m`（控制台手动）、`c`（控制台自动）、`a`（本机自动）；TTL 为剩余有效期 |
| `#len\|<范围>` | 该范围控制台条目出现过的前缀长度；全量替换时重算 |
| `#loc\|<范围>` | 该范围有过本机自动封禁（IPv4 /32、IPv6 /64） |
| `#ver` | 长度列表变化时递增；worker 按版本缓存各范围的长度列表 |
| `#seq` | 控制台条目的序号（补零到 20 位，更新不需要新内存） |
| `#live`、`#x\|<分钟>` | 条目数；每分钟到期数在分钟结束后从 `#live` 扣除，全量替换时重新计数 |
| `#q`、`#r` | 本机自动封禁的淘汰队列（写入顺序）与上报队列 |
| `#unapplied`、`#unapplied_more` | 写不下的手动封禁（最多 1000 个 id，其余只计数） |
| `#evicted` | 为腾出空间淘汰或丢弃的自动封禁数 |

- **查找**：边缘层解析站点之后、规则之前。每个请求读一次 `#ver`；平台与站点范围都没有长度时到此为止。否则按各长度掩码客户端地址逐个查找（IPv4 映射的 IPv6 地址也按 IPv4 查），先平台后站点。平台 `allow` 名单命中的地址不受封禁，其余返回 `403`、`X-Edgeweir-Error: ip-banned`。
- **容量与内存**：所有写入用 `safe_set` / `safe_add`，共享内存不会自行淘汰封禁。新条目超出容量或内存不足时，先按写入顺序淘汰最早的本机自动封禁；控制台条目从不在数据面被淘汰。仍然写不下时，手动封禁记为未生效并上报，控制台自动封禁丢弃并计数。
- **本机自动封禁**：`bans.add_auto(site_id, client, ttl_seconds, trigger)` 写入站点范围的封禁：IPv4 地址（/32）或 IPv6 /64（`ipaddr.client_network`；给出 IPv6 地址时取它的 /64），已有控制台条目时只上报；回环与未指定网络（`127.0.0.0/8`、`0.0.0.0`、`::/64`，即节点自己的流量）一律拒绝。排入上报队列（最多 10000 条，满了丢弃最旧的），上报的 `AutoBan.cidr` 即该网络。
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

- **需要的级别**：平台 Under Attack、站点 Under Attack、站点 CC 级别、该路径的 CC 级别取最大值，在规则阶段之后判断（config 规则可为本请求打开或关闭站点 Under Attack、关闭 CC 或限制其最高级别，平台 Under Attack 不受影响，§3.21）；`waf-custom` 的 `challenge` 规则在命中处判断（凭证级别足够就继续后续规则，否则挑战）。`allow` 规则（平台或站点）或平台 allow 名单命中的请求不受 Under Attack 与 CC 挑战，也不被 CC 自动封禁。CC 到 `captcha` 级且策略设置了高难度 PoW 时改用高难度 PoW。
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

- **计数**（`lua_shared_dict edgeweir_cc`，`--cc-dict-mb`，默认 32 MiB）：两个相邻窗口加权的滑动窗口，`上一窗口 × (1 − 已过比例) + 当前窗口`。每个请求对站点一次 `incr`（站点 QPS 开启时），对客户端一次 `incr`（单 IP QPS 开启时；当前窗口计数超过限额一半时才读上一窗口）。客户端按 IPv4 地址或 IPv6 /64 计（`ipaddr.client_network`，如 `2001:db8:1:2::/64`）：持有 /64 的客户端每个请求换一个地址也仍是同一个客户端，也无法用地址填满 CC 存储（挑战凭证同样按 /64 绑定），再读一次站点级别；源站请求与错误（5xx，含全部尝试失败）在 log 阶段计数，缓存命中不计。路径与地址在每个 worker 的有界 Space-Saving（每站点 64 个候选）里计数，每秒把路径计数加到共享字典、提交候选路径和最重的 10 个地址。没有 CC 的站点不做任何额外工作。
- **求值**：每秒由第一个拿到 `#eval|<秒>` 的 worker（不含正在退出的）对每个开启 CC 的站点求值。站点级取站点 QPS 与源站错误率（达到最小请求数才计算）中超出比例最大的条件；条件持续 N 秒升一级（不超过最高级别），全部低于阈值 80% 持续 M 秒降一级，80%–100% 之间两个计时都重置。路径级按单 URL QPS 同样计算，只跟踪 64 条路径（已升级的优先，其次速率最高的），按精确路径（nginx 规范化后的 `$uri`，不含查询串）匹配。请求需要的 CC 级别是站点级与该路径级的较大者。
- **单 IP**：客户端（IPv4 地址或 IPv6 /64）的滑动窗口计数超过 `ip_qps × W` 时，经 `bans.add_auto` 写入站点范围的本机自动封禁（原因 `cc_ip_rate`，指标 `ip_qps`），同一地址在封禁期内只封一次，本次请求返回 403 `ip-banned`。allow 规则或平台 allow 名单命中的请求不触发。
- **事件**：站点级变化（`site_level`，升级时指标为触发条件，降级为 `cooldown`）、路径级变化（`path_level`）、自动封禁（`ip_banned`）排入队列（最多 10000 条，满了丢弃最旧的并计数），带当时的 Top IP 与 Top 路径（各 ≤ 10，近似值），agent 上报（§2.9）。
- **状态**：级别、跟踪与升级路径、Top 地址在 reload 和阈值变更后保留；nginx 重启后计数、级别与未上报事件丢失。站点关闭 CC（或被删除）后，下一次求值（1 秒内）清除它的级别、跟踪与升级路径和 Top 地址，重新开启时从 `normal` 开始；窗口计数在 2W + 2 秒后自行过期，已写入的自动封禁按各自时长到期。

### 3.16 JA4

`edgeweir.ja4` 在 `ssl_client_hello_by_lua` 计算 JA4（FoxIO JA4，BSD-3-Clause；不实现 JA4+ 的其他方法），只为读取 `tls.ja4`（规则表达式或限速键）或开启 JA4 日志的站点计算，写入 `ngx.ctx.edgeweir_ja4`，同一连接的请求（HTTP/1.1 与 HTTP/2）继承。

- `a`：`t`（HTTP/3 请求改为 `q`）、版本（`supported_versions` 中最大的非 GREASE 值；没有该扩展时取请求阶段协商出的版本 `$ssl_protocol`，而不是 JA4 规定的 ClientHello legacy 版本，API 不提供后者）、SNI `d`/`i`、密码套件数与扩展数（两位，最多 99）、ALPN 第一个值的首尾字符（非字母数字时取其十六进制的首尾字符，没有为 `00`）。
- `b`、`c`：排序后的密码套件；排序后的扩展（去掉 `0000`、`0010`）接 `_` 与原顺序的签名算法；各取 SHA-256 前 12 个十六进制字符，列表为空时为 `000000000000`。GREASE 值一律忽略。
- 表达式字段 `tls.ja4`：明文 HTTP 为空字符串；可用于 `waf-custom`、`ratelimit`（也可作为限速键）、`challenge` 规则。站点开启 JA4 日志时采样访问日志带 `ja4`（`AccessLog.ja4`）。
- **近似**：ClientHello 来自 lua-resty-core（`ngx.ssl.clienthello`），它只列出 OpenSSL 认识的扩展；OpenSSL 不认识的扩展（例如 ALPS `4469`、ECH `fe0d`）不计入扩展数和哈希，这类客户端（例如 Chromium）的指纹与其他 JA4 工具的结果不同。规则应使用节点采样日志里看到的指纹。HTTP/3 的请求是否继承握手阶段的 `ngx.ctx` 取决于 nginx 的 QUIC 实现；拿不到时 `tls.ja4` 为空。测试向量 `test/lua/ja4-vectors.json`：JA4 规范文档的算例与按规范构造的用例。

### 3.17 压缩（gzip、Brotli、Zstandard）

站点的 `Site.tls` 为每种算法设置开关、级别（Brotli 1–11，默认 6；Zstandard 1–19，默认 3）、最小长度和内容类型，渲染为站点 `server` 块里的 `gzip*`、`brotli*`（ngx_brotli）与 `zstd*`（zstd-nginx-module）指令，改动时 reload（§3.9）。三种过滤器都只压缩状态为 200、403、404、没有 `Content-Encoding`、长度不低于最小值（长度未知时照样压缩）、类型在列表里（`text/html` 总在）的响应，并给这些响应加上 `Vary: Accept-Encoding`（`gzip_vary on`，任一算法开启时都设置）。

- **协商**（`edgeweir.compress`，纯函数由 `make lua-test` 覆盖）：过滤器本身不看 q 值，客户端接受几种就可能都去压缩。边缘层的 header filter 在压缩过滤器之前运行：按上面的条件列出站点开启且适用于这个响应的算法，再按客户端 `Accept-Encoding` 的 q 值选出一种（RFC 9110 §12.5.3：q=0 不接受；没列出的编码取 `*` 的 q 值；`x-gzip` 等同 gzip；格式错误的项忽略；没有 `Accept-Encoding` 或只剩 identity 时不压缩），q 值相同时 zstd > br > gzip，然后把请求的 `Accept-Encoding` 改写成只含这一种（或删除），只有它的过滤器会压缩。
- **不重复压缩**：源站已经编码的响应（带 `Content-Encoding`）原样返回。
- **缓存**：边缘压缩的站点回源时不带 `Accept-Encoding`（`$edgeweir_upstream_ae`），源站返回未压缩的内容；回源层把这类响应 `Vary` 里的 `Accept-Encoding` 去掉，边缘缓存里每个 URL 只有一份未压缩对象，命中后按每个请求重新协商、压缩。没有边缘压缩的站点照旧把客户端的 `Accept-Encoding` 转给源站，缓存按源站的 `Vary` 区分。
- **规则**：config 规则的 `gzip`、`brotli`、`zstd` 为 `false` 时本次响应不用该算法，`true` 重新允许（只在站点开启的算法里）；compression 阶段的规则（§3.21）给出允许的算法及其顺序，候选只保留列表里的算法，q 值相同时按列表顺序选，空列表不压缩。两者都不绕过缓存：边缘压缩的站点缓存里仍是同一份未压缩对象。不在边缘压缩的站点上，`gzip=false` 删除请求的 `Accept-Encoding`，源站返回未压缩内容，缓存按源站的 `Vary` 区分变体（源站不带 `Vary: Accept-Encoding` 时，同一 URL 可能命中之前缓存的压缩对象）。
- nginx 的 gzip 另有两个条件：带 `Via` 请求头的请求（经过其他代理）不压缩（`gzip_proxied off`），HTTP/1.0 请求不压缩；此时协商选中 gzip 的响应以 identity 返回。

### 3.18 OWASP CRS（ModSecurity）

站点的 `Site.waf` 设置模式（`detect` 只记录，`block` 超过阈值时拦截）、paranoia level（1–4）、入站异常分数阈值（1–1000，CRS 默认 5）、排除的规则 id 和请求体检查上限（字节，0 不检查请求体）。规则来自 edgeweir-openresty-modsecurity 包里的 OWASP CRS 4.29.0（`/usr/share/edgeweir-openresty/crs`），运行时不下载。

- **只在需要时加载**：没有站点运行 CRS 时 `nginx.conf` 不加载 ModSecurity 模块，也没有任何 ModSecurity 指令。有站点运行时，`nginx.conf` 在 main 层 `load_module`，在 http 层读入 agent 生成的 ModSecurity 配置一次（CRS 解析一次，所有位置共用），`modsecurity` 默认关闭；每个边缘 `server` 为用到的每个请求体上限加一个命名位置 `@edgeweir_waf_<上限>`，只在那里 `modsecurity on`，位置里设置该上限（`SecRequestBodyLimit`；上限为 0 时 `SecRequestBodyAccess Off`，请求体既不解析也不交给规则，phase 2 的规则照常检查请求行、查询参数和请求头，见 §5.1 的补丁），其余代理与缓存指令和 `location /` 相同。不运行 CRS 的站点从不进入这些位置，只多执行几个检查 ModSecurity 是否开启的 nginx 阶段处理函数。
- **请求流程**：边缘层 access 阶段照常做完封禁、规则、挑战、CC 与缓存键，然后把运行 CRS 的站点的请求 `ngx.exec` 到对应位置，请求头 `X-Edgeweir-Waf: <站点>;<模式>;<paranoia>;<阈值>` 带上站点设置（客户端带来的 `X-Edgeweir-*` 已先被删除）。ModSecurity 在该位置的 rewrite 与 preaccess 阶段检查请求行、请求头和请求体，早于缓存查找，所以缓存命中的请求同样被检查。内部跳转会清空 `ngx.ctx`：请求上下文先存进 worker 内的表，`$edgeweir_ctx_ref` 记下引用，在 CRS 位置的 access、header filter 和 log 阶段取回（被拦截的请求到不了 access 阶段）；取回后删除 `X-Edgeweir-Waf`，回源层也清空它，源站看不到。
- **生成的 ModSecurity 配置**（`conf/modsecurity-<哈希>.conf`，由 agent 从 IR 渲染）：ModSecurity v3 推荐设置（`SecRuleEngine On`、请求体处理器 XML / JSON、`SecRequestBodyLimitAction ProcessPartial`、参数数量上限、请求体与 multipart 解析错误时拒绝、`SecResponseBodyAccess Off`、`SecAuditEngine Off`、`unicode.mapping`），CRS 的 `crs-setup.conf`，读取 `X-Edgeweir-Waf` 的规则（设置 `tx.blocking_paranoia_level`、`tx.detection_paranoia_level`、`tx.inbound_anomaly_score_threshold`；`detect` 用 `ctl:ruleEngine=DetectionOnly`；值缺失或格式不对时保持 CRS 默认：paranoia 1、阈值 5、拦截），每个有排除规则的站点一条按站点 id 匹配的 `ctl:ruleRemoveById` 规则，最后是 CRS 规则。这些规则都在 CRS 之前的 phase 1 运行。本地规则 id 用 10000–10611，CRS 用 900000–999999。
- **拦截**：`block` 模式下入站异常分数达到阈值时 CRS 的 949110 拒绝请求：`403`，`X-Edgeweir-Error: waf-blocked`，`Cache-Control: no-store`。请求体解析失败等 ModSecurity 推荐规则的拒绝（400）同样带 `waf-blocked`，两者都是错误页（403 的站点模板或内置页，400 的内置页，§3.19）。`detect` 模式下规则照常匹配、计分并记录，但不拒绝。
- **命中结果**：ModSecurity-nginx 加了一个补丁（上游 pull request #374 的回移），提供变量 `$modsecurity_triggered_rules`（匹配并记录的规则 id，按匹配顺序）与 `$modsecurity_intervention`（是否拦截）；规则 id 取自 libmodsecurity 3.0.17 的 `msc_get_rules_messages_rule_ids()`，不解析日志文本，也不写审计日志。边缘层 log 阶段读取它们：每个请求去重后最多 16 个 id，计入 `MinuteStats.waf_rules`（每站点每分钟按次数取最多的 20 条）和采样访问日志（`waf_rule_ids`、`waf_blocked`）。phase 5 的关联规则（980xxx）不计入。请求内容不落盘：ModSecurity 的审计日志关闭；它为每个被拦截的请求写一行 error 日志（含请求行与匹配规则），agent 不转发这些行，只每分钟汇总一次条数。
- **变更**：模式、paranoia level、阈值在站点表里，热更新；加载与卸载模块、新的请求体上限、排除规则的变化会改变 `nginx.conf`（ModSecurity 配置的文件名含内容哈希），经 `nginx -t` 后 reload（§3.9）。刚 reload 而站点表尚未更新时，站点表里的请求体上限在新 `nginx.conf` 里可能没有对应位置：这时用现有最大的上限检查；新配置已经不再加载 ModSecurity 时不检查。
- **开销**（本机 macOS arm64、Colima 4 vCPU 且与其他项目的约 45 个容器共用；节点容器 4 个 worker；oha 1.16.0 在同一 compose 网络内，并发 32、每轮 10 秒、缓存命中、约 400 字节的 whoami 响应，paranoia 1）：

  | 场景 | 吞吐（req/s） | p50 | p99 |
  | --- | --- | --- | --- |
  | 不运行 CRS 的站点，节点未加载 ModSecurity | 92,000–108,000 | 0.19–0.21 ms | 2.5–3.1 ms |
  | 不运行 CRS 的站点，其他站点运行 CRS（模块已加载） | 93,000–117,000 | 0.18–0.20 ms | 2.3–2.7 ms |
  | 运行 CRS 的站点，`detect` | 6,100–8,000 | 1.8–4.9 ms | 10–21 ms |
  | 运行 CRS 的站点，`block`（请求未被拦截） | 6,400–8,200 | 1.5–4.6 ms | 8.8–15 ms |

  不运行 CRS 的站点在两种情况下的差异在本机的轮次间波动之内。运行 CRS 的请求吞吐约为前者的 1/13：4 个核心约 7,500 req/s，折合每个请求约 0.5 ms 的 CPU。内存（nginx 各进程 PSS 之和）：不加载时 30 MiB；加载 CRS 后启动时 71 MiB（CRS 在 master 解析一次，worker 写时复制共享），持续负载后 99 MiB。最后一个 CRS 站点关闭后配置不再加载模块，但 reload 不会让 master 卸载已加载的动态模块：libmodsecurity 与解析过的规则（约 64 MiB）留在 master 里，由 master 派生的 cache manager 继承，直到 nginx 重启（例如升级或重启服务）才释放。

### 3.19 错误页与请求 ID

- **请求 ID**：`map $http_x_request_id $edgeweir_request_id`：客户端的 `X-Request-Id` 符合 `^[A-Za-z0-9._:-]{8,128}$` 时沿用，否则取 nginx 的 `$request_id`（32 个十六进制字符）。边缘层的每个响应带 `X-Request-Id`（`add_header ... always`，错误响应同样），发往回源层的请求带同一个值（回源层原样转给源站），源站自己的 `X-Request-Id` 不转给客户端（`proxy_hide_header`）。错误页与采样访问日志使用同一个 ID。
- **适用范围**：节点生成的 403（封禁、规则与名单拒绝、CRS 拦截）、429（限速）、502、503、504（边缘层的 503、回源层的失败，包括 nginx 自己生成的回源失败）；站点开启 `intercept_origin_errors` 时，还有状态码有站点模板的源站响应。nginx 自己拒绝或出错的请求（400、413、414、500，边缘层的 502 / 504）同样换成页面，见下文「nginx 自己的错误」。节点生成的其他响应（405、421、508，未知域名以外的 404，非 GET/HEAD 请求缺少通行凭证的 403 等）保持纯文本。模板取站点该状态码的模板，没有时用内置页。
- **平台页**：查不到站点的 Host 先查离线 Host（精确域名，或上一级域名的泛域名，与站点域名规则相同）：停用站点 503 `site-disabled`，使用平台的 `site_disabled` 模板或内置页；其余 404 `unknown-host`，使用平台的 `unknown_host` 模板或内置页。离线 Host 在站点表里，按版本缓存为每个 worker 的查找表，伪造 Host 的洪泛不增加共享内存读取。
- **模板**（纯函数）：每个站点表版本编译一次，`{{status}}`、`{{request_id}}`、`{{client_ip}}`、`{{host}}` 与（`rules-v3`）`{{time}}`、`{{path}}` 替换为 HTML 转义（`&<>"'`）后的值，其余内容（包括其他 `{{...}}`）原样发送，不解释模板内容。值：边缘层为 `$edgeweir_request_id`、`$remote_addr`、去掉端口的 Host（请求没有合法的 Host 时为空：nginx 这时报告兜底 server 的名字 `_`）；回源层为请求头 `X-Request-Id`、`X-Real-IP` 与 Host；两层的 `{{time}}` 都是应答时间（UTC，RFC 3339），`{{path}}` 是该层的 `$uri`。
- **内置页**：自包含的 HTML（内联 CSS 与 SVG，无外部 URL 与脚本，按 `prefers-color-scheme` 切换浅色 / 深色），按 `Accept-Language` 选中文或英文（与挑战页相同），显示状态码、访客 → 边缘节点 → 源站的链路（标出失败的一环：403 / 429 / 404 / 停用与边缘层的 503 在边缘节点，502 / 504 与 `origin-unreachable` 的 503 在源站）、简短标题、访客可以怎么做（429 / 5xx 带「重新加载」）、请求 ID、应答时间（UTC，内置页独有的 `{{display_time}}`，模板里原样保留）、域名与客户端地址（`<details>` 点击显示）。页面按语言与种类缓存在每个 worker，只含该种类用到的样式；动效只用 CSS，`prefers-reduced-motion` 时停止。
- **响应头**：`Content-Type: text/html; charset=utf-8`、`Cache-Control: no-store`、准确的 `Content-Length`、`X-Edgeweir-Error: <代码>`；回源层的页面另带 `X-Accel-Expires: 0`，边缘层不缓存。替换源站响应时删除 `Content-Encoding`、`ETag`、`Last-Modified`、`Expires`。
- **在哪里替换**：边缘层 access 阶段的拒绝直接输出页面。回源层自己的失败直接输出；nginx 生成的回源失败（最后一次尝试没有响应头：502 `origin-unreachable`、504 `origin-timeout`）和拦截的源站错误（`origin-error`）在 header filter 中换头、由 body filter 换掉响应体。body filter 只在回源层与 CRS 位置存在（CRS 拦截同样换成页面），边缘层的 `location /` 没有 body filter。可以 stale-if-error 时先断开连接，过期副本优先于任何错误页。
- **nginx 自己的错误**：nginx 自己拒绝或出错的请求也换成页面，只有 502 / 504 会用站点的模板：格式错误的请求（请求行或请求头无法解析，缺少或非法的 Host，`bad-request`）与 CRS 以 400 拦截的请求（如解析不了的请求体，`waf-blocked`）400；请求头或 Cookie 过大（nginx 的 494，`header-too-large`）与发到 HTTPS 端口的明文 HTTP（nginx 的 497，`https-required`），与 nginx 一样应答 400；URI 过长 414（`uri-too-long`）；请求体超过 `client_max_body_size`（100m）413（`body-too-large`）；未捕获的 Lua 错误 500（`internal-error`）；边缘层到回源层的失败 502（`origin-unreachable`）/ 504（`origin-timeout`），即回源层断开连接而缓存没有可用的过期副本时（是否用过期副本在 nginx 生成应答之前决定）。400 / 413 / 414 / 494 / 497 的页面上失败的一环是访客（请求没有通过边缘节点：乱码、超过上限或未加密），不带「重新加载」；500 在边缘节点。`error_page` 把这些状态交给每个边缘层 server 与回源层 server 自己的命名位置 `@edgeweir_error`（494 / 497 用 `=494` / `=497` 原样交给处理函数）；请求行就失败的请求（格式错误、URI 过长）还没有 URI，nginx 不能把它们转进命名位置，`map $uri $edgeweir_error_page` 让它们改走内部位置 `/./edgeweir-error`（nginx 会消去请求路径里的 `.` 段，客户端到不了这个路径）。转入时 `ngx.ctx` 被清空：边缘层的 `router.error_page` 取回 CRS 位置暂存的上下文（`waf.restore`），否则按 `$edgeweir_site` 取站点，该位置的 log 阶段（`stats.log(true)`）像原来的位置一样计数，CRS 的 400 照样计入命中的规则与访问日志的 `waf_blocked`；回源层的 `origin.error_page` 按边缘层的请求头（`X-Edgeweir-Site`、`X-Edgeweir-Rules`、`X-Edgeweir-Cache-Status`）重建站点与缓存规则，边缘可以 stale-if-error 时同样先断开连接。这些页面不经过边缘层的 header filter（没有 HSTS、Alt-Svc、响应规则与压缩），`X-Request-Id` 由处理函数设置；HEAD 只有响应头（`Content-Length` 为页面长度）；子请求（slice、后台更新）保留 nginx 自己的应答。回源层的 502 / 504 仍由 header filter 换成页面，控制 API 没有 `error_page`。

### 3.20 会话保持

- **cookie**：`__ew_affinity=<源站 id>.<到期>.<kid>.<sig>`，`sig` 为 `HMAC-SHA256(密钥, "affinity|" .. 站点 id .. "|" .. 源站 id .. "|" .. 到期)` 的无填充 base64url，到期为 Unix 秒。使用集群的挑战密钥（§2.8）：`current` 签名，`next`、`current`、`previous` 都能验证，集群内任一节点都认同一个 cookie。节点还没有密钥时既不按 cookie 选源，也不签发。
- **回源层**：会话保持的站点读取 cookie，有效时指定的源站在选源时排在最前（§3.2）；源站被禁止或不可用时按其他源站一样跳过，重试可以离开它。header filter 中取最后一次尝试的源站：请求没有有效 cookie、cookie 指向别的源站，或剩余有效期不足一半时，以内部响应头 `X-Edgeweir-Affinity` 告知新的 cookie 值（到期 = 现在 + 有效期）。回源层先删除源站自己发出的同名头。
- **边缘层**：不是来自缓存的响应（`$upstream_cache_status` 不是 HIT、STALE、UPDATING、REVALIDATED）把它变成 `Set-Cookie: __ew_affinity=<值>; Path=/; Max-Age=<有效期>; HttpOnly; SameSite=Lax`（HTTPS 加 `Secure`），保留源站的 `Set-Cookie`；`X-Edgeweir-Affinity` 不转给客户端（`proxy_hide_header`，它可能留在缓存对象里，命中时忽略）。

### 3.21 规则引擎扩展（`rules-v2`）

proto v0.13.0 的规则扩展由能力 `rules-v2` 标明，用到其中任何一项的配置都要求它。Go（`internal/configir/rules.go`）逐项校验 IR，Lua 编译为闭包（`edgeweir.expressions`、`edgeweir.policy`）；语义与控制台规则包的参考求值一致，共享向量同时由 Go 与 Lua 执行。

- **函数**（字符串一律按字节处理）：`lower`、`upper`（只转换 ASCII 字母）、`len`（字节数）、`starts_with`、`ends_with`（空串总是匹配）、`url_decode`（一遍：`%XX` 不分大小写 → 字节，`+` → 空格，不完整的 `%` 原样保留）、`concat`（2–8 个参数）；只在值表达式里、每个表达式各一次：`regex_replace(串, 正则, 替换)`（替换第一个匹配；正则与 `matches` 同一子集与 PCRE 预算；`${1}`–`${8}` 引用捕获，未参与匹配的组为空串，其他 `$` 是字面量）与 `wildcard_replace(串, 通配, 替换[, "s"])`（整串匹配，`*` 匹配任意字节、至多 8 个，`\*`、`\\` 为字面量；默认 ASCII 不区分大小写，`"s"` 区分；捕获取最左放置：首段是前缀，中间每段取上一段之后的第一次出现，末段是不早于当前位置的后缀；捕获是原串的字节；不匹配时返回原串）。参数是字段、字符串常量或另一个调用，嵌套至多 4 层。任何函数算出的字符串超过 8192 字节时求值失败（失败关闭，503 `policy-unavailable`）。
- **IR**：`call`（`field` 为函数名，`value_type` 为返回类型，`children` 为参数）、`field`（参数里的字段）、`const`（字符串常量）；比较的左侧可以是一个值节点（`field` 为空，`children` 只有它，类型规则同字段，`in $列表` 只用于字段）；返回布尔的调用可以单独作为条件。
- **新字段**：`http.request.full_uri`（`scheme://host` 加收到的请求 URI）、`http.request.uri.path.extension`（最后一段路径中最后一个 `.` 之后的部分，小写，没有时为空串；与缓存规则的扩展名是同一个函数）、`http.response.content_type.media_type`（响应 `Content-Type` 去掉参数后的小写媒体类型；response-transform 改写 `Content-Type` 后随之更新）。响应字段可用于 `response-transform` 与 `compression` 阶段。
- **请求快照**：规则读写一张请求值表；改写和请求头动作写到它的副本（第一次修改时复制），原表保留客户端的请求，供批量重定向与缓存规则条件使用；响应阶段不再需要它，响应字段直接写入请求值表。
- **按需计算**：解码站点时记下平台与站点规则、值表达式和缓存规则条件读取的字段：`http.request.full_uri`、`http.request.uri.path.extension`、`http.response.content_type.media_type` 只在有规则读取时计算；没有 response-transform 与 compression 规则（平台或站点）时不运行响应阶段，不读响应头；没有浏览器 TTL 的站点不在 header filter 里判断它；没有 Origin 规则与超时覆盖时不设置 `$edgeweir_origin_override`。不用这些功能的站点每个请求不多做事。
- **重定向**：静态目标或值表达式 `target` 二选一。动态目标必须是不含空白、控制字符和反斜杠的 `http(s)` 绝对 URL（有主机、无用户信息）或以单个 `/` 开头的路径，否则失败关闭。查询串在 `#` 之前处理，片段放回最后：`preserve_query` 时接上请求的查询串（目标已有查询串时用 `&`），再删除原名（每段第一个 `=` 之前的部分，逐字节比较）在 `remove_query` 或 `set_query` 中的参数，按顺序追加 `set_query` 的 `name=值`（值按 RFC 3986 非保留字符以外一律百分号编码）；没有参数时不留 `?`。
- **改写**：静态路径或 `target`；动态结果必须以单个 `/` 开头、不含 `?`、`#`、`\` 与控制字符。查询串默认保留，`preserve_query=false` 时清空，然后按上面的规则删除与追加参数。之后的阶段看到改写后的路径、查询串与扩展名。
- **批量重定向**：站点表的 `bulk_redirects` 在解码站点时建成哈希表；重定向阶段的平台与站点规则之后，按客户端原始请求的 Host 与 `$uri` 先查 `host/path` 再查 `/path`，命中时按条目的状态码重定向，`preserve_query` 时附上原始查询串（查询处理同重定向）。表随站点表热更新，不 reload。
- **Origin 规则**（`origin` 阶段）：源站组、Host、SNI、端口，后命中的规则逐项覆盖。它们与 config 规则的回源超时一起编码进 `$edgeweir_origin_override`，经内部请求头 `X-Edgeweir-Origin`（`g=组;h=Host;s=SNI;p=端口;c=、w=、r=毫秒`）交给回源层。客户端带来的 `X-Edgeweir-*` 在边缘层就被删除，边缘层总用 `proxy_set_header` 覆盖它，回源层只经本机 unix socket 接受边缘层的请求，并在发往源站前清空它。回源层只在选中组的源站里负载均衡；端口覆盖作用于组内每个源站，Host 覆盖替换源站自己的 Host（S3 源站不受影响，签名用的 Host 照旧），SNI 覆盖替换 TLS 名称（也进入连接池的键），没有 SNI 覆盖时 TLS 名称照常由源站的 SNI 或 Host 推出；超时覆盖 balancer 的连接、发送、读取超时。会话保持、健康检查与选源顺序不变。
- **config 动作**：在 `cache_bypass`、`force_https`、`gzip` 之外，`gzip=true`、`brotli`、`zstd`（§3.17）、`websocket`、`under_attack`（站点级，§3.14）、`cc_enabled`（`false` 时本请求不受 CC 级别挑战与 CC 单 IP 封禁，计数照常）、`cc_max_level`、三个回源超时（连接 100–120000 毫秒，发送与读取 100–3600000 毫秒）、`log_sample_rate`（本请求的采样率，万分比）；新字段只在 `config` 阶段可用，后命中的规则逐项覆盖。`gzip=false` 不绕过缓存。
- **compression 阶段**：在边缘层 header filter 中，response-transform 之后运行平台与站点的 `compression` 规则，可读响应字段；动作 `compression` 给出有序的算法列表（`zstd`、`br`、`gzip` 的子集，可为空），后命中的覆盖前面的（§3.17）。
- **GeoIP 与 JA4**：缓存规则条件、值表达式和函数参数读取 GeoIP 字段或 `tls.ja4` 的站点同样查 GeoIP、计算 JA4。

**rules-v3**（proto v0.22.0）在上面的基础上增加：

- **字段**：`http.request.cookies.<名称>`（`Cookie` 头中第一个同名 Cookie 的原始值，以 `;` 分隔，一对及其名称和值两侧的空格、制表符忽略，没有 `=` 的一段跳过，多个 `Cookie` 头以 `; ` 连接；名称为 token，区分大小写）、`http.request.uri.args.<名称>`（查询串中第一个同名参数的原始值，名称与值都不解码，随改写变化）、`http.referer`、`http.user_agent`（请求头的别名，请求头动作改写它们时一起更新）、`http.request.version`（`$server_protocol`）、`http.request.scheme`、`http.request.id`（`$edgeweir_request_id`）、`http.request.timestamp.sec`（`ngx.req.start_time()` 取整）、`edge.server_port`、`ip.geoip.as_name`（GeoIP agent 与 ASN 一起返回：IPinfo Lite 的 `as_name`，ASN MMDB 的 `autonomous_system_organization`；需要 `geoip-asn-v1`）、`http.response.cache_status`（响应阶段读 `$upstream_cache_status`，节点自身生成的响应为空串）。Cookie 与参数只解析规则读到的名称；这几组字段都只为读取它们的站点计算。
- **函数**：`url_encode`、`base64_encode`、`base64_decode`（标准与 URL 安全字母表、有无填充；先按规则校验再交给 `ngx.decode_base64`，无效时为空串）、`md5`、`sha1`、`sha256`（小写十六进制）、`substring`（第二、三个子节点是 `value_type` 为 `number` 的 `const`，起点 -65536–65536、长度 0–65536）、`to_string`（参数可为任何类型）。`wildcard` / `strict_wildcard` 比较复用 `wildcard_replace` 的匹配（整串、最左放置）。
- **报头值**：`request_header` / `response_header` 可带 `target`（值表达式，此时 `value` 为空，不能与 `remove` 同用）。算出的值超过 4096 字节、含控制字符或求值出错时跳过这条动作，请求照常继续；每条规则每节点 60 秒在 `edgeweir_policy_logs` 字典记一次，写一条 NOTICE（`header value skipped site=… rule=…`）。`append` 在响应已有的同名头之后再加一行，之后的规则读到以 `, ` 连接的全部行。
- **查询参数**：`set_query` 的一项可带 `expression`（`value` 为空），重定向与改写时按当时的请求值求出、百分号编码；求值失败与动态目标一样失败关闭。
- **303 与错误页**：重定向规则可用 303（批量重定向仍为 301、302、307、308）；错误页模板增加 `{{time}}`（UTC，RFC 3339）与 `{{path}}`（`$uri`），内置页面的时间改用内部占位符，模板里的 `{{display_time}}` 原样保留。

### 3.22 探针健康端点（`probe-health-v1`）

区域探针（§2.11）用它判断节点的监听是否可用，与站点配置无关：

- **HTTP**：边缘层 access 阶段最开始（CDN-Loop、HTTP-01 应答、站点查找、封禁、规则、CC、挑战之前），对任意 Host 的 `GET`（或 `HEAD`）`/.edgeweir/health`（规范化后的 `$uri`，查询串不影响）返回 `200`，正文 `ok`，`Content-Type: text/plain`、`Content-Length: 2`、`Cache-Control: no-store`。它不经过缓存与回源，不计入站点统计，不进入采样访问日志（这两者都需要站点），不受封禁与规则影响。其他方法与路径照常处理（`/.edgeweir/` 仍是挑战的保留前缀）。所有监听都提供它，包括 PROXY protocol 监听（nginx 先解析 PROXY 头）与本地 `edge.sock`。
- **HTTPS**：`ssl_client_hello` 与 `ssl_certificate` 阶段（`edgeweir.tls`）对 SNI `health.edgeweir.invalid`（不区分大小写）或没有 SNI 的握手使用节点的健康证书；站点表里没有健康证书时与其他未知 SNI 一样中止握手。`.invalid` 是保留顶级域，不会与站点域名冲突。这样建立的连接只能访问健康端点：其他请求（含其他方法）在 access 阶段一开始返回 `421`，`X-Edgeweir-Error: sni-host-mismatch`，不进入站点逻辑。
- **健康证书**：agent 启动时读取状态目录中的 `health.crt` / `health.key`（均为 0600）；缺失、损坏、不是健康证书或 30 天内到期时生成新的：ECDSA P-256 自签名，`CN` 与唯一 SAN 为 `health.edgeweir.invalid`，有效期 10 年，ServerAuth。它与站点证书一样经控制 socket 随每张站点表下发（`health_certificate`，存在站点表配置项 `v<N>:cfg` 中），不写进 `nginx.conf`；nginx 加载 TLS 监听所需的静态证书仍是占位证书 `conf/bootstrap.crt`。证书不由任何 CA 签发，探针不校验它。

### 3.23 四层转发（`l4-v1`）

`NodeConfig.l4_apps`（proto v0.15.0）是集群的 TCP / UDP 应用：每个应用在每个节点的一个端口上把连接转发给它的源站。

**渲染**：Plan 有四层应用时 `nginx.conf` 带 `stream {}`，每个（端口、协议）一个 `server`：`listen <端口> reuseport`（UDP 另加 `udp`，接受 PROXY protocol 时加 `proxy_protocol`，监听 IPv6 时另有 `[::]:<端口>`）。`server` 不写应用 id：preread 按 `$protocol:$server_port` 在四层应用表里找应用，端口换了归属的应用也不 reload。连接到源站的方式由 nginx 按 `server` 决定，因此 PROXY protocol 的设置与端口、协议一样是结构性的：

| 应用 | 转发 |
| --- | --- |
| 不向源站发送 PROXY protocol | nginx 自己转发：`proxy_pass` 到由 `balancer_by_lua` 选源站的 upstream |
| 发送 v1 / v2，监听不接受 PROXY protocol | 同上，加 `proxy_protocol on`（v1）或 `proxy_protocol v2`。OpenResty 1.31.1.1 的 nginx 已支持 `v2`（实测头部与规范一致：12 字节签名、`0x21`、`0x11` / `0x21`、地址块，不带 TLV），地址为客户端连接的两端 |
| 监听接受 PROXY protocol 并向源站发送（TCP） | Lua 中继（`content_by_lua`）：stream 没有 realip 模块（与 OpenResty 官方构建相同，未编译 `stream_realip`），nginx 写进头部的是负载均衡器的地址；中继写入收到的头部里的客户端地址 |

stream 子系统有自己的 `lua_shared_dict`，http 子系统的 Lua 看不到它们：`edgeweir_l4`（`--l4-dict-mb`，默认 32 MiB：当前与上一版四层应用表，只用 `safe_set` 写入，不会被淘汰）、`edgeweir_l4_state`（8 MiB：被动健康、连接计数、新建速率）、`edgeweir_l4_stats`（4 MiB：分钟统计）。控制 API 把 `/v1/l4` 的请求经本机 unix socket `l4.sock`（`--l4-socket`）转给 stream 侧的 `edgeweir.l4control`（请求为一行 `<方法> <路径> <长度>` 加请求体，应答为一行 `<状态码> <长度>` 加 JSON），agent 只使用 `control.sock`。

**reload 与已有连接**：增删端口、改变协议或 PROXY protocol 设置会 reload（第一个应用出现时生成 `stream {}`，最后一个应用删除时去掉它）。按 nginx 文档，reload 时旧 worker 关闭监听 socket，继续服务已有的连接，全部结束后退出。实测（OpenResty 1.31.1.1）：reload 前建立的 TCP 连接在 reload 后照常双向转发，旧 worker 在最后一个连接结束后退出；没有连接的旧 worker 立即退出。UDP 会话不跨 reload：`reuseport` 让每个 worker 有自己的 socket，旧 worker 关闭后，客户端之后的数据报进入新 worker 的新会话（可能选到另一个源站），旧会话在空闲超时后结束。`--stream-shutdown-timeout`（默认 0，不设置）渲染为 `worker_shutdown_timeout`：时间到后旧 worker 关闭它仍在服务的全部连接（这是 main 级指令，HTTP keep-alive 与 WebSocket 连接同样受影响），这些会话照常经过 log 阶段（统计与计数）；不设置时频繁 reload 会留下多个旧 worker，直到它们的连接结束。新端口在 reload 之后、四层应用表推送之前的一瞬间（毫秒级）没有应用，那时的连接被关闭。

**热更新**：源站、权重、备用、被动健康检查参数、超时、名单及名单内容、连接限制经 `PUT /v1/l4` 写入（`{revision, content_hash, apps, ip_lists, origin_allowed_cidrs}`，`ip_lists` 只含应用引用的名单），不 reload：表以版本号写入后翻转 `version`，每个 worker 按版本缓存解码后的表（每个连接读一次 `version`）。nginx 重启后 `GET /v1/l4` 的 `version` 为 0，数据面检查（§2.3）重推。

**preread**（每个 TCP 连接、每个 UDP 会话的第一个数据报）：

- 客户端地址：监听接受 PROXY protocol 时取头部里的地址（头部为 `UNKNOWN` 时用 TCP 对端），否则为对端地址。
- 依次检查：放行名单（应用有放行名单时只放行名单内的地址）、拦截名单、每秒新建连接（本节点、按秒计数）、并发连接（本节点）。拒绝时会话以状态 403 结束，什么都不转发：TCP 关闭连接（客户端已发送而未读的数据使内核回 RST），UDP 丢弃数据报；计入 `refused`。被拒的 UDP 客户端每个数据报都开始一个新会话，各计一次。
- 选源：健康的主源按权重随机排序；主源全部下线时只用健康的备用源；全部下线时全部尝试（主源在前，fail open，成功即结束下线）。特殊地址段的 IP 字面量源站（`forbidden`）从不使用。每个连接最多尝试 3 个源站。主机名源站在 preread 用 `edgeweir.dns` 解析（与站点相同的 resolver、缓存与地址策略：特殊地址段只在 `origin_allowed_cidrs` 内可用），解析失败或地址全被拒计一次失败并跳过。

**转发**：`balancer_by_lua` 每次尝试设置一个源站；nginx 只在连接失败（拒绝、超时）时换下一个（`set_more_tries`）。连接超时与空闲超时（`proxy_timeout`：两个方向都没有数据的时间；stream 里 `set_timeouts` 的发送与读取超时都是它）按应用每个会话设置。被动健康检查：连接失败（以及 UDP 会话以 502 结束，例如源站回 ICMP 不可达）计数，计数在第一次失败后 `fail_timeout_seconds` 内有效、成功清零，达到 `max_fails` 后该源站下线 `fail_timeout_seconds` 秒；状态在 `edgeweir_l4_state`，按"应用 + 源站"区分，`GET /v1/l4` 列出下线的源站（不随心跳上报）。

**PROXY protocol 中继**：按同样的顺序依次连接源站（连接超时，失败计入健康检查），写入 v1 或 v2 头（`edgeweir.proxyproto`：源地址与端口、目的地址与端口都取收到的头部；地址族不同时 IPv4 写成 IPv4 映射地址），然后两个 light thread 双向复制（每次最多 64 KiB），任一方向关闭、写失败或两个方向在空闲超时内都没有数据时结束。限制：每个数据块经过 LuaJIT 与 cosocket，吞吐低于 nginx 自己转发；不支持半关闭（一侧关闭即结束连接，与 nginx 默认的 `proxy_half_close off` 相同）。

**UDP**：不设置 `proxy_responses`，源站对一个数据报回复多少个都转发给客户端（回显、DNS、QUIC、游戏协议都适用），会话在空闲超时后结束；所以一个客户端地址与端口在空闲超时内算一个并发会话，需要快速释放会话的应用（如 DNS）应设较短的空闲超时。UDP 不支持 PROXY protocol。

**统计**：每个应用每分钟上报 `connections`（接受的连接或会话）、`refused`、`peak_concurrent`（该分钟见到的最大并发数：接受连接时与每 10 秒采样时记录，只有长连接的分钟同样有值）、`bytes_received` / `bytes_sent`（来自客户端 / 发往客户端）。字节在连接进行中计入：每个 worker 每 10 秒读取它正在服务的会话的 `$bytes_received` / `$bytes_sent`（经 lua-resty-core 使用的变量 API；会话在 log 阶段移出采样表之后不再读取），把增量记入当前分钟，log 阶段记入剩余部分；中继会话由 Lua 计数。reload 后旧 worker 继续采样，直到最后一个会话结束，所以长连接至少每分钟计入一次。agent 与站点统计一起取出、同批上报（§2.4）。删除最后一个应用的 reload 会去掉 `stream {}`，尚未取出的分钟（最多约两分钟）与旧 worker 上仍在进行的连接的统计随之丢失。

**连接计数**：并发数在共享内存中（每个应用一个总数，另按 worker 进程记录），preread 加、log 阶段减。worker 异常退出（没有 log 阶段）时，每 30 秒一次的检查发现它已不在 `ngx.worker.pids()` 里（登记超过 60 秒），把它的计数从总数中减去，上限不会一直被占满。nginx 重启时计数清零。心跳的 `active_connections` 是 nginx 的全局计数，含四层的客户端连接、上游连接与 UDP 会话。

### 3.24 回源 HTTP/2 与 gRPC（`origin-http2-v1`）

`OriginPool.protocol`（proto v0.21.0）为 `ORIGIN_PROTOCOL_HTTP2` 的站点以 HTTP/2 请求源站，`OriginPool.grpc` 再让 gRPC 请求经 HTTP/2 端到端转发（只能与 HTTP/2 一起开启，否则整份配置被拒绝）。站点表字段 `origin_http2`、`grpc`；控制台在站点用到时要求能力 `origin-http2-v1`。

- 依据（nginx 1.31.1 的文档与源码，即 edgeweir-openresty 1.31.1.1 的内核，`nginx -t` 实测）：`proxy_http_version 2`（1.29.4 起，`ngx_http_proxy_v2_module`）对 `https` 上游经 ALPN 只提供 `h2`，对 `http` 上游直接发送 HTTP/2 连接前言（prior knowledge）；不检查协商结果，也没有回退，源站不支持时这次尝试失败。设置了 `proxy_set_header Host` 时它把 Host 作为普通的 `host` 头发送、不发 `:authority`（1.31.4 起改为总发 `:authority`）；`grpc_pass` 相同。`grpc_pass` 默认不缓冲、透传 trailers，请求体边收边发，双向流可用；`grpc_pass` 的地址可以带变量（`grpc://` / `grpcs://`），按名字找到 upstream 块。明文监听的 `http2 on` 按连接前言区分 HTTP/1.x 与 h2c；HTTP/2 请求选中的 server 没有开启 HTTP/2 时，nginx 返回 421。
- 回源层每种协议各一套（校验 / 不校验 TLS 各一个 server）：`origin[-noverify].sock` 以 HTTP/1.1 回源；`origin[-noverify]-h2.sock` 以 `proxy_http_version 2` 回源，不设置 `Connection`、`Upgrade`（HTTP/2 禁止这些头，模块默认把它们清空）；`origin[-noverify]-grpc.sock` 开启 `http2`（边缘以 h2c 连入）并以 `grpc_pass $edgeweir_grpc_scheme://edgeweir_balancer_grpc` 回源，`$edgeweir_grpc_scheme` 由 `$edgeweir_upstream_scheme` 映射（`https` → `grpcs`）。三者共用 `edgeweir.origin` 的选源、签名、错误页与健康统计。
- 连接池：`balancer_by_lua` 的连接池属于各自的 upstream 块（`lscf->balancer`），HTTP/1.1、HTTP/2 与 gRPC 的连接不能互用（HTTP/2 模块从连接池的清理回调里找自己的连接数据，找不到就失败），所以每种协议一个 balancer upstream：`edgeweir_balancer`、`edgeweir_balancer_h2`、`edgeweir_balancer_grpc`，都设置 `keepalive 0`（§3.6）。
- 边缘层（`edgeweir.router`）：按站点的协议把 `$edgeweir_origin_layer` 设为 `_h2` 回源层；WebSocket 升级只能经 HTTP/1.1 代理，仍走 HTTP/1.1 回源层。开启 gRPC 的站点上 `Content-Type` 为 `application/grpc`（可带 `+…` 后缀或参数；`application/grpc-web` 不算）的请求，在访问阶段末尾经 `ngx.exec` 转入 `@edgeweir_grpc`，请求上下文与 CRS 位置一样经 `$edgeweir_ctx_ref` 带过去（`edgeweir.waf.stash_ctx`）。该位置以 `grpc_pass grpc://$edgeweir_origin_layer` 把请求经 h2c 送到 `_grpc` 回源层，不缓存，关闭 server 块开启的压缩，`client_max_body_size 0`（它累计一个流的全部请求数据，长时间的流会超过 100m）。gRPC 请求不进 CRS 位置：ModSecurity-nginx 在 preaccess 阶段总是读完整个请求体（与 `SecRequestBodyAccess` 无关）才继续，客户端流与双向流因此永远等不到转发。
- 边缘到 `_grpc` 回源层的 upstream 保留 nginx 默认的连接缓存（gRPC 不缓存，没有要退回的过期副本）；HTTP/1.1 与 HTTP/2 回源层的 upstream 设置 `keepalive 0`（§3.1）。
- 客户端连接：有站点开启 gRPC 时，明文监听的默认 server 开启 `http2`（接受 h2c），开启 gRPC 的站点自己的 `server` 块在每个监听上开启 HTTP/2（HTTPS 设置关闭 HTTP/2 时也开启）；其他站点保持原设置，h2c 请求它们的域名得到 421。
- 主动健康检查（§2.10）：HTTP/2 站点的源站以 HTTP/2 探测：HTTPS 经 ALPN 只提供 `h2`，协商不出 `h2` 时记为 `connect_failed`（Go 的服务端在 ALPN 无交集时直接拒绝握手，记为 `tls_failed`），HTTP 以 prior knowledge 探测；方法、路径、Host（`:authority`）与 User-Agent 同 HTTP/1.1 探测。

### 3.25 监听端口、访客 IP 与四层补充（`edge-ports-v1`、`client-ip-v1`、`l4-v2`）

proto v0.23.0 的三项能力，设计见控制台仓库的 ADR-0033：

- **监听端口**（`edge-ports-v1`）：`Listener` 可以是 80 / 443 之外的端口。`Site.ports` 列出站点绑定的监听端口（空为全部监听）：`render` 只在这些端口上为站点渲染 server 块；HTTPS 端口上有开启 HTTP/3 的站点时同号 UDP 监听 QUIC。`edgeweir.router` 对查到的站点检查 `$server_port`，未绑定时返回未知域名页（ACME token 在 80 上仍放行；本地 `edge.sock` 不检查）；`edgeweir.tls` 的两个 TLS 回调用 `ngx.ssl.server_port()` 判断，未绑定时中止握手。`TlsOptions.redirect_status` / `redirect_port` / `redirect_excluded_domains` 决定强制 HTTPS 的状态码、目标端口与不跳转的域名（配置规则显式打开的跳转不受排除影响）。
- **访客 IP**（`client-ip-v1`）：`NodeConfig.client_address` 的 `proxy_protocol` 模式要求每个监听都带 `proxy_protocol`（`real_ip_header proxy_protocol`）；`header` 模式渲染 `set_real_ip_from <可信 CIDR>`、`real_ip_header`、`real_ip_recursive on`（`x-forwarded-for` / `x-real-ip` 写成 nginx 识别的大小写）；`direct` 只用于丢弃访客的 `X-Forwarded-For`。非直连时回源 `X-Forwarded-For` 为 `map` 出的「收到的链 + `$realip_remote_addr`」，直连为 `$proxy_add_x_forwarded_for`（或丢弃时为 `$remote_addr`）。规则字段 `ip.peer` 为 `$realip_remote_addr`（本地监听为 `$remote_addr`）。可信 CIDR 随站点表下发：封禁与 CC 单 IP 计数跳过它们。没有 `client_address` 而监听自带 `proxy_protocol` 的旧配置照常接受。
- **四层补充**（`l4-v2`）：`L4App.port_end` 为端口段（≤ 1000 个端口），stream `listen 起-止`，TCP 端口段不带 `reuseport`；`edgeweir.l4` 对单端口查表、对端口段按协议二分查找。`L4Origin.port` 为 0 时取 `$server_port`。`L4App.certificate_id` 的应用在 stream server 上终结 TLS：`ssl_client_hello_by_lua` 校验 SNI 属于证书名称（没有 SNI 时放行）并按 `tls_minimum_version` 限制协议，`ssl_certificate_by_lua` 设置证书；agent 把证书材料与 DNS 名称附在 L4 表中（与站点证书同一状态文件）。
- **资源**：`render` 按监听 socket 数（`reuseport` 的每个 worker 副本都算，`worker_processes auto` 按在线 CPU 数估算）提高 `worker_connections`；agent 启动时把自身 `RLIMIT_NOFILE` 软限制设为硬限制，nginx 主进程继承后才能打开端口段的全部监听。

### 3.26 域名写法、未知域名与节点 IP 访问（`domains-v2`、`unknown-host-v1`）

proto v0.25.0 的两项能力，设计见控制台仓库的 ADR-0036：

- **域名写法**（`domains-v2`）：`Domain.match` 为 `SUFFIX`（`.a.com`：任意层级子域名，不含 `a.com` 本身）或 `REGEX`（`~` 后的模式匹配整个小写主机名，控制台与 TS / Go / Lua 共用的正则子集，≤ 256 字节）；`Domain.order` 是正则之间的顺序（网站创建毫秒 × 16 + 序号）。优先级：精确 > `*.`（一级）> 后缀（长的在前）> 正则（按 order）。三种实现共用 `test/lua/host-match-vectors.json`（与控制台的副本逐字节相同）（`configir.HostMatcher`、`store.lookup_host` 与控制台的 `matchHost`）。
- **查找**：`edgeweir.store` 把后缀写成 `sfx:<名称>` 键，按标签由近到远查（以 `.` 开头的主机名没有上级，只匹配正则）；正则每个站点表版本编译一次（`ngx.re` 的 `jo` 选项，换表时编译失败的整表拒绝），后缀与正则的命中结果进单独的 LRU（4096 项，随版本失效）。精确与泛域名的查找不变。
- **server 块**：只有配置里有后缀或正则域名（或交给默认网站）时 `render` 才改写 `server_name`：`*.x` 写成一级正则 `~^[^.]+\.x$`，后缀与正则各一个 server 块（后缀长的在前，正则按 order），保证 nginx 的 server 选择（精确 → 最长前导通配 → 正则按出现顺序）与 Lua 的优先级一致；正则写成 `"~(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(?-i)^(?:模式)$"`：与 Lua 相同的 PCRE 回溯上限（每个不属于精确或通配名称的 Host 都要试这些正则），`(?-i)` 让 nginx 区分大小写（源码含大写字母时 nginx 默认不区分，例如 `\x4F`）。有正则时设置 `lua_regex_cache_max_entries`（1024 + 2 × 模式数）。没有这些写法的配置渲染结果逐字节不变。
- **证书**：agent 为有后缀或正则域名的网站下发证书的 DNS 名称；`edgeweir.tls` 对后缀与正则主机按证书名称（含 `*.`）判断能否握手，`edgeweir.policy` 不把证书不覆盖的这类主机跳转到 HTTPS。后缀与正则域名的名称不是主机名：TLS 等待与「不跳转的域名」只把精确域名当作主机名。
- **未知域名与节点 IP 访问**（`unknown-host-v1`）：`NodeConfig.unknown_hosts` 分别给出未绑定域名与节点 IP / 空 Host 的处理：`page`（404 平台页）、`close`（`ngx.exit(444)`）、`site`（交给 `default_site_id`，按其端口绑定）。默认网站的 server 块为 `default_server`（QUIC 监听带 `reuseport`），第一个名称为 `_`（没有 Host 的请求 `$host` 仍是 `_`，按节点 IP 访问处理），明文监听上保留通用 server 的 HTTP/2（有 gRPC 网站时的 h2c：nginx 按默认 server 接受连接前言）。交给默认网站的请求保留原 Host，缓存键总是包含 Host（网站的缓存键不含 Host 时也一样）；证书不覆盖其主机名时不做强制 HTTPS 跳转。HTTPS 没有 SNI 或健康 SNI 而 Host 是 IP 时，处理不是 `page` 就按 IP 访问处理，否则仍是 421。`default_certificate` 时未知 SNI 用默认网站的证书握手，否则仍中止握手。
- **扫描防护**：`scan_threshold` 与 `scan_ban_seconds` 都大于 0 时，未知域名与节点 IP 访问按客户端地址（IPv6 为 /64）在 `edgeweir_cc` 里计 60 秒窗口，超过阈值的那次请求写入平台范围的本机自动封禁（站点 id `*`，原因 `unknown_host_scan`，指标 `unknown_host_requests`），已在平台范围封禁的地址不重复封禁（`ub|` 只是并发 worker 之间 1 秒的去重）；平台 allow 名单与可信代理地址不计；nftables 的受保护地址也包含本集群 `client_address` 的可信代理，其他集群的扫描封禁不会在内核层丢弃它们。agent 经 `ReportBans` 以 `BAN_SCOPE_PLATFORM` 上报（`AutoBan.scope`），控制台解封后同样经 `POST /v1/bans/release` 删除，共享的封禁由控制台的增量删除；计数保留它的窗口，解封后下一个超过阈值的请求再次封禁。

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
| `/var/lib/edgeweir-node/health.crt`、`health.key` | 健康证书与私钥（0600，§3.22） |
| `/var/lib/edgeweir-node/traffic-spool.json`、`logs-spool.json` | 控制台尚未确认的统计批次与采样访问日志批次（0600） |
| `/var/lib/edgeweir-node/run.lock` | `run` 运行期间持有的锁（flock），`enroll --force` 据此拒绝替换正在使用的身份 |
| `/var/lib/edgeweir-node/upgrade.sock`、`upgrades/` | `supervise` 监督进程的本机 socket（0600）；升级状态 `upgrades/state.json` 与各版本目录 `upgrades/releases/<任务 id>/`（0700） |
| `/var/lib/edgeweir-node/nginx/` | nginx prefix：`conf/nginx.conf`（有 HTTPS 监听时还有占位证书 `conf/bootstrap.crt`、`bootstrap.key`；有站点运行 OWASP CRS 时还有 `conf/modsecurity-<哈希>.conf`）、`logs/nginx.pid`、`tmp/` |
| `/var/lib/edgeweir-probe/probe.key`、`probe.crt`、`ca.crt`、`probe.json` | 探针模式的身份（私钥 0600；`probe.json`：probe_id、probe_name、region_id、server_url、server_name、ca_sha256、enrolled_at），目录 0700 |
| `/var/cache/edgeweir-node/<zone>/` | proxy_cache 数据 |
| `/run/edgeweir-node/control.sock`、`control.sock.geo`、`edge.sock`、`edge-tls.sock`、`origin.sock`、`origin-noverify.sock`、`l4.sock` | 控制 API、GeoIP 查询（agent 提供）、预热专用的本地边缘监听（明文；TLS，有 HTTPS 监听时）、回源层（校验 / 不校验证书）、stream 子系统的控制中继（有四层应用时） |
| `/usr/share/edgeweir-node/lua/edgeweir/` | Lua 模块 |
| `/usr/lib/edgeweir-openresty/` | edgeweir-openresty：`nginx/sbin/nginx`、`luajit/`、`lualib/`、`bin/`；edgeweir-openresty-modsecurity 另装 `modules/ngx_http_modsecurity_module.so` 与 `lib/libmodsecurity.so.3` |
| `/usr/share/edgeweir-openresty/` | OWASP CRS（`crs/`：`crs-setup.conf`、`rules/`、`plugins/`、`LICENSE`）与 `modsecurity/unicode.mapping` |
| `/usr/share/doc/edgeweir-openresty/` | `NOTICE`（全部第三方组件与许可证全文）、`edgeweir-openresty.cdx.json`（组件清单）、`nginx-V.txt`、`build-toolchain.txt` |

所有持久化写入都是：写临时文件 → fsync → rename → fsync 目录。状态目录为 0700；agent 以 root 运行并指定 `--nginx-user` 时，worker 必须进入的目录（套接字目录、prefix 及其上级的状态目录）若属于 root 且对其他用户关闭，则改为 worker 用户组并加上组的 x 位（状态目录变为 0710）。

## 5. 部署形态

- **容器**：`debian:bookworm-slim` 为基础，带与 edgeweir-openresty、edgeweir-openresty-modsecurity 两个包相同的 OpenResty 树（§5.1，在同一个 Dockerfile 里构建，compose 只需本仓库即可构建镜像）；agent、nginx master 和 worker 都以 uid 10001 运行（容器网络命名空间内非特权进程可以绑定 80 端口）；`ENTRYPOINT edgeweir-node supervise --manage-nginx`，`STOPSIGNAL SIGTERM`，健康检查为 `edgeweir-node healthcheck`。镜像带 Debian 的 `ca-certificates` 与 `nftables` 包。内核封禁需要两项：镜像以 `--build-arg NFT_CAPABILITY=true` 构建（给 `/usr/sbin/nft` 加文件能力 `cap_net_admin+ep`），容器以 `--cap-add NET_ADMIN` 启动（compose 中为 `cap_add: [NET_ADMIN]`）。默认镜像不加任何能力；只加了文件能力而容器没有 `NET_ADMIN` 时 `nft` 无法执行，agent 退回边缘层封禁。nftables 规则作用于容器自己的网络命名空间。
- **systemd**：`packaging/systemd/edgeweir-node.service`，服务用户 `edgeweir`，只保留 `CAP_NET_BIND_SERVICE`，`ProtectSystem=strict` 等加固选项；OpenResty（`EDGEWEIR_NGINX_BIN=/usr/lib/edgeweir-openresty/nginx/sbin/nginx`）作为 agent 的子进程运行，与 OpenResty 官方包的 `openresty.service` 互斥。deb/rpm 包含二进制、Lua 模块、unit 和 `/etc/default/edgeweir-node`，依赖 `edgeweir-openresty (>= 1.31.1.1-2)`，推荐安装 `edgeweir-openresty-modsecurity`（没有它时站点不能在该节点运行 OWASP CRS）与 `nftables`；preinstall 创建 `edgeweir` 用户，postinstall 创建 `/var/lib/edgeweir-node`（0700）和 `/var/cache/edgeweir-node`（0750）。
- **探针模式**（§2.11）：
  - 容器：同一个节点镜像，入口改为 `edgeweir-node probe`（compose 中 `entrypoint: ["/usr/local/bin/edgeweir-node", "probe"]`，或 `docker run --entrypoint /usr/local/bin/edgeweir-node <镜像> probe`），状态目录 `EDGEWEIR_STATE_DIR=/var/lib/edgeweir-probe` 挂载卷（镜像中已建好，属 uid 10001，0700）；首次启动由 `EDGEWEIR_SERVER`、`EDGEWEIR_CA_SHA256`、`EDGEWEIR_TOKEN` 注册。镜像的健康检查查询数据面控制 socket，探针容器应关闭它（compose `healthcheck: {disable: true}`）。
  - systemd：`packaging/systemd/edgeweir-probe.service`（随 deb/rpm 安装，默认不启用），服务用户 `edgeweir`，不授予任何 capability，`MemoryDenyWriteExecute=yes`、`ProcSubset=pid`，只允许 IP 与 unix 套接字，`StateDirectory=edgeweir-probe`（0700）；首次启动的参数写在 `/etc/default/edgeweir-probe`（0600，由 systemd 读取）。缺少注册参数时退出码 2，不自动重启（`RestartPreventExitStatus=2`）。
- **systemd 下的内核封禁**：默认 unit 不授予 `CAP_NET_ADMIN`。需要时安装 `nftables`，加一个 drop-in `/etc/systemd/system/edgeweir-node.service.d/kernel-ban.conf`：

  ```ini
  [Service]
  AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
  ```

  然后执行 `systemctl daemon-reload && systemctl restart edgeweir-node`，日志出现 `kernel bans active` 即生效。环境能力同样被 OpenResty 子进程继承。

### 5.1 edgeweir-openresty

`packaging/openresty/` 从固定版本的源码构建 OpenResty，产出两个包，与 edgeweir-node 一起发布并列入同一个 `checksums.txt`（cosign 签名）：

| 包 | 内容 | 依赖 |
| --- | --- | --- |
| `edgeweir-openresty` 1.31.1.1-2 | `/usr/lib/edgeweir-openresty`（nginx、LuaJIT、lualib、`bin/openresty`、`bin/resty`），`/usr/share/doc/edgeweir-openresty` | glibc ≥ 2.34、libgcc |
| `edgeweir-openresty-modsecurity` 1.31.1.1-2 | `modules/ngx_http_modsecurity_module.so`、私有的 `lib/libmodsecurity.so.3`（不在动态链接器的搜索路径里）、`/usr/share/edgeweir-openresty`（CRS、`unicode.mapping`） | 同版本的 edgeweir-openresty、libstdc++ |

文件名按 nfpm 惯例：`edgeweir-openresty_1.31.1.1-2_amd64.deb`、`edgeweir-openresty-1.31.1.1-2.x86_64.rpm`（arm64 为 `arm64` / `aarch64`），`-modsecurity` 同理；另有每个架构的 SPDX SBOM `edgeweir-openresty_1.31.1.1-2_<架构>.sbom.json`。`make openresty-packages ARCH=amd64|arm64` 构建到 `out/openresty/`，goreleaser 把它们复制进 `dist/`、计入 `checksums.txt` 并随发布上传；发布工作流在对应架构的机器上构建。两个包安装到独立目录，不与发行版或 OpenResty 官方的包冲突。

- **构建环境**：固定 digest 的 `almalinux:9.7`，工具链（gcc 11.5、binutils 2.35.2）只从已冻结的 AlmaLinux 9.7 vault 安装。glibc 2.34 是最低要求：产物可在 RHEL / Rocky / AlmaLinux 9、Debian 12、Ubuntu 22.04 及更新的发行版上运行；构建检查二进制需要的 glibc 版本不超过 2.34、libmodsecurity 需要的 libstdc++ 不超过 GLIBCXX_3.4.29。
- **源码与校验**（`sources.lock`）：每个源码包先校验固定的 SHA-256；上游发布了签名的，再用 `keys/` 里固定的公钥以 `gpgv` 校验，并要求签名密钥属于固定的主密钥指纹。

  | 组件 | 版本 | 签名 |
  | --- | --- | --- |
  | OpenResty | 1.31.1.1 | PGP（Yichun Zhang，`2545 1EB0 8846 0026 195B D62C B550 E09E A0E9 8066`） |
  | OpenSSL | 3.5.9 | PGP（OpenSSL，`B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40`） |
  | PCRE2 | 10.49 | PGP（Nicholas Wilson，`A955 3620 4A3B B489 7152 3128 2A98 E77E B6F2 4CA8`） |
  | zlib | 1.3.2 | PGP（Mark Adler，`5ED4 6A67 21D3 6558 7791 E2AA 783F CD8E 58BC AFBA`） |
  | Brotli | 1.2.0 | 无（SHA-256） |
  | ngx_brotli | `a71f9312` | 无（SHA-256） |
  | Zstandard | 1.5.7 | PGP（Zstandard Release Signing Key，`4EF4 AC63 455F C9F4 545D 9B7D EF8F E995 28B5 2FFD`） |
  | zstd-nginx-module | 0.1.1 | 无（SHA-256） |
  | ModSecurity | 3.0.17 | PGP（OWASP ModSecurity，`0B2B A192 4065 B446 9120 2A2A D286 E022 149F 0F6E`） |
  | ModSecurity-nginx | 1.0.4 | PGP（同上） |
  | YAJL | 2.1.0 | 无（SHA-256） |
  | libxml2 | 2.15.4 | 无（SHA-256，与 GNOME 发布的 `.sha256sum` 一致） |
  | OWASP CRS | 4.29.0 | PGP（OWASP Core Rule Set，`3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`） |

- **补丁**（`patches/`）：YAJL 的安全修复（取自 Fedora：CVE-2017-16516、CVE-2022-24795、CVE-2023-33460 与内存泄漏）；libmodsecurity 在不检查请求体（`SecRequestBodyAccess Off`）时仍运行 phase 2 的规则（上游 3.0.17 在这种情况下跳过全部 phase 2 规则，包括查询参数与请求头的检查和入站异常评分 949110，CRS 几乎完全失效；上游 issue #2465），请求体不解析、不交给规则，与 ModSecurity v2 相同，构建时用 CRS 的测试载荷实测（有、无请求体检查时查询参数里的载荷都返回 403，无请求体检查时请求体里的载荷不拦截）；ModSecurity-nginx 回移上游 pull request #374（`$modsecurity_triggered_rules`、`$modsecurity_intervention`）；zstd-nginx-module 只把 libzstd 作为自己的链接库（原配置把全部 `--with-ld-opt` 重复加入链接）；nginx 以 root 启动且没有 `user` 指令时，`nobody` 组不存在就用 `nogroup`（Debian、Ubuntu 没有 `nobody` 组；configure 只按构建机的 `/etc/group` 选一个）。
- **configure**：与 OpenResty 官方包相同（`--with-pcre-jit`、`--with-stream`、`--with-stream_ssl_module`、`--with-stream_ssl_preread_module`、`--with-http_v2_module`、`--with-http_v3_module`、不编译 mail 模块、`--with-http_stub_status_module`、`--with-http_realip_module`、`--with-http_addition_module`、`--with-http_auth_request_module`、`--with-http_secure_link_module`、`--with-http_random_index_module`、`--with-http_gzip_static_module`、`--with-http_sub_module`、`--with-http_dav_module`、`--with-http_flv_module`、`--with-http_mp4_module`、`--with-http_slice_module`、`--with-http_gunzip_module`、`--with-threads`、`--with-compat`、`--with-http_ssl_module`、`--without-http_rds_json_module`、`--without-http_rds_csv_module`、`--without-lua_rds_parser`、LuaJIT `-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT`，`--with-cc-opt` 含 `-DNGX_LUA_ABORT_AT_PANIC`），`--prefix=/usr/lib/edgeweir-openresty`，另加 `--add-module` ngx_brotli（过滤与静态模块）和 zstd-nginx-module。不编译 `http_auth_basic`：它需要 `crypt(3)`，AlmaLinux 9 的 libcrypt.so.2 在 Debian 与 Ubuntu 上不存在；节点不使用 Basic 认证。编译加 `-fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2`（x86_64 另有 `-fcf-protection`），链接 `-z relro -z now`。
- **静态链接**：OpenSSL（`no-shared`，`enable-ktls`）、PCRE2、zlib、Brotli、Zstandard 静态链接进 nginx。OpenSSL 与 PCRE2 以整个静态库链接并导出（ngx_lua 的 `-Wl,-E`）：LuaJIT FFI 代码（lua-resty-openssl、`resty.sha256`）在进程内找 libcrypto 的函数，找不到时会去加载系统的 libcrypto；构建检查 nginx 导出了这些符号，并用 `resty` 实测 HMAC、随机数与 SHA-256。动态模块也会链接 `--with-ld-opt`，所以 ModSecurity-nginx 在第二遍 nginx configure 里（同一份打过补丁的 nginx 源码、同样的参数与 `--with-compat`）单独构建。libmodsecurity 编译为共享库，PCRE2、YAJL、libxml2 静态链入并隐藏符号（`--exclude-libs`），不带 curl、GeoIP、MaxMind、LMDB、Lua、ssdeep；运行时只依赖 libstdc++、libgcc 与 glibc，模块经 RPATH 找到 `/usr/lib/edgeweir-openresty/lib`。
- **可复现**：`SOURCE_DATE_EPOCH` 取自 `sources.lock`，固定构建路径，`-ffile-prefix-map`，二进制去掉符号，文件时间、属主与权限统一，nfpm 使用同一时间戳。在 arm64 上不使用缓存重新构建，树（`tree.sha256`）与四个包的 SHA-256 与前一次完全相同。
- **许可证**：构建前逐个检查源码中的许可证文件（文件存在、仍含预期的许可证文字），全部允许商业使用；`NOTICE` 列出每个组件、版本与 SPDX 标识并附许可证全文（OpenResty 及其捆绑模块 BSD-2-Clause / BSD-3-Clause / MIT，nginx BSD-2-Clause，LuaJIT MIT，OpenSSL Apache-2.0，PCRE2 BSD-3-Clause WITH PCRE2-exception，zlib Zlib，Brotli MIT，ngx_brotli BSD-2-Clause，Zstandard 按 BSD-3-Clause，zstd-nginx-module BSD-2-Clause，ModSecurity 与 ModSecurity-nginx Apache-2.0，ModSecurity 捆绑的 libinjection BSD-3-Clause 与 Mbed TLS（按 Apache-2.0），YAJL ISC，libxml2 MIT，OWASP CRS Apache-2.0）。
- **SBOM**：构建写入 CycloneDX 组件清单（`sources.lock` 的每个源码及其 SHA-256、OpenResty 捆绑并编译的组件、ModSecurity 捆绑的库），syft 扫描安装树时并入，生成 SPDX SBOM。
- **更新**：改 `sources.lock` 的版本、URL、SHA-256（签名密钥轮换时连同 `keys/` 与指纹），并把 `epoch` 改为新的日期；包版本是 OpenResty 的版本加 `nfpm/edgeweir-openresty.yaml` 里的 release 号（两个包共用）：OpenResty 升级时 release 回到 1，OpenResty 不变而包内容变化（其他组件升级、补丁、构建参数、打包）时加一。edgeweir-node 包依赖的最低版本在 `.goreleaser.yaml`。

## 6. 已知限制

- 旧占位字段 `CacheRuleMatch.expression` 仍拒绝非空值；表达式通过 `EdgeRule` 与 `CacheRuleMatch.condition` 的类型化 AST 下发。
- 不支持内部 CA 轮换。
- 客户端上传大小固定为 100m（IR 暂无对应字段）。
- 访问日志默认关闭，按站点采样，经有界私有队列与持久批次去重上报。
- 预热不支持前缀与全站预热；sitemap 预热只跟随一层索引，每个文档最多 50 MiB。
- 错误页模板与离线 Host 在站点表里（`edgeweir_sites`，`--sites-dict-mb`，默认 64 MiB，保存当前与上一版本）；每个站点最多 5 个 64 KiB 的模板，站点多、模板大时需要调大。
- 主动健康检查的状态只在 agent 内存里：agent 重启后源站从健康开始重新探测。
- Cache-Tag 索引按对象记录标签，字典满时按 LRU 淘汰；被淘汰对象在有标签标记的站点上多回源一次。
- 使用 required_features 协商能力；未知枚举或能力拒绝整份配置，保留 LKG。
- 尚未收到第一份配置时，`ReportStatus.state` 为 `APPLY_STATE_UNSPECIFIED`，message 为 `waiting for the first configuration`。
- 内核封禁在 input 链丢弃被封地址的全部入站包，节点也无法与该地址建立出站连接（例如该地址恰好是源站）；受保护地址不受影响。
- 本机自动封禁只在数据面字典里，nginx 重启后丢失（已上报并由控制台共享的条目会再次下发）。
- CC 计数与级别按节点独立决策，nginx 重启后从正常级别重新开始。
- JA4 看不到 OpenSSL 不认识的 ClientHello 扩展，没有 `supported_versions` 时版本取协商结果（§3.16）。
- 运行 OWASP CRS 的站点：ModSecurity-nginx 在回源前读完整个请求体（最多 `client_max_body_size` 100m，超过缓冲区时写入临时文件）再检查，上传不再流式转发；超过请求体检查上限的部分不检查（`ProcessPartial`）。响应体不检查（`SecResponseBodyAccess Off`），CRS 的响应规则只看响应头；ModSecurity-nginx 仍要求响应体在内存中经过它，这些站点的响应（含缓存命中）不使用 sendfile。WebSocket 升级请求只检查握手。
- CRS 在节点上按 paranoia level 与规则运行，误报需要按规则 id 排除；每个请求约 0.5 ms CPU（§3.18）。
- `connections_active`（心跳的活动连接数）是 nginx 的 `$connections_active`：除客户端连接外，还包括边缘层到回源层 unix socket 的连接（进行中的回源）。
- 主机指标只在 Linux 上测量；容器内的 CPU、负载与内存是宿主机的值。
- 没有 SNI 的 TLS 握手会得到自签名的健康证书（`CN=health.edgeweir.invalid`），随后只能访问健康端点（§3.22）。
- 四层应用向源站发送的 PROXY protocol 版本在节点上是结构性设置（reload，nginx 按 `server` 决定）；UDP 会话不跨 reload；PROXY protocol 中继吞吐低于 nginx 自己转发、不支持半关闭；`--stream-shutdown-timeout` 作用于旧 worker 的全部连接（§3.23）。
- 动态封禁只在边缘层（HTTP）执行；四层应用只受 nftables 内核封禁（`kernel-ban-v1`）与它们自己的名单约束。
- 内核按 TCP 连接的源地址丢包。节点在要求 PROXY protocol 的负载均衡器之后时，内核只看到负载均衡器的地址：平台封禁对客户端只在边缘层生效，负载均衡器的地址需要放进平台 `allow` 名单，否则封禁它会丢弃经它转发的全部流量。

## HTTPS 与证书

支持 HTTPS、HTTP/2、HTTP/3 与 SNI 证书热更新。证书材料在 certificates.json（0600）中保存当前与前一份 LKG 的引用；节点身份私钥与网站 TLS 私钥分别管理。激活后推送失败会恢复，配置未持久化不能回报 APPLIED。详情见控制面 docs/guide/https.md。

## 规则与 GeoIP

- `Site.rules`、`NodeConfig.ip_lists/platform_rules`、缓存规则条件与批量重定向进入热更新表，Go 验证后 Lua 编译为固定闭包（函数、值表达式与新动作见 §3.21）。禁止运行用户 Lua。每阶段平台规则先执行，平台 IP 白名单仅覆盖平台 IP 黑名单；站点放行不能绕过平台 WAF。
- IP 前缀树、有限 PCRE 工作量、不会淘汰现有键的固定窗口限速（分区满时新计数放行并每分钟记录一次日志，见 docs/rate-limit-storage.md）；规则或依赖数据执行错误时拒绝请求。
- `internal/geoip` 读取本地 MMDB，经 0600 Unix socket 服务同机 worker：发布镜像构建时下载并内置的 IPinfo Lite（国家、ASN，`--geoip-ipinfo auto`），以及运维提供的 City/ASN MMDB。国家和 ASN 优先取 IPinfo，查不到时回落到 City/ASN；一级行政区只来自 City，且仅当其国家与结果一致。数据库通过完整性与类型检查才上报能力；GeoIP 请求不离开节点，运行时不下载数据。
- 缓存、缓存规则条件、批量重定向和刷新使用改写前的请求；配置与列表更新不 reload。`rules-v1`、`rules-v2`、`rules-v3`（§3.21）、`geoip-city-v1`（国家；沿用旧名以兼容控制台，来自 IPinfo 或 City）、`geoip-subdivision-v1`（City，一级行政区）、`geoip-asn-v1`（IPinfo 或 ASN）分开上报；`geoip-country-v1` 告知控制台一级行政区已单独上报。控制台对国家和一级行政区规则仍只下发 `geoip-city-v1` 要求，节点逐条表达式校验时一级行政区需要 `geoip-subdivision-v1`，没有 City MMDB 的节点拒绝这类配置。
- 持久化失败在恢复旧配置后退避五分钟或等下一版本，避免每次轮询重新激活未持久化内容。
- `test/lua/expression-vectors.json` 镜像控制面规则包的共享向量：接受的条件由 Lua（PCRE2）求值、Go 校验（字段比较的 `matches` 另由 Go RE2 执行），值表达式由 Lua 求出期望的字符串，结构化缓存条件同时按结构化匹配检查，派生字段（扩展名、媒体类型）由 Lua 计算，被拒的正则与 IR 由 Go 校验拒绝；GeoIP MMDB（City、ASN 及 IPinfo Lite 结构）为 `internal/testutil/geofixture` 自行生成的数据。

## 统计

`traffic-spool.json`（0600）在调用 `ReportStatsV2` 之前保存不可变的批次和单调递增的序号；本地状态丢失后用游标查询恢复；读到游标之前取出的分钟桶存为未编号批次。队列上限为 10000 个分钟桶或 32 MiB，超出时丢弃最旧的批次，水位停在其中最早的一分钟 24 小时。Lua 的 Space-Saving 摘要（Top URL / Top IP）用单独的共享字典，不含查询串和请求头，是近似值。全部批次确认后上报统计水位 `complete_until`（§2.4）。

## 运维

固定监督进程持独占状态锁，经本机 0600 socket 接收类型化任务，并替子进程运行 OpenResty：子进程经 socket 的 `/engine/test`、`/engine/reload`、`/engine/status` 测试与重载（`RemoteEngine`），停止时不停 OpenResty，所以升级、试运行、回滚和 agent 重启都不重启 OpenResty，共享内存（封禁、CC 状态、限速计数、统计计数）保留。OpenResty 在子进程第一次请求重载时启动；切换到更旧版本（可能自己运行 OpenResty）之前先停止它；监督进程退出时在子进程之后停止它。子进程以退出码 2 退出（参数或本机设置有误）时监督进程不再重启它、自己以退出码 2 退出（systemd unit 设置了 `RestartPreventExitStatus=2`）；其他连续一分钟内的退出按 2 秒起、翻倍至 1 分钟的间隔重启。发布来源、cosign 和公钥由节点运维配置；控制面不能选择公钥或任意命令。验证已签名清单和归档哈希、文件布局、ELF 架构与版本后，程序和 Lua 在私有版本目录内切换。原子状态记录准备 / 试运行 / 当前版本，健康窗口失败或中途重启恢复前一版本及配置快照。结果保留到控制面确认；基础安装指纹变化时采用新镜像 / 软件包，避免旧自升级程序掩盖系统更新。

`config/receipts.json` 保存绑定节点、集群、revision、内容哈希的控制台认证回执，权限 0600；与 LKG 一同备份/回滚。控制面恢复后只接受有凭证的领先版本参与跳号，未认证整数不会耗尽发布序号。采样日志默认关闭，无查询参数、头或正文，经持久批次上报；磁盘队列有明确上限和丢弃日志。
