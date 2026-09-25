# edgeweir-node 架构

本文描述 Phase 0 节点的实现。需求来源是控制面仓库的 BOOTSTRAP.md（§2 节点部分、§3.3），节点和控制面之间的契约是 `edgeweir/proto`（`proto/v0.1.0`）里的 `edgeweir.node.v1`。

## 1. 组件

```text
                        控制台 (edgeweir, :8443, 应用自终结 TLS)
                               ▲  Connect 协议 (二进制 protobuf, HTTP/2)
         Enroll: CA pin + token│  其余 RPC: mTLS (证书 CN = node id)
┌──────────────────────────────┴───────────────────────────────────────────┐
│ edgeweir-node (Go, 静态二进制)                                             │
│  enroll ─ pki ─ identity          controlplane (Connect 客户端, 证书热替换)   │
│  agent: watch / poll / sync / report / renew / stats 循环                  │
│  configir (规范排序, content_hash, diff, 校验 → Plan)   configstore (LKG)   │
│  render (nginx.conf 模板)   engine (openresty -t / reload / 子进程托管)      │
│  dataplane (unix socket JSON 客户端)                                        │
└───────────────┬──────────────────────────────────┬───────────────────────┘
      nginx.conf │ -t / HUP / 子进程                 │ PUT /v1/sites, GET /v1/status,
                ▼                                  ▼ POST /v1/stats/drain
┌──────────────────────────────────────────────────────────────────────────┐
│ OpenResty                                                                 │
│  控制 server   unix:/run/edgeweir-node/control.sock  → lua/edgeweir/control │
│  边缘层 server  :80 ... (每个 listener 一个)            → router + proxy_cache │
│  回源层 server  unix:/run/edgeweir-node/origin.sock   → origin → 源站         │
│  lua_shared_dict: edgeweir_sites / edgeweir_meta / edgeweir_stats          │
└──────────────────────────────────────────────────────────────────────────┘
```

| 包 | 职责 |
| --- | --- |
| `cmd/edgeweir-node` | CLI：`enroll`、`run`、`healthcheck`、`version`；参数可由 `EDGEWEIR_*` 环境变量提供 |
| `internal/pki` | ECDSA P-256 密钥、CSR、PEM、CA pin 校验、mTLS 配置、续期判断 |
| `internal/identity` | 状态目录里的身份文件，原子写入，续期时的密钥对原子替换与崩溃恢复 |
| `internal/enroll` | 注册流程 |
| `internal/controlplane` | Connect 客户端：pin 通道（注册）和 mTLS 通道（可热替换证书） |
| `internal/configir` | 规范排序、content_hash、diff 应用、校验并生成与引擎无关的 `Plan` |
| `internal/configstore` | LKG 持久化（current + previous），加载时校验哈希 |
| `internal/render` | 用 Go `text/template` 渲染 `nginx.conf`，解析 `/etc/resolv.conf` |
| `internal/engine` | `openresty -t`、reload、托管模式下的子进程监督 |
| `internal/dataplane` | Lua 控制 API 的 unix socket 客户端，站点表 JSON 结构 |
| `internal/agent` | 运行时主循环 |
| `lua/edgeweir/*.lua` | 数据面：`router`（边缘层）、`origin`（回源层）、`store`（站点表）、`rules`、`stats`、`control` |
| `internal/gen` | 由 buf 从 `edgeweir/proto` 的 git tag 生成，已提交 |

第三方 Go 依赖只有 `connectrpc.com/connect` 和 `google.golang.org/protobuf`。

## 2. 生命周期

```text
run 启动
  │
  ├─ 准备目录；有 LKG 且仍合法 → 按 LKG 渲染并启动 OpenResty、推送站点表
  │            否则 → bootstrap 配置（:80，所有 Host 返回 404 unknown-host）
  │
  ├─ 未注册：每 2s 检查 identity.json（此时数据面已经在服务）
  │     └─ `edgeweir-node enroll`（可在 run 运行时执行，如 docker compose exec）
  │
  ├─ 加载身份，建立 mTLS 通道；首个成功的 mTLS RPC 打印
  │     "switched to mTLS channel node_id=<id>"
  │
  └─ 并行循环
        watch  : WatchConfig 流；REVISION 且比已应用的新 → 触发 sync
        poll   : 每 30s 触发一次 sync（不论流是否健康）
        sync   : GetConfig → 校验 → 应用 → 持久化 LKG → 触发 report（串行执行）
        report : 立即、每次应用后、每 report_interval_seconds（默认 15s）
        renew  : 控制台要求或剩余有效期 < 1/3 时续期证书
        stats  : 每 60s 从 Lua 取出完整分钟的统计，ReportStats 上报
        dataplane: 每 5s 及 nginx (重)启动时检查 GET /v1/status，不一致则重推
```

### 2.1 注册（`enroll`）

1. 校验参数：`--server` 必须是 https；`--ca-sha256` 为 64 位十六进制（也接受 `sha256:` 前缀和冒号分隔）；已有身份时除非 `--force` 否则拒绝。先确认状态目录可写，避免白白消耗一次性 token。
2. 本地生成 ECDSA P-256 私钥，CSR 的 CN 为主机名（控制台会改成 node id）。
3. 用 pin 通道调用 `Enroll`：`tls.Config` 设置 `InsecureSkipVerify`，由 `VerifyConnection` 做完整校验：
   - 服务端证书链中必须有一张证书的 DER SHA-256 等于 pin（控制台发送 leaf + CA）；
   - 以这张证书为唯一根，校验 leaf 的证书链、主机名（默认取 URL 的 host，`--server-name` 可覆盖）和 ServerAuth 用途。
   校验通过后才发送 token。
4. 校验响应：`ca_certificate_pem` 的哈希必须等于 pin；节点证书必须由该 CA 签发、用于 ClientAuth、公钥与本地私钥一致；CN 与 node_id 不一致时只告警。
5. 原子写入 `node.key`（0600）、`node.crt`、`ca.crt`，最后写 `identity.json`（它是"已注册"的标记）。以 root 执行且状态目录属于服务用户时，文件会交给该用户。`--force` 会先删除旧身份和旧 LKG。

token 用过即失效，重复注册返回 `permission_denied`（或 `unauthenticated`）。

### 2.2 mTLS 通道

- 客户端证书为节点证书，`RootCAs` 只有内部 CA，`ServerName` 同注册时。
- `GetClientCertificate` 每次握手读取当前证书；续期后重建 transport 并重连 watch 流。
- HTTP/2（ALPN），开启 HTTP/2 ping 检测死连接；支持 `HTTPS_PROXY` 等代理环境变量。
- 控制台返回 `unauthenticated` / `permission_denied`（节点被删除、证书吊销或过期）时，节点记录明确的错误日志，继续按 LKG 服务。证书过期后无法续期，需要重新注册。

### 2.3 获取与应用配置

`GetConfig(revision=0, base_revision=<已应用的 revision>)`：

- **snapshot**：直接进入校验。
- **diff**：以本地 LKG 为基础，listeners / cache_zones / certificates 整体替换，按 id upsert 站点，删除 `removed_site_ids`，重新规范排序后计算哈希，与 `diff.content_hash` 比较。基础 revision 不符、哈希不一致或任何错误 → 重新请求快照（`base_revision=0`）。
- LKG 属于其他集群（重新注册到别的集群）时不作为 diff 基础。

**content_hash**：规范排序后（listeners 按 port，cache_zones 按 name，sites 按 id，certificates 按 id；站点内 domains 按 name，origins 按 id，cache_rules 按 (priority, id)，稳定排序），把 `revision` 置 0、`content_hash` 置空，`proto.MarshalOptions{Deterministic: true}` 编码后取 SHA-256 小写十六进制。控制台用 protobuf-es 的 `toBinary` 计算，两者都按字段号顺序编码并省略 proto3 默认值，NodeConfig 中没有 map 字段，因此字节一致。跨语言测试向量见 `internal/configir/testdata/content_hash_vector.json`（含 protojson 形式的配置、规范字节和期望哈希）。

**校验策略**（`configir.Build`）：

| 情况 | 处理 |
| --- | --- |
| 哈希不符（快照或 diff 回退后的快照） | 整个配置拒绝 |
| 任一缓存规则的 `match.expression` 非空 | 整个配置拒绝（Phase 0 节点不支持规则表达式，proto 约定） |
| `cluster_id` 与节点所属集群不同 | 整个配置拒绝 |
| listener 端口非法 / 重复 | 跳过该 listener 并告警 |
| HTTPS listener | 跳过并告警：proto v0.1.0 没有下发证书材料的途径 |
| 没有可用 listener | 使用默认端口（80）并告警 |
| cache zone 名非法或与内部 shared dict 重名 | 跳过并告警；没有 zone 时使用内置 `edgeweir_default` |
| 站点引用不存在的 zone / 未指定 zone | 使用第一个 zone |
| 非法域名、单级顶级泛域名（如 `*.com`）、已被前面站点（按 id 顺序）占用的域名 | 丢弃该域名并告警；站点没有域名则跳过 |
| 非法源站（地址、端口、Host 头、SNI） | 丢弃该源站并告警；站点没有源站则跳过 |
| 缓存规则 action 未指定，或条件列表过滤后变空 | 跳过该规则（绝不放宽成"匹配全部"） |
| `enabled=false` 的站点 | 不对外服务（等同未知域名） |

跳过项作为告警写入 `ReportStatus.message`（`applied with N warning(s): ...`），状态仍为 `APPLIED`，这样单个坏站点不会拖垮整个集群。整个配置被拒绝时状态为 `APPLY_STATE_FAILED`，`applied_revision` 保持为仍在服务的 LKG revision，message 给出原因（包括 `nginx -t` 的原始输出）。确定性失败（哈希、校验、`nginx -t`）的同一 revision 在 5 分钟内不重复尝试。

**应用**（`agent.applyPlan`）：

1. 渲染 `nginx.conf`。与当前已安装的内容不同（或引擎未运行）时，写到 `nginx.conf.next`，执行 `openresty -p PREFIX -c nginx.conf.next -e stderr -t -q`，通过后原子改名为 `nginx.conf` 并 reload。
2. 把 Plan 转成站点表 JSON，`PUT /v1/sites` 推给 Lua（数据面刚启动时带退避重试，最长 15s）。
3. 原子写入 LKG（current → previous 备份），更新状态并触发 `ReportStatus`。

`nginx.conf` 只包含结构性设置，站点数据从不写进去，所以"渲染结果是否变化"就是"是否需要 reload"的判定：站点、源站、缓存规则、缓存代际号的变化只走热更新。

### 2.4 状态回报、续期、统计

- `ReportStatus`：`applied_revision`、`applied_content_hash`、`state`、`message`、`info`（hostname、agent_version、os、arch、engine=`openresty`、`openresty -v` 得到的版本、非回环地址）、`applied_at`、`data_plane_healthy`（最近一次控制 API 探测结果）、`certificate_not_after`。响应中的 `latest_revision` 比已应用的新会触发 sync；`report_interval_seconds` 调整心跳间隔（限制在 1s–5min）。
- 续期：响应要求或剩余有效期不足 1/3 时，生成新密钥和 CSR 调用 `RenewCertificate`；新证书必须由已固定的 CA 签发（Phase 0 不支持 CA 轮换）。先写 `node.key.new` / `node.crt.new`，再依次改名；启动时若发现密钥和证书不匹配且存在 `node.crt.new`，自动完成中断的替换。随后重建 TLS 客户端。
- 统计：Lua 在边缘层 log 阶段按 `<分钟>|<站点id>|<指标>` 累加（请求数、发送/接收字节、命中/未命中、状态码），agent 每分钟调用 `POST /v1/stats/drain` 取出已结束的分钟并删除，转换成 `MinuteStats` 批量上报；上传失败的批次保留重试（有上限）。

### 2.5 WatchConfig

- 请求带 `known_revision`；首条消息是 `WATCH_EVENT_REVISION`，之后约每 15s 一条 `KEEPALIVE`。
- 45s 内没有任何消息视为死流，主动断开重连。
- 断线重连退避 1s → 30s，带随机抖动；收到过消息后退避复位。
- 无论流是否健康，每 30s 都会 `GetConfig` 轮询一次；已是最新时控制台返回空 diff，开销很小。

## 3. 数据面

### 3.1 双层缓存

`proxy_cache_valid` 是静态指令，改 TTL 就要 reload。为了让缓存规则（含 TTL）可以热更新，同一个 nginx 里分两层：

```text
客户端 ──► 边缘层 (listen :80, default_server)
            access_by_lua  edgeweir.router
              · 删除客户端带来的 X-Edgeweir-* 请求头
              · 按 Host 查站点：精确匹配 → 上一级域名的泛域名；查不到 → 404 + X-Edgeweir-Error: unknown-host
              · 按顺序匹配缓存规则（路径前缀 / 扩展名，首个命中生效）
              · 设置 $edgeweir_cache_zone / $edgeweir_cache_key / bypass / no_cache
            proxy_cache $edgeweir_cache_zone; key = 站点id:缓存代际号:scheme://host+request_uri
            proxy_cache_lock / use_stale (error timeout updating 5xx) / background_update / revalidate
            add_header X-Cache $upstream_cache_status always
            内部请求头 X-Edgeweir-Site / -TTL / -Cache-Mode（proxy_set_header 设置，覆盖客户端同名头）
                │ keepalive, unix socket
                ▼
          回源层 (listen unix:origin.sock)，外部不可达
            access_by_lua  edgeweir.origin
              · 按站点 id 取源站池：主源按权重随机；没有主源时才用备用源
              · proxy_pass $scheme://address:port（变量 → 由 resolver 解析域名）
              · Host = host_header 或客户端 Host；SNI = sni / host_header / address
              · 发往源站前清除内部头；忽略源站的 X-Accel-*（防止源站操纵缓存或内部跳转）
            header_filter_by_lua
              · OVERRIDE：200/203/206/300/301/308 响应加 X-Accel-Expires: <ttl>
              · RESPECT：源站没有 Cache-Control/Expires 时才加
                │
                ▼
              源站
```

边缘层的 proxy_cache 优先采用 `X-Accel-Expires`，nginx 不会把 `X-Accel-*` 转发给客户端。因此规则 TTL 以请求头的形式传到回源层、再以响应头的形式回到边缘层的缓存，全程不需要 reload。首次请求 `X-Cache: MISS`，第二次 `HIT`；没有命中缓存规则的请求为 `BYPASS`。按 nginx 默认行为，带 `Set-Cookie` 的响应不缓存。

`proxy_cache` 指令使用变量，每个站点可以落到不同的 cache zone；刷新整个站点只需递增 `cache_generation`（在 cache key 里）。

### 3.2 站点表与控制 API

控制 API 只监听 `unix:/run/edgeweir-node/control.sock`（目录权限 0750），由 `lua/edgeweir/control.lua` 处理：

| 方法与路径 | 作用 |
| --- | --- |
| `GET /v1/health` | 存活检查 |
| `GET /v1/status` | `{version, revision, content_hash, site_count, pushed_at, nginx_version, ...}`，`version=0` 表示 nginx 启动后还没收到站点表 |
| `PUT /v1/sites` | 原子替换整张站点表 |
| `POST /v1/stats/drain` | 返回并删除所有已结束分钟的统计 |

站点表 JSON（Go 结构见 `configir.Site`，由 agent 从 IR 转换，Lua 不接触 protobuf）：

```json
{
  "revision": "12",
  "content_hash": "…",
  "sites": [{
    "id": "site-a", "name": "demo", "cache_zone": "default", "cache_generation": "1",
    "load_balance": "weighted_random",
    "domains": [{"name": "demo.test"}, {"name": "example.com", "wildcard": true}],
    "origins": [{"id": "o1", "scheme": "http", "address": "whoami", "port": 80, "weight": 1,
                 "backup": false, "host_header": "", "sni": ""}],
    "cache_rules": [{"id": "r1", "action": "cache", "ttl": 60, "mode": "override",
                     "path_prefixes": ["/"], "extensions": ["png"]}]
  }]
}
```

`revision` 和 `cache_generation` 用字符串传递，因为 Lua 的数字是 double。

`PUT /v1/sites` 在 `edgeweir_sites` 里以版本前缀写入新表（`v<N>:site:<id>`、`v<N>:host:<name>`、`v<N>:wild:<name>`，使用 `safe_set`，内存不足时整体回滚并返回 507），写完后翻转 `edgeweir_meta` 中的 `version`，请求永远不会看到写了一半的表。上一版本保留到下一次替换，供翻转瞬间仍在处理的请求使用。每个 worker 用 lua-resty-lrucache 缓存解码后的站点和 Host 查询结果，键里带版本号，翻转即失效。

shared dict 在 HUP reload 时保留，在 nginx 重启后清空。agent 每 5s（以及收到 nginx 启动事件时）调用 `GET /v1/status`，发现 `version=0` 或 revision/哈希与期望不符就重新推送。

### 3.3 reload 与热更新

| 变更 | 方式 |
| --- | --- |
| 监听端口、HTTP/2、PROXY protocol | 重新渲染 → `openresty -t` → reload（HUP） |
| cache zone（增删、大小） | 同上 |
| resolver（`/etc/resolv.conf`，agent 启动时读取） | 同上 |
| 站点、域名、源站、缓存规则、TTL、缓存代际号 | 热更新：`PUT /v1/sites`，不 reload |

`resolver` 取自 `/etc/resolv.conf` 的 nameserver（Docker 中为 `127.0.0.11`；IPv6 加方括号；带 zone 的链路本地地址跳过；没有时回退到 `127.0.0.1`），`valid=30s`；主机没有全局 IPv6 地址时加 `ipv6=off`。

### 3.4 进程管理

- **托管模式**（`--manage-nginx`，容器和 systemd 默认）：agent 以子进程运行 `openresty -p PREFIX -c nginx.conf -e stderr -g 'daemon off;'`。首次配置检查通过后才启动；reload 发送 SIGHUP；子进程意外退出时按 1s → 30s 退避重启，重启后自动重推站点表；agent 收到 SIGTERM/SIGINT 时向 OpenResty 发送 SIGQUIT 优雅退出，8s 后仍未退出则 SIGKILL。子进程在独立进程组中，Linux 上设置 `Pdeathsig`，agent 意外死亡时 OpenResty 也会退出。启动前清理残留的 unix socket。nginx 的 stderr 按行转进 agent 日志（`component=nginx`）。
- **非托管模式**：OpenResty 由外部管理，agent 用 `-s reload` 通知。
- `worker_rlimit_nofile` 取进程的硬上限（os/exec 子进程只继承默认软上限），`worker_connections` 随之调整。

## 4. 文件布局

| 路径 | 内容 |
| --- | --- |
| `/var/lib/edgeweir-node/node.key` | 节点私钥，PKCS#8 PEM，0600 |
| `/var/lib/edgeweir-node/node.crt`、`ca.crt` | 节点证书、内部 CA 证书 |
| `/var/lib/edgeweir-node/identity.json` | node_id、cluster_id、node_name、server_url、server_name、ca_sha256、enrolled_at |
| `/var/lib/edgeweir-node/config/current.binpb`、`previous.binpb` | LKG 配置及其备份（二进制 protobuf，0600） |
| `/var/lib/edgeweir-node/nginx/` | nginx prefix：`conf/nginx.conf`、`logs/nginx.pid`、`tmp/` |
| `/var/cache/edgeweir-node/<zone>/` | proxy_cache 数据 |
| `/run/edgeweir-node/control.sock`、`origin.sock` | 控制 API、回源层 |
| `/usr/share/edgeweir-node/lua/edgeweir/` | Lua 模块 |

所有持久化写入都是：写临时文件 → fsync → rename → fsync 目录。

## 5. 部署形态

- **容器**：`openresty/openresty:1.31.1.1-bookworm` 为基础，agent、nginx master 和 worker 都以 uid 10001 运行（容器网络命名空间内非特权进程可以绑定 80 端口）；`ENTRYPOINT edgeweir-node run --manage-nginx`，`STOPSIGNAL SIGTERM`，健康检查为 `edgeweir-node healthcheck`。
- **systemd**：`packaging/systemd/edgeweir-node.service`，服务用户 `edgeweir`，只保留 `CAP_NET_BIND_SERVICE`，`ProtectSystem=strict` 等加固选项；OpenResty 作为 agent 的子进程运行，与发行版自带的 `openresty.service` 互斥。取舍说明见 unit 文件内的注释。

## 6. 已知限制（Phase 0）

- HTTPS 监听被跳过：proto v0.1.0 只有 `CertificateRef`，没有下发证书/私钥材料的 RPC。
- 回源 HTTPS 不校验源站证书（IR 暂无开关），SNI 已按配置发送。
- `ROUND_ROBIN`、`CONSISTENT_HASH` 退化为加权随机；尚无被动健康检查。
- 访问日志关闭，只有聚合统计。
- `CacheRuleMatch.expression` 非空的配置会被拒绝。
- 不支持内部 CA 轮换。
- 客户端上传大小固定为 100m（IR 暂无对应字段）。
