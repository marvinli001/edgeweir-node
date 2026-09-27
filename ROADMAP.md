# Edgeweir 节点路线图

本文是 Edgeweir 平台路线图的节点侧（`edgeweir-node`）视图。功能全集来自 BOOTSTRAP §4，这里按主题重新整理，并标出每一项主要在哪一侧实现，以及节点侧的大致做法。平台整体路线图见控制面仓库 [edgeweir/edgeweir 的 ROADMAP.md](https://github.com/edgeweir/edgeweir/blob/master/ROADMAP.md)。

标记说明：

- **[节点]**：主要在本仓库实现（Go agent 或 OpenResty/Lua）
- [节点+控制面]：两侧都要改，通常还要扩展 `edgeweir/proto` 里的 NodeConfig IR 或 RPC
- [控制面]：只在 `edgeweir/edgeweir` 实现，列在这里是为了完整
- 缩进的"节点侧："是实现思路，不是承诺，落地时以 ADR 为准

## Phase 0（已完成）

端到端最小闭环：注册 → mTLS → 同步配置 → 渲染并重载 OpenResty → 热更新站点表 → 回源并缓存 → 回报状态。

**注册与身份**

- [x] 一次性 token 注册；ECDSA P-256 私钥和 CSR 在节点本地生成，只发送 CSR
- [x] 注册时按安装命令里的 sha256 固定（pin）控制面内部 CA
- [x] 注册后所有 RPC 走 mTLS；证书在剩余有效期不足 1/3 时，或控制面要求时，自动续期

**配置同步**

- [x] `WatchConfig` 服务端流接收 revision 通知，另有约每 30 秒一次（±20% 随机抖动）的 `GetConfig` 轮询兜底；断线重连退避 1s → 30s
- [x] 支持快照和增量 diff，应用前校验 `content_hash`；diff 无法应用时退回拉取快照
- [x] last-known-good 配置原子落盘（current 加一份 previous 备份），控制面不可用时节点照常按它服务

**数据面**

- [x] 只有结构性变更（监听端口、缓存 zone、resolver）才用 Go 模板重新渲染 `nginx.conf`，先 `openresty -t` 再 reload
- [x] 站点、源站、缓存规则通过本地 unix 控制 socket 热更新到 `lua_shared_dict`，每个 worker 用 lua-resty-lrucache 加版本号做缓存和失效
- [x] OpenResty 双层缓存设计，缓存 TTL 可以热更新；响应带 `X-Cache: MISS` / `HIT`

**上报**

- [x] `ReportStatus` 心跳，携带已应用的 revision
- [x] 按站点、按分钟的统计（请求数、字节数、缓存命中/未命中、状态码），经 `ReportStats` 上报

**发布与部署**

- [x] 容器镜像
- [x] goreleaser 产出 linux amd64/arm64 的 deb、rpm、tar.gz；cosign keyless 签名，附 SBOM 和 SLSA provenance
- [x] systemd unit

### 仍然存在的限制（节点）

回源证书校验、负载均衡策略和被动健康检查已在 MVP M2 实现；当前限制见 ARCHITECTURE.md §6，主要是：

- HTTPS、证书、HTTP/2/3 已在 MVP M3 实现；Brotli/Zstd 仍需后续构建。
- 访问日志关闭，只有聚合统计；访问日志采样上报属于 MVP M6。
- 旧 `CacheRuleMatch.expression` 占位字段仍被拒绝；M4 规则使用结构化 `Site.rules`。

## MVP

### 集群与站点

- [x] [控制面] 多集群、节点组、区域（MVP M1）
- [x] [节点+控制面] 站点支持 HTTP 和 HTTPS
  - 节点侧：先扩展 proto 下发证书材料；`ssl_certificate_by_lua` 按 SNI 从共享内存加载证书，换证书不需要 reload
- [x] [节点+控制面] 多域名，含泛域名（MVP M1）
  - 节点侧：Phase 0 已支持多域名和单级泛域名（`*.example.com` 只匹配最左边一级标签），Lua 路由先精确匹配 Host，再查上一级域名的泛域名

### 源站

- [x] [节点+控制面] 源站池：权重、备用源站
  - 节点侧（MVP M2）：`balancer_by_lua` 按策略选源（加权随机、平滑加权轮询、一致性哈希），重试只在主源之间，主源全部下线时才用备用源；一次请求内最多尝试 3 个源站
- [x] [节点+控制面] 源站地址限制与回环检测
  - 节点侧（收尾）：特殊地址段（回环、链路本地、私网、CGNAT 等）默认不能作为源站，配置字面量和 DNS 解析结果都检查，平台允许清单可放行；请求带 `CDN-Loop`，回环返回 508
- [x] **[节点]** 被动健康检查
  - 节点侧（MVP M2）：连接失败、超时、502/503/504 计为失败，连续失败次数达到阈值后在恢复时间内不再选中；状态经 ReportStatus 上报给控制台
- [x] [节点+控制面] 回源 Host 和 SNI
  - 节点侧（MVP M2）：Host 与 SNI 按源站设置，重试换源时重建请求；回源 HTTPS 默认用系统 CA（或 `--trusted-ca`）按源站的 SNI/Host 校验证书，可按站点关闭
- [x] [节点+控制面] 对象存储源站鉴权
  - 节点侧（MVP M2）：Lua 用 AWS SigV4 签名 GET/HEAD；密钥经 mTLS 的 GetOriginCredentials 获取，不进配置
- [x] [节点+控制面] 回源连接池与超时、WebSocket 透传
  - 节点侧（MVP M2）：连接池按地址、端口和 SNI 区分；超时按站点设置；WebSocket 经两层透传，可按站点关闭

### 缓存

- [x] [节点+控制面] 缓存规则：按后缀、路径、前缀、状态码、大小匹配
  - 节点侧（MVP M2）：请求条件在边缘层判断，状态码和大小在源站层判断
- [x] **[节点]** 自定义缓存键
  - 节点侧（MVP M2）：Lua 统一生成 key：查询参数全部 / 忽略 / 白名单、排序、请求头、Cookie、设备类型、是否包含 Host
- [x] **[节点]** 遵循或覆盖源站缓存头
  - 节点侧：遵循时交给 proxy_cache 解析源站头；覆盖时用规则 TTL，双层缓存已支持 TTL 热更新
- [x] **[节点]** stale 响应
  - 节点侧（MVP M2）：按规则设置 stale-while-revalidate / stale-if-error（Cache-Control 扩展，边缘层还原源站原头）
- [x] **[节点]** Range 请求和分片缓存
  - 节点侧（MVP M2）：按站点开启 1 MiB slice，分片范围进入 cache key
- [x] [节点+控制面] 刷新：URL、前缀、全量
  - 节点侧（MVP M2）：类型化任务下发刷新标记，标记的时间（节点首次执行任务时分配）进入 cache key，下一次请求在新 key 上 MISS；标记持久化并在 nginx 重启后先于站点表灌入，每站点有上限，超出或装不下时合并为全站标记
- [x] [节点+控制面] 预热：URL
  - 节点侧（MVP M2）：agent 经本机边缘监听请求 URL，限制并发，逐节点回报结果；前缀与全量预热见 v1

### 协议与证书

- [x] [控制面] ACME 自动证书（`edgeweir-certd`：lego + libdns，支持 ARI 和 DNS-01）
- [x] [控制面] 上传证书
  - 两种证书到节点都走上面"站点支持 HTTPS"里的证书下发
- [x] **[节点]** HSTS
- [x] **[节点]** HTTP/2
- [x] **[节点]** HTTP/3
  - 节点侧：官方 OpenResty 1.31.1.1 已包含 `http_v3`；QUIC 监听属于结构性变更，走 reload
- [x] **[节点]** Gzip
- [ ] **[节点]** Brotli、Zstd（当前官方引擎不含模块）
  - 节点侧：Gzip 官方包即可；Brotli 和 Zstd 依赖自定义构建

### 访问控制与规则

- [x] [节点+控制面] IP、CIDR 黑白名单
  - 节点侧：IP 名单经 unix socket 热更新，不 reload
- [x] [节点+控制面] 国家、省份、ASN 黑白名单
  - 节点侧：Go 读取运维提供的本地 MMDB，经 0600 Unix socket 提供结果；默认 DB-IP Lite CC BY 4.0
- [x] **[节点]** 限速
  - 节点侧：有界固定窗口计数放在 `lua_shared_dict`，内存不足失败关闭
- [x] [节点+控制面] 重定向、改写、请求头和响应头规则
  - 节点侧：控制面把表达式编译进 IR，节点再编译成 Lua，按 request-transform → redirect → config → waf-custom → ratelimit → cache → origin → response-transform 的阶段执行

### DNS

- [x] [控制面] 接入第三方 DNS：DNSPod、阿里云、华为、Cloudflare
- [x] [控制面] 自动下发 CNAME
- [x] [控制面] 健康检查不通过自动摘除解析，并提供记录修复任务
- [x] **[节点]** 本机自检，异常如实上报
  - 节点侧：agent 每 5 秒（以及 OpenResty 每次（重）启动时）探测数据面控制 API，结果作为 `data_plane_healthy` 随 `ReportStatus` 上报；配置应用结果（`state`、`message`，含 `nginx -t` 输出、reload 未生效）同样上报；托管模式下 OpenResty 意外退出时按退避自动重启
- [ ] [控制面] 节点健康检查失败自动下线（依据心跳和上面的自检结果）

### 运维

- [x] [节点+控制面] 分钟级统计：请求数、流量、带宽、命中率、状态码（lite 模式；小时/天汇总与保留在 MVP M5）
  - 节点侧：Phase 0 已上报请求数、字节数、命中和状态码，带宽由字节数推算
- [ ] [节点+控制面] 分钟级 Top URL 和 Top IP
  - 节点侧：在 Lua 中做 Top-K 预聚合，随 `ReportStats` 上报，不上传原始日志
- [x] [控制面] 告警：邮件、Webhook、钉钉、企业微信、Telegram
- [x] [控制面] 审计日志（MVP M1）
- [x] [控制面] 开放 API
- [x] [节点+控制面] 访问日志采样上报（MVP M6）
  - 节点侧：按站点采样率在 log 阶段采集（时间、客户端 IP、方法、Host、路径、状态码、字节、耗时、缓存状态），批量上报

### 节点基础能力（BOOTSTRAP §2 的节点职责，§4 未单列）

- [ ] **[节点]** OpenResty 自定义构建：`http_v3`、brotli、zstd、geoip2、lua-resty-lmdb；ModSecurity + CRS 作为可选动态模块。Brotli/Zstd 与可选扩展仍需另行构建；HTTP/3 已使用官方模块，GeoIP 使用本地 Go MMDB 服务
- [ ] **[节点]** 有了自定义构建后，评估用 lua-resty-lmdb 替代 `lua_shared_dict` 存放配置
- [x] [节点+控制面] agent 自升级：先校验 sha256 和 cosign 签名，通过后再原子替换二进制并重启；失败时保留旧版本

## v1

### 安全

- [ ] [节点+控制面] OWASP CRS 托管规则，先观察再拦截
  - 节点侧：ModSecurity + CRS 可选动态模块，先以仅检测模式运行，命中结果随统计上报
- [ ] **[节点]** 分级 CC 防护：限速 → 302/cookie → JS → 验证码 → 滑块，按 QPS 和错误率自动升级
- [ ] **[节点]** 5 秒盾 / PoW 挑战
- [ ] **[节点]** JA4 指纹
  - 节点侧：在 `ssl_client_hello_by_lua` 阶段读取 ClientHello 计算指纹
- [ ] **[节点]** nftables/ipset 联动
  - 节点侧：Lua 把需要封禁的 IP 经 unix socket 交给 agent，由 agent 维护 nftables set / ipset，在内核层丢包
- [ ] [节点+控制面] URL 鉴权（A–D 四种签名方式）
- [ ] [节点+控制面] 防盗链
- [ ] [节点+控制面] UA 名单

### 缓存与调度

- [ ] [节点+控制面] Tiered Cache / L2 回源聚合节点 + Topologies（可复用的缓存层级拓扑）
- [ ] **[节点]** 组内一致性哈希分片
  - 节点侧：同组节点之间按 cache key 做一致性哈希，只由负责的节点回源
- [ ] [节点+控制面] 按 Cache-Tag 清缓存
  - 节点侧：缓存时记录响应的 `Cache-Tag` 与缓存条目的对应关系
- [ ] [节点+控制面] 预热：前缀、全量（需要源站文件清单或站点地图），以及按缓存键变体（例如移动端）预热；目前只预热桌面变体（控制面收尾延后项 D4）
- [ ] [控制面] 智能调度规则：节点指标条件 → 动作（下线、切备用节点、切备用 IP）→ 持续时间 → 自动恢复
- [ ] [控制面] 分布式区域探针
- [ ] [节点+控制面] 节点租期，到期自动摘除
  - 节点侧：心跳续约，控制面按租期判断

### 日志

- [ ] [节点+控制面] 原始访问日志写入 ClickHouse
  - 节点侧：沿用 MVP M6 的采样上报，批量压缩
- [ ] [节点+控制面] Logpush：S3、HTTP、Kafka

### 协议与优化

- [ ] **[节点]** TCP/UDP 四层转发，支持 PROXY protocol
  - 节点侧：OpenResty stream 模块；配置变更尽量不断开已有连接
- [ ] [节点+控制面] 图片 WebP/AVIF 转换和缩放（imgproxy）
- [ ] **[节点]** 103 Early Hints
- [ ] **[节点]** 注入 Speculation-Rules
- [ ] [节点+控制面] 自定义错误页

### 发布

- [ ] [节点+控制面] 配置金丝雀发布 + 自动回滚
  - 节点侧：回报每个 revision 的应用结果和错误率；本地已保留上一份配置，可快速退回

### 租户

- [ ] [控制面] 租户门户
- [ ] [控制面] 套餐和配额
- [ ] [控制面] 流量包、余额
- [ ] [控制面] 95 计费（依赖节点上报的分钟级流量）
- [ ] [控制面] 支付接口
- [ ] [控制面] 实名认证
- [ ] [控制面] 工单

## v2

- [ ] [控制面] 自建权威 DNS/GTM（评估 PowerDNS 和 CoreDNS 方案）
- [ ] **[节点]** XDP/eBPF 三四层防护
  - 节点侧：由 agent 加载和管理 XDP 程序，与 nftables/ipset 联动共用封禁名单
- [ ] [节点+控制面] 共享压缩字典
- [ ] [节点+控制面] Cache Reserve：S3/MinIO 持久缓存层
- [ ] [节点+控制面] 边缘计算：表达式 DSL 或 Wasm 沙箱，租户脚本需管理员审批
- [ ] **[节点]** Pingora 引擎，等它的 HTTP/3 成熟之后
  - 节点侧：NodeConfig IR 与 OpenResty 解耦，新引擎实现 `agent.Engine`（配置检查、reload、进程监督）和 `agent.DataPlane`（站点表、清缓存标记、统计、健康状态）两个接口，再替换 `internal/render` 的配置渲染即可接入
- [ ] [控制面] 高防 IP 售卖模块
- [ ] [节点+控制面] Tunnels 内网穿透
