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

- [x] `WatchConfig` 服务端流接收 revision 通知，另有每 30 秒一次的 `GetConfig` 轮询兜底；断线重连退避 1s → 30s
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

### Phase 0 已知限制（节点）

- HTTPS 监听暂时跳过：proto v0.1.0 没有下发证书和私钥材料的 RPC。需要扩展 proto，例如新增 `GetCertificate` RPC，或在配置中内联加密后的证书材料。
- 回源 TLS 不校验源站证书：IR 里还没有对应的 verify 开关。
- 负载均衡策略 `ROUND_ROBIN` 和 `CONSISTENT_HASH` 目前退化为加权随机。
- 被动健康检查尚未实现。
- 访问日志关闭，只有聚合统计。
- 带规则表达式（`CacheRuleMatch.expression`）的缓存规则会被 Phase 0 节点拒绝。

## MVP

### 集群与站点

- [ ] [控制面] 多集群、节点组、区域
- [ ] [节点+控制面] 站点支持 HTTP 和 HTTPS
  - 节点侧：先扩展 proto 下发证书材料；`ssl_certificate_by_lua` 按 SNI 从共享内存加载证书，换证书不需要 reload
- [ ] [节点+控制面] 多域名，含泛域名
  - 节点侧：Phase 0 已支持多域名和单级泛域名（`*.example.com` 只匹配最左边一级标签），Lua 路由先精确匹配 Host，再查上一级域名的泛域名

### 源站

- [ ] [节点+控制面] 源站池：权重、备用源站
  - 节点侧：Phase 0 已按权重随机选择主源、没有主源时才用备用源；待补齐"主源不可用时切备用"（依赖被动健康检查）以及 `ROUND_ROBIN`、`CONSISTENT_HASH`
- [ ] **[节点]** 被动健康检查
  - 节点侧：在 Lua 选源器里按连续失败和超时把源站标记为不可用，冷却期后恢复
- [ ] [节点+控制面] 回源 Host 和 SNI
  - 节点侧：Host 头和 `proxy_ssl_name` 取自站点配置；IR 增加回源证书校验开关后默认开启校验
- [ ] [节点+控制面] 对象存储源站鉴权
  - 节点侧：在 Lua 中给回源请求签名（如 S3 SigV4），密钥随配置加密下发

### 缓存

- [ ] [节点+控制面] 缓存规则：按后缀、路径、前缀、状态码、大小匹配
- [ ] **[节点]** 自定义缓存键
  - 节点侧：cache key 统一由 Lua 生成，在同一处扩展
- [ ] **[节点]** 遵循或覆盖源站缓存头
  - 节点侧：遵循时交给 proxy_cache 解析源站头；覆盖时用规则 TTL，双层缓存已支持 TTL 热更新
- [ ] **[节点]** stale 响应
  - 节点侧：`proxy_cache_use_stale` + `proxy_cache_background_update` + `proxy_cache_lock`
- [ ] **[节点]** Range 请求和分片缓存
  - 节点侧：proxy_cache 配合 slice 模块，分片范围进入 cache key
- [ ] [节点+控制面] 刷新：URL、前缀、全量
  - 节点侧：URL 刷新按 cache key 定位缓存条目；全量刷新递增 cache key 中的代际号（Phase 0 的 key 已包含代际号）；前缀刷新用按前缀的代际号或本地索引，待定
- [ ] [节点+控制面] 预热：URL、前缀、全量
  - 节点侧：agent 向本机数据面发请求填充缓存，限制并发

### 协议与证书

- [ ] [控制面] ACME 自动证书（`edgeweir-certd`：lego + libdns，支持 ARI 和 DNS-01）
- [ ] [控制面] 上传证书
  - 两种证书到节点都走上面"站点支持 HTTPS"里的证书下发
- [ ] **[节点]** HSTS
- [ ] **[节点]** HTTP/2
- [ ] **[节点]** HTTP/3
  - 节点侧：依赖带 `http_v3` 的 OpenResty 自定义构建；QUIC 监听属于结构性变更，走 reload
- [ ] **[节点]** Gzip、Brotli、Zstd
  - 节点侧：Gzip 官方包即可；Brotli 和 Zstd 依赖自定义构建

### 访问控制与规则

- [ ] [节点+控制面] IP、CIDR 黑白名单
  - 节点侧：IP 名单经 unix socket 热更新，不 reload
- [ ] [节点+控制面] 国家、省份、ASN 黑白名单
  - 节点侧：geoip2 模块（自定义构建）或 Lua 读取 mmdb，数据库由 agent 更新
- [ ] **[节点]** 限速
  - 节点侧：lua-resty-limit-traffic，计数放在 `lua_shared_dict`
- [ ] [节点+控制面] 重定向、改写、请求头和响应头规则
  - 节点侧：控制面把表达式编译进 IR，节点再编译成 Lua，按 request-transform → redirect → config → waf-custom → ratelimit → cache → origin → response-transform 的阶段执行

### DNS

- [ ] [控制面] 接入第三方 DNS：DNSPod、阿里云、华为、Cloudflare
- [ ] [控制面] 自动下发 CNAME
- [ ] [控制面] 健康检查不通过自动摘除解析，并提供记录修复任务
- [ ] [节点+控制面] 节点健康检查失败自动下线
  - 节点侧：`ReportStatus` 心跳之外加本机自检（OpenResty 进程、配置应用结果），异常如实上报

### 运维

- [ ] [节点+控制面] 分钟级统计：请求数、流量、带宽、命中率、状态码
  - 节点侧：Phase 0 已上报请求数、字节数、命中和状态码，带宽由字节数推算
- [ ] [节点+控制面] 分钟级 Top URL 和 Top IP
  - 节点侧：在 Lua 中做 Top-K 预聚合，随 `ReportStats` 上报，不上传原始日志
- [ ] [控制面] 告警：邮件、Webhook、钉钉、企业微信、Telegram
- [ ] [控制面] 审计日志
- [ ] [控制面] 开放 API

### 节点基础能力（BOOTSTRAP §2 的节点职责，§4 未单列）

- [ ] **[节点]** OpenResty 自定义构建：`http_v3`、brotli、zstd、geoip2、lua-resty-lmdb；ModSecurity + CRS 作为可选动态模块。上面的 HTTP/3、Brotli/Zstd、地区名单都依赖它
- [ ] **[节点]** 有了自定义构建后，评估用 lua-resty-lmdb 替代 `lua_shared_dict` 存放配置
- [ ] [节点+控制面] agent 自升级：先校验 sha256 和 cosign 签名，通过后再原子替换二进制并重启；失败时保留旧版本

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
- [ ] [控制面] 智能调度规则：节点指标条件 → 动作（下线、切备用节点、切备用 IP）→ 持续时间 → 自动恢复
- [ ] [控制面] 分布式区域探针
- [ ] [节点+控制面] 节点租期，到期自动摘除
  - 节点侧：心跳续约，控制面按租期判断

### 日志

- [ ] [节点+控制面] 原始访问日志写入 ClickHouse
  - 节点侧：访问日志按比例采样，批量压缩上报
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
  - 节点侧：NodeConfig IR 与 OpenResty 解耦，新引擎实现 `internal/engine` 的接口即可接入
- [ ] [控制面] 高防 IP 售卖模块
- [ ] [节点+控制面] Tunnels 内网穿透
