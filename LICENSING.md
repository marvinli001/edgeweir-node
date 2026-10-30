# 开源许可与商业产品边界 / Licensing and product boundaries

适用日期：2026-09-26。`edgeweir-node` 与控制面 `edgeweir` 保持 **AGPL-3.0-only**，以 [LICENSE](LICENSE) 为准；第三方组件遵循各自许可证。本文不修改许可证，也不增加使用限制。唯一的附加许可是控制台仓库 [LICENSING.md](https://github.com/marvinli001/edgeweir/blob/master/LICENSING.md#节点扩展例外) 中的**节点扩展例外**（AGPL 第 7 条）：只通过公开格式 `edgeweir-node-extension-v1` 与 Lua API 和 Edgeweir 交互的节点扩展可以按任意条款分发，节点加载运行它们不使扩展受 AGPL 约束；对节点本身（包括扩展运行时 `lua/edgeweir/ext.lua`、`internal/extension`）的修改仍为 AGPL-3.0-only。`examples/extensions` 下的示例按 MIT-0 提供。共同产品边界见同一文件。

发布镜像内置的 GeoIP 数据 `/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb` 是 [IPinfo Lite](https://ipinfo.io/lite)，按 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 原样再分发，不属于 AGPL 代码。署名：IP address data is powered by [IPinfo](https://ipinfo.io)。

节点的 OpenResty（edgeweir-openresty 与 edgeweir-openresty-modsecurity 两个包，以及容器镜像里的同一份文件）由第三方开源组件构建，各组件按自己的许可证分发，均允许商业使用：OpenResty 及其模块、nginx（BSD）、LuaJIT、lua-cjson、Brotli、libxml2（MIT）、OpenSSL、ModSecurity、ModSecurity-nginx、OWASP CRS（Apache-2.0）、PCRE2（BSD-3-Clause WITH PCRE2-exception）、zlib（Zlib）、Zstandard（按 BSD-3-Clause）、YAJL（ISC）等。组件清单与许可证全文见 `/usr/share/doc/edgeweir-openresty/NOTICE`。

节点程序 `edgeweir-node` 本身编进的第三方组件（Go 模块，以及图片格式转换用的 libwebp、libavif、aom、dav1d、libyuv，均为 BSD / MIT / ISC / Apache-2.0 许可，libwebp、aom、libyuv 另附免版税的专利授权）同样允许商业使用，清单与许可证全文见包内 `/usr/share/doc/edgeweir-node/NOTICE`（仓库根目录 `NOTICE`）。

- 允许个人和企业在遵守 AGPL 的前提下使用、修改、分发及经营收费服务，没有“仅限个人”或“禁止商用”的附加条款。AGPL 不禁止收费或竞争；源码与网络交互义务以 LICENSE 为准。
- 已有的节点与数据面能力（含心跳与数据面健康上报、分层缓存（Tiered Cache）、采样访问日志、`ReportStats` 统计、内置 IPinfo Lite、HTTP/2 与 HTTP/3），以及控制面的组织、成员、权限、隔离和现有控制台 / 后台继续开源，不以官方许可证限制节点、组织、成员或站点数量。资源保护与权限限制仍正常执行。
- 以下数据面能力属于独立商业产品：组内缓存共享（一致性哈希分片、缓存索引节点）、访问日志直推自定义 sink 与 Logpush、Prometheus 指标、GeoIP 热更新、103 Early Hints、Speculation-Rules、0-RTT、Tunnels、边缘计算、XDP / eBPF、按学习基线的自适应七层 DDoS 缓解、Bot 评分。
- 对外客户门户、套餐计费、财务和分销属于未来独立商业运营产品；官方账户、订阅、许可证与插件分发属于独立商业服务。
- 节点不回连官方授权服务，不持有官方商业许可证，不因许可证到期或授权服务故障停止已有 CDN 流量。节点身份、mTLS 与发布物签名是安全机制，不是商业授权。
- 独立原创商业代码可以另行约定许可；私有仓库、独立进程或容器不是 AGPL 豁免。集成、复制或分发核心代码与依赖仍需满足适用许可证；除节点扩展例外，本文不授予闭源插件豁免或商业双许可。
- 社区可按适用许可自行实现类似商业功能。核心贡献按 AGPL-3.0-only 及节点扩展例外提供，不自动授予闭源再许可权；既有版本的合规使用权不受产品边界调整影响。

## English summary

`edgeweir-node` and the `edgeweir` console remain **AGPL-3.0-only**, with commercial use permitted subject to the license. The existing node and data-plane capabilities (including heartbeat and data-plane health reports, Tiered Cache, sampled access logs, `ReportStats` statistics, the bundled IPinfo Lite, HTTP/2 and HTTP/3), organizations, membership, access control, isolation and the existing console/admin remain open source. A customer commerce portal, billing, finance and reselling belong to a planned separate commercial product. These data-plane capabilities belong to a separate commercial product: cache sharing within a group (consistent-hash sharding, cache index nodes), access log push to custom sinks and Logpush, Prometheus metrics, GeoIP hot reload, 103 Early Hints, Speculation-Rules, 0-RTT, Tunnels, edge compute, XDP/eBPF, adaptive layer-7 DDoS mitigation with learned baselines and bot scoring.

The node has no official license gates or vendor phone-home. An expired vendor license or licensing outage must not stop existing CDN traffic. Node identity, mTLS and artifact signatures serve security, not commercial licensing. Separate commercial products do not amend LICENSE, withdraw existing rights, grant a plugin linking exception or automatically authorize proprietary reuse of contributions. The only additional permission is the **node extension exception** (AGPL section 7) in the console's [LICENSING.en.md](https://github.com/marvinli001/edgeweir/blob/master/LICENSING.en.md#node-extension-exception): node extensions that interact with Edgeweir only through the documented format `edgeweir-node-extension-v1` and the Lua API may be conveyed under any terms, and the node loading and running them does not subject them to the AGPL; changes to the node itself, the extension runtime (`lua/edgeweir/ext.lua`, `internal/extension`) included, stay AGPL-3.0-only. The examples under `examples/extensions` are offered under MIT-0. See the same file for the shared boundary.

The node's OpenResty (the edgeweir-openresty and edgeweir-openresty-modsecurity packages and the same files in the container image) is built from third-party open-source components under their own licenses, all of which permit commercial use: OpenResty and its modules, nginx (BSD), LuaJIT, lua-cjson, Brotli, libxml2 (MIT), OpenSSL, ModSecurity, ModSecurity-nginx, the OWASP CRS (Apache-2.0), PCRE2 (BSD-3-Clause WITH PCRE2-exception), zlib (Zlib), Zstandard (under BSD-3-Clause), YAJL (ISC) and others. The component list and the full license texts are in `/usr/share/doc/edgeweir-openresty/NOTICE`.

The third-party components compiled into the `edgeweir-node` program itself (Go modules, and libwebp, libavif, aom, dav1d and libyuv for image format conversion, all under BSD, MIT, ISC or Apache-2.0 licenses, with royalty-free patent grants for libwebp, aom and libyuv) permit commercial use as well; the list and the full license texts are in `/usr/share/doc/edgeweir-node/NOTICE` (`NOTICE` at the repository root).

Release images bundle the [IPinfo Lite](https://ipinfo.io/lite) database unmodified under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); it is data, not AGPL code. IP address data is powered by [IPinfo](https://ipinfo.io).
