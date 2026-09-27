# 开源许可与商业产品边界 / Licensing and product boundaries

适用日期：2026-09-26。`edgeweir-node` 与控制面 `edgeweir` 保持 **AGPL-3.0-only**，以 [LICENSE](LICENSE) 为准；第三方组件遵循各自许可证。本文不修改许可证，也不增加使用限制或插件链接例外。共同产品边界见本仓库镜像的 [ADR-0019](docs/adr/0019-open-core-and-commercial-products.md)。

- 允许个人和企业在遵守 AGPL 的前提下使用、修改、分发及经营收费服务，没有“仅限个人”或“禁止商用”的附加条款。AGPL 不禁止收费或竞争；源码与网络交互义务以 LICENSE 为准。
- 节点、数据面，以及控制面的组织、成员、权限、隔离和现有控制台 / 后台继续开源，不以官方许可证限制节点、组织、成员或站点数量。资源保护与权限限制仍正常执行。
- 对外客户门户、套餐计费、财务和分销属于未来独立商业运营产品；官方账户、订阅、许可证与插件分发属于独立商业服务。这些产品尚未因本次文档变更而创建或实现。
- 节点不回连官方授权服务，不持有官方商业许可证，不因许可证到期或授权服务故障停止已有 CDN 流量。节点身份、mTLS 与发布物签名是安全机制，不是商业授权。
- 独立原创商业代码可以另行约定许可；私有仓库、独立进程或容器不是 AGPL 豁免。集成、复制或分发核心代码与依赖仍需满足适用许可证，本文不授予闭源插件通用豁免或商业双许可。
- 社区可按适用许可自行实现类似商业功能。核心贡献按 AGPL-3.0-only 提供，不自动授予闭源再许可权；既有版本的合规使用权不受产品边界调整影响。

## English summary

`edgeweir-node` and the `edgeweir` console remain **AGPL-3.0-only**, with commercial use permitted subject to the license. Organizations, membership, access control, isolation and the existing console/admin remain open source. A customer commerce portal, billing, finance and reselling belong to a planned separate commercial product.

The node has no official license gates or vendor phone-home. An expired vendor license or licensing outage must not stop existing CDN traffic. Node identity, mTLS and artifact signatures serve security, not commercial licensing. Separate commercial products do not amend LICENSE, withdraw existing rights, grant a plugin linking exception or automatically authorize proprietary reuse of contributions. See [ADR-0019](docs/adr/0019-open-core-and-commercial-products.md) for the shared boundary.
