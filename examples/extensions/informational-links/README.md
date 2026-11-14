# 信息响应链接

中性测试扩展：在访问阶段发送两条 Link 信息响应头，在最终响应里报告调用结果。`phase` 选择 `access`、`access_late` 或两个阶段；`deny` 在发送后返回 403。

使用 Lua API 2，要求节点 ≥ 1.9.0、`extensions-early-hints-v1` 与 edgeweir-openresty ≥ 1.31.1.1-4。签名、安装和按网站开启见控制台扩展契约。
