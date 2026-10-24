# 恒脑私有智能体交付记录

## 入口

- 智能体：**网站安全巡检-交付版**，已按“仅自己”可见范围发布。[使用入口](https://gc.das-ai.com/agents/2113486599799504897)；[编辑入口](https://gc.das-ai.com/agent-save/2113173645547864066?from=self)。
- API 工具：**公开靶场即时巡检 / 执行白名单即时巡检**，用户私有。[工具详情](https://gc.das-ai.com/tools/2113251819312971777)。
- 恒脑工具请求地址：`https://hengnao-authorized-scan.pages.dev/scan`，`POST`，请求体的 `target_url` 引用上游路由代码节点的 `target_url`。密钥只保存在恒脑工具请求头配置和 Cloudflare Pages Secret 中，不在仓库。

## 当前执行链

```text
用户输入 → 路由代码节点 → 自规划节点 → 工具节点：执行白名单即时巡检
         → 代码节点：校验并生成巡检报告 → 结束节点
```

工具节点在画布上仍显示旧名称“读取云端巡检记录”，但其插件配置已改为实时 API 工具。报告代码节点使用 [`prototype/hengnao_live_result_node.py`](../prototype/hengnao_live_result_node.py)，核对目标、数据类型、执行模式、页面白名单及扫描时间，只把本轮结果作为报告。结束节点输出可读文本。

用户输入预设目标即触发本轮工具调用，当前交付不依赖定时巡检、GitHub `latest.json` 或本机临时隧道。录制演示时要展示工具节点的新 `scan_id` 与报告时间一致；报告不得沿用上次结果。

## 已完成试运行

输入：`请对 https://public-firing-range.appspot.com/ 执行网站巡检，仅检查预设的三个公开测试页面，并报告实际请求结果。`

2026-10-23 的最终恒脑试运行中，报告节点与结束节点沿用同一轮扫描时间 `2026-10-23T04:18:58.124000+00:00`。三个预设页面均为 HTTP 200；报告列出一条 `mixed_content` 规则发现和三条缺少 `X-Content-Type-Options` 的被动观察，均标记“待核实”。报告来源显示为 Cloudflare Pages Function。随后智能体按“仅自己”可见范围发布。这是公开扫描器测试靶场的只读检查，不代表真实业务网站存在已确认漏洞。

2026-10-24 的 Pages 接口再次验证为 `scan_status=complete`，3 页、1 条规则发现、6 条响应头观察、0 条资源观察、0 个请求错误。两次观察数量不同，演示时应以本轮结构化结果为准；此项是接口验证，不冒充恒脑平台当轮试运行。

## 范围和后续

当前仅允许 `https://public-firing-range.appspot.com/`，只读取首页、`/mixedcontent/index.html`、`/clickjacking/index.html`。输入其他网址会被代码节点拒绝，API 也会返回 400 且不请求该目标。接口没有跨次扫描基线，因此不会把缺失的“已消失”或“内容变化”编造成结果。部分页面失败时报告明确写明未完成。

旧的 GitHub Actions + `latest.json` 链路仍保留在仓库中供历史对照，但当前私有智能体已改为本轮即时调用。若需要支持新的真实业务网站，先取得明确授权和范围，再扩展服务端白名单、路由及规则；现在的工具不接受任意 URL。

新增目标的申请与核定过程见 [`docs/authorized-targets.md`](authorized-targets.md)。用户自行声明授权不会自动放行目标。
