# 恒脑私有智能体交付记录

## 入口和运行方式

- 智能体：**网站安全巡检-交付版**（当前为用户私有）。[编辑入口](https://gc.das-ai.com/agent-save/2113173645547864066?from=self)。
- 试运行输入：`请对 https://public-firing-range.appspot.com/ 执行网站巡检，仅检查预设的三个公开测试页面，并报告实际请求结果。`
- 预期输出：报告列出扫描时间、来源、允许范围内的页面、规则发现和被动配置观察，并将这些项目保留为待核实；`status` 为 `cached_result`（超过 48 小时则为 `stale_result`）。

## 当前执行链

```text
用户输入 → 路由代码节点 → 自规划节点 → 读取云端巡检记录（GET）
         → 校验并生成巡检报告（代码节点） → 结束节点
```

“读取云端巡检记录”使用用户私有 API 工具“公开巡检结果 / 读取最新结果”，读取 [scan-results 分支的 latest.json](https://raw.githubusercontent.com/Palpitate-17/-/scan-results/results/latest.json)。实际 HTTP 巡检由仓库的 `Scan public Firing Range testbed` GitHub Actions 工作流执行。恒脑中的代码节点运行 [`prototype/hengnao_cached_result_node.py`](../prototype/hengnao_cached_result_node.py) 的内容，对结果来源、目标、白名单路径和时效进行核对，并生成中文报告。结束节点引用该代码节点的 `result_key`。

本链路读取最近一次云端巡检记录。用户输入不会启动一次新的 GitHub Actions 任务，因此报告须写明扫描时间，不能描述成“本轮即时扫描”。本机 API、Cloudflare 临时隧道和用户电脑无需在演示时保持在线。

## 能力范围与复测

当前固定目标是 Google Firing Range 公开扫描器测试靶场，仅允许首页、`/clickjacking/index.html`、`/mixedcontent/index.html`。这是测试靶场，不是团队获得授权的业务网站。代码节点拒绝其他目标或不匹配的数据类型；结果过期、缺字段时显示异常状态，不把错误解释成“无漏洞”。

验收时先在 GitHub 仓库的 **Actions → Scan public Firing Range testbed** 手动运行一次，等 [latest.json](https://raw.githubusercontent.com/Palpitate-17/-/scan-results/results/latest.json) 更新后，在恒脑输入上面的试运行文本。确认工具节点返回 JSON、代码节点 `status=cached_result`、结束节点有扫描时间和发现摘要。若云端任务未成功，先看 Actions 日志及目标站连通性。

要实现“输入一个已获授权网址后立即巡检”，还需要把按白名单执行请求的扫描服务部署到稳定的 HTTPS 环境，并让恒脑工具调用该服务的 `POST /scan`。仓库现有 `prototype/local_scan_api.py` 可在本地联调；恒脑代码节点所在执行环境曾无法直连该测试靶场，不能只把本地扫描脚本粘进代码节点就声称已具备即时扫描能力。
