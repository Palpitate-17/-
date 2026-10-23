# 巡检 API 与检测模块接口契约

当前版本：API v1.0；检测器 v0.3.0。真实 HTTP 服务已经实现，本地 TCP 端到端闭环已验证；恒脑账号内工具注册仍待完成。

## HTTP 接口

| 方法 | 路径 | 结果 |
|---|---|---|
| `POST` | `/api/v1/scans` | 202；返回 `scan_id` 和查询地址 |
| `GET` | `/api/v1/scans/{scan_id}` | 任务状态、页面数量、coverage、错误 |
| `GET` | `/api/v1/scans/{scan_id}/findings` | 完整结构化 findings |
| `POST` | `/api/v1/findings/{finding_id}/retest` | 单条复测，返回 open/resolved |
| `GET` | `/api/v1/scans/{scan_id}/report` | JSON 报告 |

OpenAPI：`docs/openapi.json`。运行时也可访问 `/docs` 和 `/openapi.json`。设置 `HENGXUN_API_KEY` 后，除健康检查和接口文档外的业务接口均要求 `X-API-Key`。

## 创建任务的关键字段

- `authorization_confirmed` 必须为 true。
- `target_url` 只能是 HTTP(S)，不得含 userinfo。
- `allowed_hosts`、`allowed_paths`、`denied_paths` 在每次请求前重新校验。
- `max_pages` 最大 300，`max_depth` 最大 5，`rate_limit_rps` 最大 5。
- `lab_mode` 只有服务器环境变量 `HENGXUN_ALLOW_LAB_MODE=true` 时才有效；生产默认拒绝回环、私有、链路本地和保留地址。
- `custom_sensitive_rules` 支持关键词或正则；`sensitive_file_extensions` 控制需要抓取的文本资源类型。
- `baseline_ignore_selectors` 来自受信任务配置，不能由网页内容当作执行指令。
- `external_link_blocklist` 只做本地匹配，不主动访问外部链接。

## 状态与覆盖

任务状态：

```text
queued → validating → crawling → scanning → analyzing → reporting → completed
```

异常终态为 `failed` 或 `cancelled`。每个模块另有：

```text
succeeded / skipped / failed / inconclusive
```

`findings=[]` 只有在对应 coverage 为 succeeded 时才能解释成“本次适用规则未发现候选”。skipped、failed 和 inconclusive 都不能解释成安全。

## Finding 字段

每条发现包含 `finding_id`、`scan_id`、`fingerprint`、`category`、`rule_id`、`severity`、`confidence`、`url`、`title`、`evidence_masked`、`description`、`impact`、`remediation`、`verification`、`status`、`detector`、`detector_version`、`first_seen`、`last_seen` 和 `metadata`。

公开 URL 会移除 userinfo/fragment并遮蔽查询值；证据只输出脱敏片段。服务端另行保存受控原 URL 用于复测，不得用展示 URL 重新请求。

## Python 检测入口

```python
from scanner.rules import load_rules
from scanner.sensitive import detect_sensitive
from scanner.baseline import build_baseline, compare_baseline
from scanner.external_links import compare_external_links, detect_external_link_risks
```

- 敏感检测覆盖 HTML 可见文本、HTML 注释、内联 JavaScript、JS/JSON/TXT 响应。
- 基线覆盖状态、标题、正文摘要、DOM 摘要、外部脚本、内联脚本、form、iframe 和 meta refresh。
- 外链检测记录标签来源，支持新增变化、本地黑名单、Punycode、IP 字面量和 URL 内嵌凭据特征；不会访问外部地址。

旧 `scanner/adapters/hengnao.py` 只为历史四字段模拟流程保留。新恒脑工作流应使用 v1 API，不应继续把旧兼容对象当正式接口。

## 尚未接入

- 弱配置检测器和常见漏洞安全模板，因此 coverage 会明确标为 skipped。
- 基线人工审批接口和定时调度。
- HTML/PDF 报告；当前可导出 JSON。
- 恒脑账号内的真实 API 工具节点、调用日志和截图。
