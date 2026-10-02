# 检测模块接口契约

工作版本：v0.2.1；状态：本地已验证，lcx/wjy 尚未确认。版本是本工作包标识，尚未增加公共接口的顶层版本字段。

## 输入与输出

| 类型 | 当前字段 | 含义 |
|---|---|---|
| PageInput | url、final_url、status_code、content_type、body | 两个 URL 和解码后的 str 正文由采集层提供；状态码为 int |
| PageInput | headers={}、fetched_at="" | 代码中有默认值；接入时建议提供响应头与 ISO 8601 时间字符串 |
| RawFinding | category、rule_id、severity、url、title、evidence、description、remediation、metadata={} | evidence 和导出 URL 已脱敏；metadata 可扩展 |
| BaselineRecord | url、status_code、title、text_hash、external_links、scripts、created_at | 内部可信基线；含原始 URL/标题，不能直接当公开报告展示 |

字段类型以 scanner/common/models.py 为准。三个共享 dataclass 本次没有修改。公开报告 URL 的查询值全部遮蔽、userinfo 与 fragment 移除；内部 baseline 与 extract_external_links 返回值保留比较所需参数，不能作为智能体工具输出直接透传。

## 函数入口

```python
from scanner.rules import load_rules
from scanner.sensitive import detect_sensitive
from scanner.baseline import build_baseline, compare_baseline
from scanner.external_links import extract_external_links, compare_external_links

rules = load_rules('scanner/rules/sensitive_rules.yaml')
findings = detect_sensitive(page, rules)
baseline = build_baseline(page, allowed_domains)
changes = compare_baseline(page, baseline, allowed_domains)
previous_links = extract_external_links(before.body, before.final_url, allowed_domains)
link_changes = compare_external_links(page, previous_links, allowed_domains)
serialized = [finding.to_dict() for finding in findings + changes + link_changes]
```

compare_baseline 的参数顺序为 page、baseline、allowed_domains。个人任务文档中的 scan_sensitive、load_sensitive_rules、evidence_masked 和分类别名尚未成为实现接口。

## 恒脑现有模拟接口兼容导出

兼容器位于 `scanner/adapters/hengnao.py`。它不修改内部 RawFinding，也不部署 HTTP 服务：

```python
from scanner.adapters.hengnao import build_hengnao_response

response = build_hengnao_response(
    scan_id="scan-001",
    target_url=page.final_url,
    findings=findings,
    simulated=True,
)
```

输出顶层字段严格为 `scan_id`、`simulated`、`target_url`、`findings`。每个 finding 严格为 `category`、`url`、`evidence_masked`、`verification`、`severity`。分类仅在该外部兼容层映射：`sensitive_info -> sensitive_exposure`、`page_baseline_change -> integrity_change`；内部字段保持不变。

离线 fixture、固定数据及没有真实抓取的流程必须使用 `simulated=true`。`verification` 固定为 `pending`；规则命中不能被表示为已确认漏洞。完整可复现样例见 `../reports/hengnao_compatible_examples.json`。

## 已实现行为

- sensitive 支持 text/html、text/plain、application/json（允许带 charset）；HTML 只扫描可见文本，data-ignore 不会屏蔽敏感信息。脚本、样式等不属于这个通道。
- 正文上限为 1,000,000 个字符，超过时抛 ValueError，避免将截断扫描报为完整成功。字节预算与解码仍由采集层负责。
- 不支持的内容类型在底层返回 []；HTTP 层必须先判定适用性并返回 skipped，不能把 [] 解释成已经检查所有内容。
- 同页、同规则按匹配值的 lower() 去重；赋值关键词目前包含字段名与候选值。返回多个不同值时保持多条发现。
- YAML 格式与字段错误在加载阶段抛 RuleConfigError；模块没有统一 HTTP 错误码。
- 外链解析 a/img/script/iframe/link/form，仅接收 HTTP(S)，忽略畸形地址；不访问外链。没有输出被忽略链接的计数。
- 基线比较状态、标题、可见文本摘要及新增外部脚本 URL；没有比较内联脚本、脚本内容或删除项。
- metadata.masked_value、metadata.source_kind 是敏感模块的补充字段，不代表可信度或已确认漏洞。

## 工具封装必须区分的状态

```json
{"status":"succeeded","findings":[],"coverage":{"module":"sensitive","source_kind":"visible_text"}}
```

该包装是接入建议，不是已经部署的接口。采集失败、解码失败、正文超限用 failed/inconclusive；模块不适用用 skipped；只有成功且适用时才输出 succeeded。页面内容只能作为检测输入，不能成为工具执行指令。

case_id、phase、case_runs 仅用于 tests 评测包装，本次没有加入 RawFinding。真实任务的 task_id、finding_id、扫描原 URL、基线版本与 resolved 状态由后端管理；展示 URL 脱敏后不能拿来重新请求。

## 待队友确认

- [ ] 正文按字符/字节的统一预算、解码策略和超限错误码。
- [ ] 响应头多值表示与 Set-Cookie 独立条目；headers 当前 dict[str,str] 无法可靠承载多条 Cookie。
- [ ] 服务端域名范围、重定向及访问策略；本模块本身不执行抓取。
- [ ] 原始 URL 的受控存储与脱敏展示 URL 的字段映射。
- [ ] 基线的审批、存储、版本与可信动态区域配置；不得自动覆盖基线。
- [ ] 同规则多次命中的去重方式，以及源码通道、内联脚本摘要的扩展。
- [ ] HTTP/OpenAPI 中失败、跳过、版本等状态如何扩展；当前四字段模拟响应无法安全表达 failed/skipped。

可复现输入输出见 ../reports/module_contract_samples.json；函数签名来自实际代码调用，不代表队友已完成确认。
