# 爬虫与检测模块接口草案（待双方确认）

截至 2026-10-22，wjy 的抓取程序在 `prototype/local_scan.py` 中已经取得页面 URL、HTTP 状态、Content-Type 和正文，但公开结果中的 `pages` 只有 URL 与状态。以下约定用于 **wjy 输出 Asset → 队友接收 Asset 并输出 Finding**。现有恒脑工作流仍通过外层 `POST /scan` 读取报告；下面的代码节点连接方式是待联调的新方案，尚未接入现有工作流。

## 恒脑代码节点间传输（优先采用）

你发的恒脑模板只规定 `handler(args: Args) -> dict` 怎样读写节点参数，没有规定业务数据结构。建议爬虫节点的输出参数命名为 **`assets_json: String`**，值是 Asset 数组的 JSON 字符串；检测节点的输入参数同名，使用恒脑变量选择器引用上一个节点的 `assets_json`。检测节点输出 **`findings_json: String`**，值是 Finding 数组的 JSON 字符串。这样不依赖平台是否支持复杂对象类型，且可以用 Python 标准库 `json` 在两端解析。不要手写变量引用语法。

```python
# 爬虫节点 handler 中，assets 是本次抓取后得到的 Asset 字典列表
return {"assets_json": json.dumps(assets, ensure_ascii=False)}

# 检测节点 handler 中
assets = json.loads(args.input.assets_json)
findings = []  # 队友按规则逐条检测后填充
return {"findings_json": json.dumps(findings, ensure_ascii=False)}
```

本地联调仍用 UTF-8 JSON Lines 文件：爬虫写 `assets.jsonl`，每行一个 Asset；检测模块读这个文件，写 `findings.jsonl`，每行一个 Finding。两人可分别在本机测试。文件和代码节点使用**同一字段结构**，转换方式是 `json.dumps(list_of_assets)` / `json.loads(assets_json)`。两个本地文件已加入 `.gitignore`，不能上传真实网页正文。

## Asset v1（爬虫输出）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema_version` | string | 固定 `1.0`。 |
| `scan_id` | string | 同一轮扫描使用同一个 ID。 |
| `url` | string | 本次实际请求的绝对 URL；只能在事先配置的授权范围内。 |
| `resource_type` | string | `html`、`text`、`script`、`style`、`json`、`other` 之一。 |
| `content_type` | string | 原响应的 Content-Type，例如 `text/plain; charset=utf-8`；缺失时为空字符串。 |
| `status_code` | integer | 实际 HTTP 状态码，例如 `200`。网络请求失败不伪造 Asset，另记抓取错误。 |
| `headers` | object | 响应头，键统一小写、值为字符串；交接前移除 Cookie、认证信息等敏感值。 |
| `body_text` | string | 解码后的文本，最多 256 KiB；非文本资源用空字符串。只传给检测模块，不写入恒脑最终结果。 |

本地虚构测试样例（不是有效密钥）：

```json
{"schema_version":"1.0","scan_id":"demo-001","url":"http://127.0.0.1:8765/public/config.txt","resource_type":"text","content_type":"text/plain; charset=utf-8","status_code":200,"headers":{"content-type":"text/plain; charset=utf-8"},"body_text":"api_key=DEMO-ONLY-12345"}
```

## Finding v1（检测模块输出）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema_version` | string | 固定 `1.0`。 |
| `scan_id` | string | 复制对应 Asset 的 `scan_id`。 |
| `category` | string | 稳定规则类别，例如 `sensitive_exposure` 或 `mixed_content`。 |
| `url` | string | 命中的 Asset URL。 |
| `evidence_masked` | string | 脱敏后的短证据，不包含完整密钥、密码或 Cookie。 |
| `verification` | string | 初始为 `pending`；未人工验证不写 `confirmed`。 |
| `severity` | string | 初始为 `pending`；分级需要独立证据。 |

可选字段：`potential_impact`、`remediation_if_confirmed`。一条 Asset 可以产生 0 到多条 Finding；无命中时不输出 Finding 行。示例：

```json
{"schema_version":"1.0","scan_id":"demo-001","category":"sensitive_exposure","url":"http://127.0.0.1:8765/public/config.txt","evidence_masked":"api_key=[REDACTED]","verification":"pending","severity":"pending"}
```

## 联调验收

1. wjy 提供上面的虚构 Asset，再提供一个正文不含敏感标记的 `/about.html` Asset。
2. 检测模块对前者输出一条脱敏 Finding，对后者输出零条；`scan_id` 和 `url` 一致。
3. 双方交换各自生成的 JSONL 文件并检查 UTF-8、字段名、类型和输出数量。
4. 选择代码节点方案时，恒脑工作流用“开始 → 爬虫代码节点 → 检测代码节点 → 报告模型节点 → 结束”。报告模型只读取脱敏后的 `findings_json` 和页面摘要，不引用 `assets_json` 中的 `body_text`；现有报告提示词要改为读取新字段。若继续使用现有外部 `/scan` API，由 wjy 将 Finding 合并进响应的 `findings` 数组，保留其他顶层字段，此时不需要添加爬虫代码节点。

本地实际抓取时，在自建演示站运行后，执行 `python prototype/local_scan.py --assets-output assets.jsonl` 即可生成 Asset 样例。`body_text` 可能包含页面中的敏感内容，先用虚构测试站联调；不要将真实网页正文放进聊天、仓库、日志或模型提示词。

需要双方确认的只有两点：`resource_type` 的枚举是否满足检测规则，以及队友是否需要更多**不含敏感值**的响应头。确认后再锁定 v1，避免双方边开发边改字段名。
