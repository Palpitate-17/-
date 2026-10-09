# 恒脑网站巡检验证版：API 联调记录

> 负责人：wjy
> 日期：2026 年 10 月 2 日
> 状态：恒脑已通过临时 HTTPS 地址调用本地模拟 API，工具、模型和结束节点均返回预期结果。真实巡检尚未实现。

## 已验证的调用链

```text
开始节点 input → API 工具节点 target_url → 大模型节点 → 结束节点
```

| 节点 | 当前配置 | 已验证结果 |
| --- | --- | --- |
| 开始 | 必填 `input: String`，试运行填写 `https://demo.example.test/` | 将目标 URL 传入工具 |
| API 工具 | “网站巡检模拟API”中的“模拟网站巡检”；`POST /scan`；`target_url` 引用开始节点的 `input` | 返回 `scan_id=mock-001`、`simulated=true`、`target_url`、`findings` |
| 大模型 | HengNao-v4 快速决策，Temperature `0.2`；用户提示词引用工具节点的 `result_key` | 根据工具返回的 JSON 生成报告 |
| 结束 | 回答内容引用大模型节点的 `result_key` | 输出完整报告，而非 `_error_code` |

API 工具请求头包含 `X-API-Key` 和 `Content-Type: application/json`。密钥只保存在运行环境和恒脑工具配置中，不写入仓库。工具节点的 `result_key` 是完整 JSON 的字符串；节点也解析出 `scan_id`、`simulated`、`target_url`、`findings`。

## 本地模拟 API 与临时 HTTPS

本地服务代码见 [mock_scan_api.py](../prototype/mock_scan_api.py)。它只接受 `https://demo.example.test/`，从[本地测试材料](../prototype/offline_fixture.json)生成模拟发现，不访问目标网站。启动前在同一个 PowerShell 窗口设置 `SCAN_API_KEY`，然后运行脚本。另一个窗口用 Cloudflare Quick Tunnel 将 `http://127.0.0.1:8000` 暴露为临时 HTTPS 地址；恒脑 API 工具的请求地址填域名，能力路径填 `/scan`。

临时域名每次重建可能改变；本地 API 或隧道停止后，恒脑无法调用。正式演示应改用稳定 HTTPS 服务地址。若重新启动 API，确保 8000 端口只有一个监听进程，以免新旧密钥混用。

## 输入输出约定

请求：

```http
POST /scan
Content-Type: application/json
X-API-Key: <运行时密钥>

{"target_url":"https://demo.example.test/"}
```

模拟响应：

```json
{
  "scan_id": "mock-001",
  "simulated": true,
  "target_url": "https://demo.example.test/",
  "findings": [
    {
      "category": "sensitive_exposure",
      "url": "https://demo.example.test/public/config.txt",
      "evidence_masked": "api_key=[REDACTED] (simulated HTTP 200)",
      "verification": "pending",
      "severity": "pending"
    },
    {
      "category": "content_changed",
      "url": "https://demo.example.test/",
      "evidence_masked": "SHA-256 mismatch: expected 16bfc1ebd014, actual cce820515e1c (fixture)",
      "verification": "pending",
      "severity": "pending"
    }
  ]
}
```

## 2026-10-05 离线 MVP 进展

`/scan` 的请求与顶层返回字段保持不变。服务现在逐页读取本地测试材料：检测形如 `api_key=...` 的演示字符串并隐藏其值；比较页面内容与预设 SHA-256 基线，生成内容变化记录。无异常的 `/about` 页面不会被列为发现。两类发现都保持 `simulated=true`、`verification=pending`、`severity=pending`，不能作为真实漏洞或篡改证据。

运行 `python prototype/mock_scan_api.py --self-test` 可检查两类发现、脱敏、正常页面和超出测试范围的输入。这个版本不抓取网页、不发现子页面，也不判断页面是否真的对匿名用户开放。待提供获授权的测试站和真实 API 后，再做端到端联调。

## 大模型提示词要点

系统提示词要求仅根据提供的证据判断，区分模拟发现、待核实和已验证事实；不能将测试标记当作真实密钥，也不能声称实际访问或扫描网站。缺少访问权限验证时不得把公开可访问作为已证实事实；真实风险等级在验证前写“待定”。

用户提示词在“API 返回数据：”后，通过**恒脑变量选择器**引用 API 工具节点的 `result_key`。不要手写或猜测平台变量语法。核心要求是：`simulated=true` 时将所有发现标为“模拟发现、待核实”，保留 `pending` 状态，只引用 API 提供的 URL 与脱敏证据。

演示前需在恒脑界面核对最终保存的提示词，并将准确文本补充到仓库；本节只记录设计要点。

## 2026-10-02 联调验收

1. PowerShell 调用临时 HTTPS `/scan` 返回模拟 JSON。
2. 恒脑创建 API 工具能力时，自动调用显示“响应成功”，并解析出四个输出字段。
3. 工作流按“开始 → 工具 → 大模型 → 结束”运行成功。
4. 工具节点的 `result_key` 含完整模拟 JSON；结束节点输出中文巡检报告，明确“模拟发现、待核实”，展示脱敏证据，没有宣称实际扫描。

当时的验收截图：[工具节点输出](images/hengnao-tool-output.png)、[结束节点报告](images/hengnao-end-result.png)。它们记录的是 10 月 2 日的固定响应版本；10 月 5 日的离线规则版已通过本地自检，尚未在恒脑重新试运行。截图只包含虚构测试值，没有运行密钥。

## 下一阶段交接

- **lcx：**提供稳定 HTTPS 地址和第一版真实巡检 API；与 wjy 确认请求和响应字段。真实接口至少需要强制校验授权范围、限制请求次数，并返回可复现的原始证据。
- **ljy：**提供自建测试站点和正反例。测试数据使用虚构值，标注预期发现与不应报告的情况。
- **wjy：**把此文档及成功截图放进队长的 GitHub 仓库；接入真实 API 后复测字段映射、误报表述与结束节点报告。当前模拟数据不能作为真实检测结果。

仓库不得包含 API 密钥、账号密码或未脱敏的真实站点数据。
