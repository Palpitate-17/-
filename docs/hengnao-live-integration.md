# 恒脑真实 API 接入与留证手册

状态：后端接口和本地网络闭环已完成；恒脑平台的真实工具节点需要队伍账号登录后配置和试运行。

## 1. 先部署可访问的 HTTPS API

本地启动：

```powershell
Copy-Item .env.example .env
# 编辑 .env，把 HENGXUN_API_KEY 换成随机长字符串
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/health
```

恒脑不能访问你电脑上的 `127.0.0.1`。联调时应把 API 部署到团队控制的 HTTPS 地址。临时演示可使用可信隧道服务把 `localhost:8000` 暴露为 HTTPS，但必须：设置 API Key、只使用自建靶场、演示结束立即关闭隧道。正式提交建议使用学校或团队控制的云主机和固定域名。

外网连通后先访问：

```text
https://你的API域名/health
https://你的API域名/openapi.json
```

## 2. 恒脑工具需要的接口

| 工具 | 方法与路径 | 用途 |
|---|---|---|
| 创建巡检 | `POST /api/v1/scans` | 返回 `scan_id` 和查询地址 |
| 查询状态 | `GET /api/v1/scans/{scan_id}` | 轮询至 `completed` 或 `failed` |
| 查询发现 | `GET /api/v1/scans/{scan_id}/findings` | 获取结构化风险和覆盖状态 |
| 单条复测 | `POST /api/v1/findings/{finding_id}/retest` | 返回 `open` 或 `resolved` |
| 导出报告 | `GET /api/v1/scans/{scan_id}/report` | 获取 JSON 报告 |

认证请求头：

```text
X-API-Key: 只保存在恒脑工具密钥配置中的值
```

可导入的接口定义见 `docs/openapi.json`。如果平台不支持整体导入，就按上表分别创建 API 工具。

## 3. 创建巡检请求样例

```json
{
  "target_url": "https://你们的授权测试站.example/",
  "authorization_confirmed": true,
  "allowed_hosts": ["你们的授权测试站.example"],
  "allowed_paths": ["/"],
  "denied_paths": ["/__test__"],
  "max_pages": 20,
  "max_depth": 2,
  "rate_limit_rps": 2,
  "timeout_seconds": 10,
  "lab_mode": false,
  "external_link_blocklist": ["malicious.example.invalid"]
}
```

恒脑工作流必须采用异步顺序：

```text
开始节点
→ 收集并确认授权范围
→ 创建巡检工具
→ 读取 scan_id
→ 查询状态（未完成则等待后重试，设最大次数）
→ 查询发现
→ 大模型依据 findings 与 coverage 解释结果
→ 结束节点
```

模型必须同时读取 `coverage`。`skipped`、`failed`、`inconclusive` 不能解释为“未发现风险”。

## 4. 恒脑提示词补充

```text
你是已授权网站安全巡检结果解释智能体。只能根据 API 工具真实返回的数据回答。

1. 创建任务前确认 authorization_confirmed=true，并复述 allowed_hosts、allowed_paths、denied_paths。
2. 任务未 completed 时不得生成最终安全结论；failed 时说明 error.code 与 error.message。
3. 对 coverage 中 skipped、failed、inconclusive 的模块逐项说明未覆盖，绝不写成“安全”。
4. 发现证据只能引用 evidence_masked，不输出或推测完整敏感值。
5. verification=pending 的结果统一写“规则命中，待人工核实”。
6. 不编造 API 未返回的漏洞、攻击过程、修复结果或工具执行情况。
7. 用户要求复测时，只把 finding_id 传给复测工具，根据返回的 open/resolved 解释结果。
```

## 5. 恒脑无法导出时的提交证据

至少保存以下材料，均不得包含账号密码、API Key 或真实敏感数据：

1. 工作流全景截图，能看清节点连接。
2. 每个工具节点的 URL、方法、请求映射和响应映射截图，密钥打码。
3. 系统提示词和用户提示词的仓库文本。
4. 一次成功创建任务、轮询、查询发现、复测的工具日志截图。
5. `docs/openapi.json` 和一组脱敏请求/响应样例。
6. 五分钟演示视频中的连续实录。
7. 平台中智能体名称、更新时间、运行成功状态截图。

这些材料用于证明恒脑中的实例可运行和可重建；仓库不需要包含恒脑账号本身。
