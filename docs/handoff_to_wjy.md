# 给 wjy 的恒脑交接

真实接口已经完成，不再使用手工粘贴模拟资料作为最终流程。

请使用：

- `docs/openapi.json`：恒脑 API 工具定义。
- `docs/hengnao-live-integration.md`：节点顺序、鉴权、提示词和留证清单。
- `reports/e2e_verification.md`：本地真实 HTTP 闭环结果。
- `app/contracts.py`：字段与状态的代码定义。

恒脑必须执行：创建任务→轮询状态→读取 findings 和 coverage→解释结果→需要时调用复测。模型不得把 skipped/failed 当作安全，也不得把 `verification=pending` 写成已确认漏洞。

恒脑平台无法导出时，保存工作流全景、每个工具节点、变量映射、脱敏调用日志、提示词和连续演示录像。不要截图或提交 API Key、手机号、密码、验证码和真实敏感数据。
