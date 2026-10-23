# 网站安全智能巡检

本项目面向获得授权的网站巡检：发现页面，执行受控的被动检测，记录脱敏证据和复测状态，再由恒脑智能体解释结果。扫描范围必须事先明确；规则命中不等于已确认漏洞。

## 当前实现

| 模块 | 当前状态 | 入口 |
|---|---|---|
| Cloudflare Pages 即时巡检 | 已部署；只读取公开扫描器测试靶场的三个预设页面 | [部署说明](docs/cloudflare-live-scan.md) |
| 恒脑私有智能体 | 已发布；当前调用上述 Pages 接口 | [交付记录](docs/hengnao-private-delivery.md) |
| 真实巡检 API | 已实现版本化异步接口、SQLite 状态、API Key、覆盖状态和 JSON 报告；本地闭环已验证，尚未部署并接入恒脑 | [接口契约](docs/interface_contract.md)、[联调手册](docs/hengnao-live-integration.md) |
| 页面发现 | 同源、路径、页数、深度、速率和响应大小受控的 HTTP 爬取 | [爬虫实现](app/crawler.py) |
| 检测规则与评测 | 敏感信息、DOM/脚本基线、外链变化和本地风险规则 | [检测模块](docs/ljy-module-readme.md)、[评测结果](docs/evaluation.md) |
| 复测闭环 | 本地验证首次基线、页面变化、恢复页面和单条 `resolved` | [验证记录](reports/e2e_verification.md) |

## 本地运行真实巡检 API

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\scripts\run_local_demo.ps1
```

API 文档默认位于 `http://127.0.0.1:8000/docs`；可供恒脑导入的静态定义为 [`docs/openapi.json`](docs/openapi.json)。

早期离线 MVP、模拟 API 和本地演示仍保留在 [`prototype/`](prototype/) 与 [`docs/`](docs/) 中，便于复现开发过程。提交计划见 [`docs/submission-plan.md`](docs/submission-plan.md)。

所有扫描和测试只能用于本人所有或明确获得授权的目标。仓库不得提交 API Key、账号密码、真实个人信息或未脱敏的生产巡检日志。
