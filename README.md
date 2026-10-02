# -
命题企业：杭州安恒信息技术股份有限公司 赛题介绍：政企网站长期暴露在互联网中，易因组件漏洞、配置缺陷、页面被篡改或挂马而遭受攻击；同时，运维人员误发布文件、代码或业务数据，也可能造成敏感信息泄露。传统人工巡检覆盖有限、响应滞后。本赛题拟构建网站安全智能巡检智能体，在获得授权的前提下，周期性发现站点及下属页面，编排开源安全工具完成风险评估、内容完整性检测与敏感信息检查，形成可解释、可跟踪、可复测的风险闭环，提升单位网站持续安全运营能力。

## 当前模块

| 模块 | 当前状态 | 入口 |
|---|---|---|
| 真实巡检 API | 已实现版本化异步接口、SQLite 状态、API Key、模块覆盖状态和 JSON 报告 | [docs/interface_contract.md](docs/interface_contract.md) |
| 页面发现 | 已实现同源、路径、页数、深度、速率和响应大小受控的 HTTP 爬取 | [app/crawler.py](app/crawler.py) |
| 检测规则与评测 | 已实现敏感信息、DOM/脚本基线、外链变化和本地风险规则 | [docs/ljy-module-readme.md](docs/ljy-module-readme.md) |
| 复测闭环 | 已真实验证首次基线、页面变化、恢复页面和单条 `resolved` | [reports/e2e_verification.md](reports/e2e_verification.md) |
| 恒脑工作流 | 模拟流程已有；真实 API 接入所需接口、OpenAPI 和提示词已准备，平台账号内联调待完成 | [docs/hengnao-live-integration.md](docs/hengnao-live-integration.md) |

## 本地运行

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\scripts\run_local_demo.ps1
```

API 文档默认位于 `http://127.0.0.1:8000/docs`；可供恒脑导入的静态定义为 `docs/openapi.json`。

所有扫描和测试只能用于本人所有或明确获得授权的目标。仓库不得提交 API Key、账号密码、真实个人信息或未脱敏的生产巡检日志。
