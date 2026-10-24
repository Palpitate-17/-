# Ljy 巡检规则、真实采集与评测模块

当前工作版本：v0.3.0；以下验证状态截至 2026-10-24。已完成版本化巡检 API、受控真实爬虫、增强后的三个检测器、SQLite 状态和审计、单条复测、JSON 报告及恒脑 OpenAPI。此模块仍是本地验证版本；当前已发布的恒脑智能体调用单独的 Cloudflare Pages 固定靶场接口。

## 一键验证

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\.venv\Scripts\python.exe -X utf8 -m tests.run_local_evaluation
.\.venv\Scripts\python.exe -X utf8 -m tests.build_handoff_samples
.\scripts\run_local_demo.ps1
```

## 当前实测

- pytest：64 项通过，1 条第三方框架弃用提示（2026-10-24）。
- 固定真值：29条，实际执行25条，4条弱配置用例明确 skipped。
- 成功执行子集：TP=19、FP=0、FN=0、TN=9；这是合成集结果，不代表真实互联网网站总体效果。
- 真实 TCP HTTP 闭环：两次均扫描9页；状态变化后出现四类发现；恢复页面后单条复测变为 resolved。

## 主要入口

| 目标 | 文件 |
|---|---|
| API 服务 | `app/main.py` |
| 契约 | `app/contracts.py`、`docs/openapi.json` |
| 真实爬虫与范围限制 | `app/crawler.py`、`app/security.py` |
| 任务编排与复测 | `app/service.py` |
| SQLite 存储与审计 | `app/store.py` |
| 三个检测器 | `scanner/sensitive.py`、`scanner/baseline.py`、`scanner/external_links.py` |
| 本地靶场 | `test_site/` |
| 端到端自动测试 | `tests/test_api_workflow.py` |
| 恒脑接入 | `docs/hengnao-live-integration.md` |

## 重要边界

- 只允许扫描本人所有或明确获授权的目标。
- 生产模式拒绝非公网解析结果；本地靶场模式必须由服务端显式启用。
- 外链风险规则是本地特征判断，不等同于在线信誉确认。
- 规则命中默认 `verification=pending`，不能直接宣称为已确认漏洞。
- 弱配置和常见漏洞模块仍未接入，不能用空结果掩盖跳过状态。
- Docker 文件已生成；当前机器有 Docker CLI，但守护进程未运行，因此尚未实际构建镜像。
- 恒脑私有智能体已发布并能调用固定靶场的 Pages 接口；本模块的通用 API 尚未部署和接入该智能体。
