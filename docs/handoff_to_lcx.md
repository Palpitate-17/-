# 给 lcx 的后端交接

当前不再需要 lcx 从零搭建巡检 API：`app/` 已包含可运行的 FastAPI、真实爬虫、SQLite、API Key、状态、coverage、复测和 JSON 报告。

请优先完成三件事：

1. 审阅并确认 `docs/openapi.json`，不要再维护另一套不兼容字段。
2. 把弱配置和安全模板结果转换为 `RawFinding` 或 v1 Finding，并把 coverage 从 skipped 改为真实状态。
3. 在有 Docker 的机器运行 `docker compose up -d --build`，验证 Python 3.12 镜像和持久化卷。

安全边界位于 `app/security.py`，真实采集位于 `app/crawler.py`，编排和复测位于 `app/service.py`。不要删除范围复核、DNS地址判断、限速、页面上限、响应大小和外链不访问策略。

最小验收：

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\scripts\run_local_demo.ps1
```

当前已知待协作项：基线人工审批、Set-Cookie多值、弱配置、Nuclei/ZAP安全模板、定时任务、HTML/PDF报告和部署到恒脑可访问的HTTPS地址。
