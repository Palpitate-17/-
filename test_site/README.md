# 测试站点使用说明

仅在本机或隔离的比赛演示环境启动：

```powershell
uvicorn test_site.app:app --host 127.0.0.1 --port 8001
```

## 切换前后状态

将 `state.json` 的 `phase` 改为 `before` 或 `after`，再访问：

- `/baseline/home`：页面基线变化；
- `/external/page`：外链变化。

不要把 `phase` 切换做成未鉴权的网络接口。上述切换用于手动 HTTP 演示。`python -m tests.run_local_evaluation` 使用固定 fixture，不需要启动网站或修改 state.json；新增 /fixtures/... 标识 URL 不是站点路由。

所有手机号、邮箱和凭据都是虚构测试值；不得在页面内填写真实个人信息、Cookie、Token 或口令。
