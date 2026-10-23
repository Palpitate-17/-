# 真实 HTTP 端到端验证记录

验证日期：2026-10-03。目标仅为本机自建授权靶场。

## 验证拓扑

```text
PowerShell 客户端
→ http://127.0.0.1:18000 巡检 API
→ http://127.0.0.1:18001 自建靶场
```

API 与靶场分别运行在独立 Uvicorn 进程中，巡检通过真实 TCP HTTP 请求完成，不使用测试进程内传输。

## 本次结果

| 阶段 | 结果 |
|---|---|
| 首次巡检 | `completed`，发现并扫描 9 页，7 条发现 |
| 切换靶场后巡检 | `completed`，发现并扫描 9 页，18 条发现 |
| 第二次巡检类别 | sensitive_info、page_baseline_change、external_link_change、external_link_risk |
| 单条复测 | 恢复页面后，指定外链变化从 `open` 变为 `resolved` |
| 执行覆盖 | crawler、sensitive、baseline、external_links 均 succeeded |
| 明确未覆盖 | weak_configuration、common_vulnerability 均为 skipped，不冒充“无问题” |

本次动态任务 ID 为临时运行证据，数据库位于被 Git 忽略的 `.runtime/`，不作为固定测试真值。可使用 `scripts/run_local_demo.ps1` 重新生成同类验证结果。
