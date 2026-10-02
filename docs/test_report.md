# v0.3.0 实际测试报告

日期：2026-10-03。全部目标均为合成 fixture 或本机自建授权靶场。

## 结果摘要

| 项目 | 结果 |
|---|---|
| Python / OS | Python 3.11 / Windows |
| pytest | 63 passed，0 failed，1条第三方弃用提示 |
| 离线真值 | 29条；25 succeeded、4 skipped、0 failed |
| 成功子集 finding 指标 | TP=19、FP=0、FN=0、Precision/Recall/F1=1.0 |
| 成功负例 | TN=9，负例 case 误报率0 |
| 真实 HTTP 首次巡检 | 9页、7条发现、completed |
| 真实 HTTP 变化巡检 | 9页、18条发现、completed |
| 单条复测 | 页面恢复后由 open 变为 resolved |

离线指标只代表当前小型合成集，不能写成系统在未知真实网站上的准确率。四条弱配置真值仍明确跳过。

## 已验证能力

1. API Key、版本化请求/响应、异步任务状态和失败信息。
2. 授权 host/path、重定向、页数、深度、速率、正文大小和生产地址限制。
3. 真实发现 HTML、JS、JSON 页面资源，外链不进入爬取队列。
4. 可见文本、HTML 注释、内联 JavaScript、独立 JS/JSON 的敏感候选检测与证据脱敏。
5. 正文、DOM、标题、状态、外部/内联脚本、form、iframe、meta refresh 基线。
6. 外链新增、来源标签、本地黑名单、Punycode/IP/userinfo 特征。
7. SQLite 任务、finding、baseline 和审计记录，以及单条复测状态更新。
8. OpenAPI 1.0 文件可生成并解析，共6条路径。

## 验证命令

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\.venv\Scripts\python.exe -X utf8 -m tests.run_local_evaluation
.\.venv\Scripts\python.exe -X utf8 -m tests.build_handoff_samples
.\.venv\Scripts\python.exe -X utf8 -m scripts.export_openapi
.\scripts\run_local_demo.ps1
```

真实 HTTP 运行记录见 `reports/e2e_verification.md`。

## 未验证或未完成

- 弱配置和常见漏洞检测仍为 skipped。
- 尚未测试生产公网网站、并发压力、P50/P95 或长时间稳定性。
- Python 3.12 和 Docker 镜像尚未实测；当前机器未安装 Docker 命令。
- 恒脑官网可以访问，但浏览器当前需要队伍账号、密码和验证码，尚未产生真实工具调用日志。
- 当前只有 JSON 报告，没有 HTML/PDF 报告、定时调度或告警界面。
- 基线首次成功抓取后自动建立，比赛终版仍应增加人工审批与版本选择接口。
