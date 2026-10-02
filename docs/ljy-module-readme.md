# Ljy 巡检规则与评测模块

当前工作版本：v0.2.1（2026-10-02）。已完成三个检测器、统一证据脱敏、真实离线评测入口，以及与 PR #1 模拟 `/scan` 四个顶层字段和五个 finding 字段兼容的导出器。兼容器只生成 JSON，不会部署 HTTP 服务或修改队友分支；队友契约仍待确认。

## 直接运行

在 PowerShell 中执行：

```powershell
# 先进入团队仓库根目录
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
.\.venv\Scripts\python.exe -X utf8 -m tests.run_local_evaluation
.\.venv\Scripts\python.exe -X utf8 -m tests.build_handoff_samples
```

评测无需启动网站、联网或修改 test_site/state.json；它读取固定 HTML/JSON fixture 并实际调用检测器。输出在 reports/actual_findings.json、evaluation_results.json 和 evaluation_results.csv。交接脚本还会生成 reports/hengnao_compatible_examples.json。

依赖实测版本见 `../reports/verification.json`。本次实测 Python 3.11.15，尚未验证方案目标 Python 3.12。

## 当前结果

- pytest：47 项通过；1 条框架弃用提示记录在测试报告。
- 固定真值：28 条，实际执行 24 条，4 条弱配置用例跳过，执行覆盖率 85.71%。
- 成功执行子集：TP=15、FP=0、FN=0；负例 TN=9，负例误报率 0。小型合成集不能代表真实网站总体效果。

## 从哪些文件开始

| 目标 | 文件 |
|---|---|
| 看本次改动与局限 | [test_report.md](test_report.md) |
| 接入检测函数 | [interface_contract.md](interface_contract.md)、[handoff_to_lcx.md](handoff_to_lcx.md) |
| 准备恒脑解释文案 | [handoff_to_wjy.md](handoff_to_wjy.md)、[agent_examples.json](../reports/agent_examples.json) |
| 保持现有模拟 API 字段 | `../scanner/adapters/hengnao.py`、[hengnao_compatible_examples.json](../reports/hengnao_compatible_examples.json) |
| 修改可执行规则 | `../scanner/rules/sensitive_rules.yaml`；自定义关键词样例 `internal_keywords.example.yaml` |
| 增加测试数据 | `../tests/fixtures/local_cases.json` + `../tests/ground_truth.json` |
| 理解评测口径 | [evaluation.md](evaluation.md) |
| 查看后续实现样例 | `../tests/fixtures/planned_cases.json`（草案，不计入活动评测） |

本地演示网站可单独启动：

```powershell
python -m uvicorn test_site.app:app --host 127.0.0.1 --port 8001
```

新增加的 /fixtures/... 是离线用例的标识 URL，并非测试站路由。兼容样例全部标记 simulated=true；只有 lcx 的采集层真正获取并检查页面后才能设置 false。内联脚本秘密检测、内联脚本基线、弱配置检测器和恒脑 HTTP 联调仍待后续实现，详见测试报告。
