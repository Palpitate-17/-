# 评测口径与运行方法

## 本地实际执行

```powershell
python -X utf8 -m tests.run_local_evaluation
```

读取 tests/ground_truth.json 与 tests/fixtures/local_cases.json，以固定 fixture 构造 PageInput，实际调用三个检测器，写入 reports/actual_findings.json，再计算 JSON/CSV 指标。不会读取并切换 state.json，不会访问外链。

同一 scenario 可对应同页多个规则 case；检测一次，按规则关联 case。未预期的规则仍会保留并记 FP，不会先过滤掉。manifest 必须恰好覆盖每个 case 一次。

每个 case 留下 succeeded、failed 或 skipped 记录。原有 4 条弱配置用例等待 lcx 接入，显式跳过。源码与内联脚本基线的拟新增样例在 planned_cases.json，不属于当前活动评测。

## 导入其他实际结果

```powershell
python -X utf8 -m tests.evaluate --ground-truth tests/ground_truth.json --findings reports/actual_findings.json
```

findings 输入可为裸数组，或对象 {findings: [...], case_runs: [...]}。禁止默认使用 actual_findings_example.json 冒充实际执行。裸数组只能计算发现数量匹配；无法证明空结果来自成功执行，因此 coverage.verified=false、case_metrics=null。

匹配键：case_id + phase + category + rule_id + 规范化 URL。phase 包含 before/after/restored/none；URL 相同但阶段不同，不能互抵 TP。无 case_id 时只在完整键唯一的情况下关联；有阶段的用例缺 phase 会报错。同一完整键多个 case 时必须给 case_id。URL 移除 fragment、统一 scheme/netloc 大小写，保留查询顺序；当前固定集的页面 URL 不包含查询值，脱敏后同形 URL 需要通过 case_id 和后端扫描上下文区分。

## 两种统计单位

| 单位 | 指标 | 定义 |
|---|---|---|
| finding | TP | 正确键上数量 min(expected, actual) |
| finding | FP | 不应出现、错阶段/错规则/错 URL、或超出期望的告警数 |
| finding | FN | 正确键上缺少的预期告警数 |
| finding | Precision / Recall / F1 / FDR | TP/(TP+FP)、TP/(TP+FN)、2TP/(2TP+FP+FN)、FP/(TP+FP) |
| negative case | TN | 成功执行且没有任何关联告警的反例数 |
| negative case | negative_case_fpr | 出现告警的反例数 / 成功执行反例总数 |
| execution | coverage | 成功执行 case / 全部活动 case；同时报告 failed/skipped/unrecorded |

分母为零的指标输出 null。跳过/失败/没有执行记录的 case 不进入成功执行子集指标；不能因此宣称完整测试集召回率为 100%。未能关联 case 的告警计 finding FP，另列 unassigned_findings，不用于负例 case 分母。

运行器发现 failed、FP 或 FN 返回非零退出码；仅有明示 skipped 不导致失败。输入哈希记录代码、配置和页面 fixture；目录没有 Git 提交号时用此快照追溯。case_runs 的 scenario_elapsed_ms 是整个共享场景耗时，同场景记录不可相加。

## 扩展用例

先独立定义期望规则/数量与 reason，再在 manifest 加对应输入，避免把当前程序输出抄作真值。本次新增真值由既定输入语义给出，尚未经队友独立标注复核。变更后运行相关回归与本地评测，检查全部 mismatches 和覆盖状态。状态码基线等能力只有单元覆盖或尚未进入固定指标时，应单列说明。
