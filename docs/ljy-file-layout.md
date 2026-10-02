# 文件说明与填写顺序

## 建议顺序

| 阶段 | 要做什么 | 完成标志 |
|---|---|---|
| 1. 接口冻结 | 与 lcx 确认 `PageInput`、`RawFinding` 和 `BaselineRecord` 字段 | `docs/interface_contract.md` 双方确认 |
| 2. 规则样例 | 写 3—5 条敏感信息规则和对应网页 | 每条规则至少有一个正例、一个反例 |
| 3. 三类检测 | 完成敏感信息、页面基线、外链变化模块 | 单元测试全部通过 |
| 4. 固定评测集 | 补齐 `ground_truth.json` | 每个用例都有唯一 `case_id` 和预期结果 |
| 5. 评测与修复 | 运行指标脚本并检查误报、漏报 | 产出 CSV、JSON 和误报记录 |
| 6. 交接 | 向 lcx、wjy 提供接口与样例 | 两份交接文档填写完成 |

## 目录总览

| 路径 | 用途 | 你需要填写/修改的内容 |
|---|---|---|
| `scanner/common/models.py` | 团队统一数据结构 | 只在与 lcx 达成一致后修改字段 |
| `scanner/common/text_utils.py` | HTML 正文、URL 和文本归一化 | 敏感扫描不忽略动态区域；基线忽略策略需可信配置 |
| `scanner/common/masking.py` | 证据脱敏 | 新增数据类型时补充掩码策略 |
| `scanner/rules/sensitive_rules.yaml` | 敏感信息规则库 | 规则 ID、匹配方式、排除项、严重度、说明 |
| `scanner/rules.py` | 加载和校验 YAML | 规则字段变化时同步修改 |
| `scanner/sensitive.py` | 敏感信息检测 | 处理误报、去重、证据截取 |
| `scanner/baseline.py` | 页面基线生成与比较 | 确定哪些变化应告警 |
| `scanner/external_links.py` | 外链提取与新增外链检测 | 维护允许域名及 URL 规范化 |
| `scanner/adapters/hengnao.py` | 将内部 RawFinding 转成现有恒脑模拟 API 字段 | 不部署接口；fixture 必须 simulated=true |
| `test_site/app.py` | 可控测试站点 | 新用例增加路由 |
| `test_site/state.json` | 当前基线阶段 | `before` 或 `after` |
| `test_site/pages/*.html` | 正反例页面 | 页面内不得放真实个人信息或密钥 |
| `tests/ground_truth.json` | 带标准答案的固定测试集 | URL、正负例、分类、规则 ID、期望数量 |
| `tests/test_*.py` | 自动化回归测试 | 每修一个误报或漏报都增加回归用例 |
| `tests/evaluate.py` | finding 和 case 指标、执行覆盖 | case_id/phase 匹配，与团队最终结果文件格式对齐 |
| `tests/run_local_evaluation.py` | 实际执行离线 fixture 并生成评测 | 三个本地模块，弱配置显式 skip |
| `tests/build_handoff_samples.py` | 调用检测器生成交接样例 | 先运行本地评测，再生成契约与解释素材 |
| `tests/test_hengnao_adapter.py` | 验证恒脑兼容字段、分类映射、脱敏和参数校验 | 修改兼容器后必须回归 |
| `tests/fixtures/local_cases.json` | 活动真值的输入场景映射 | 每个 case 恰好覆盖一次，同场景多个规则共同运行 |
| `tests/fixtures/planned_cases.json` | 源码/内联脚本后续用例草案 | 尚未实现，不计入当前活动指标 |
| `reports/actual_findings.json` | 实际发现、case_runs、环境与哈希 | 运行器自动生成 |
| `reports/module_contract_samples.json` | 三个模块的 6 条正反例输入输出 | 合成契约样例，非评测输入 |
| `reports/agent_examples.json` | 8 条解释/失败/跳过素材 | HTTP 包装仍是待确认映射 |
| `reports/hengnao_compatible_examples.json` | 6 条现有模拟 `/scan` 字段兼容响应 | 可交给 wjy 试运行；均为合成数据 |
| `reports/evaluation_results.*` | 指标产物 | 用实际运行结果替换示例 |
| `reports/false_cases.md` | 误报漏报台账 | 记录原因、修复方式、回归用例 |
| `docs/interface_contract.md` | 与 lcx 共用的契约 | 双方确认版本和变更记录 |
| `docs/rule_reference.md` | 规则说明 | 给答辩、报告和队友查阅 |
| `docs/evaluation.md` | 评测口径 | 明确 TP/FP/FN 的定义 |
| `docs/test_report.md` | 测试报告 | 环境、版本、结果、结论、限制 |
| `docs/handoff_to_lcx.md` | 给 lcx 的交接单 | 函数入口、输入输出、异常和示例 |
| `docs/handoff_to_wjy.md` | 给 wjy 的交接单 | 正反例、预期输出、演示顺序 |
| `docs/changelog.md` | 变更历史 | 每次规则或接口修改都登记 |

## 规则文件必须包含的内容

每条敏感信息规则至少包含：

- 稳定且唯一的 `id`，如 `SENSITIVE_PHONE_CN`；
- `name` 和 `description`；
- `match_type`：`regex` 或 `keyword`；
- 对应的 `pattern` 或 `keywords`；
- `severity`；
- `mask` 脱敏类型；
- `exclude_values` 和 `exclude_context_regex`；
- `enabled` 开关。

## 标准答案必须包含的内容

每个测试用例至少包含：

- 唯一 `case_id`；
- 要访问的 `url`；
- `phase`（无阶段时为 `none`）；
- `positive`（是否应产生告警）；
- `category`、`rule_id` 和 `expected_count`；
- 一句话 `reason`，解释为什么应该或不应该告警。

不要把程序当前输出直接复制成标准答案。标准答案应先由人根据赛题要求独立标注，再用程序输出与它比较。
