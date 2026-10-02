# 变更日志

## v0.2.1 — 2026-10-02

- 新增 `scanner/adapters/hengnao.py`，将内部 RawFinding 转换为 PR #1 模拟 `/scan` 的现有字段，不修改队友代码。
- 分类在兼容层映射为 sensitive_exposure、integrity_change、external_link_change；内部类别保持不变。
- 展示 URL 和 evidence_masked 再次防御性脱敏，verification 固定 pending。
- 新增参数、分类、空结果、不可变性和脱敏测试；全量 pytest 47 项通过。
- 交接脚本从实际离线检测输出生成 6 条 `hengnao_compatible_examples.json`；全部明确为合成数据和 simulated=true。

限制：这里只生成响应对象和样例，没有部署 `/scan`、没有修改恒脑节点，也没有完成真实 HTTP 联调。现有四字段顶层格式无法安全表达 failed/skipped，仍需 lcx/wjy 确认后续扩展。

## v0.2.0 — 2026-09-29

本地实施，目录没有 Git 提交号；代码与输入快照 SHA-256 在 reports/evaluation_results.json。

- 修整段证据脱敏；排除值与相邻匹配也遮蔽，凭据不保留前后缀。
- 修长凭据截断残留；赋值关键词支持带引号的 JSON key:value，空字符串不产生发现。
- 分离可见敏感扫描与基线动态忽略；动态区域里的手机号仍参与敏感检测。
- 外链增加 form[action]，限定 HTTP(S) 并跳过畸形地址；URL 查询值、userinfo、fragment 不出现在导出结果。
- 修基线新增脚本的 URL 展示脱敏；URL 规范化保留 IPv6 与内部请求语义。
- 强化 YAML 根节点、字段类型、布尔开关、mask、正则与排除正则校验。
- 敏感正文超限抛错；HTTP 层的状态映射仍待确认。
- 评测以 case_id/phase/分类/规则/URL 匹配，支持数组与对象输入，区分执行覆盖和 finding/case 指标；不再默认读示例发现。
- 新增实际离线运行器、12 条活动真值、3 条后续草案、规则来源记录、契约/解释样例和真实报告。
- 校正 W-P02 的 SameSite 标注；共享 dataclass 与现有函数参数顺序保持。

验证：39 个 pytest 通过；24/28 case 执行，4 个弱配置 skipped，TP=15/FP=0/FN=0/TN=9。源码通道、内联脚本基线、弱配置检测及 HTTP/恒脑接入仍待实现。

## 初始模板

三个检测器骨架、本地测试站、16 条真值与文档模板。
