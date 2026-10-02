# 给 wjy 的恒脑解释与演示材料

状态：解释素材已生成；wjy 确认、恒脑工具注册与运行联调仍待完成。恒脑暂按 HTTP/OpenAPI 接入设计。

## 素材

| 文件 | 用途 |
|---|---|
| reports/agent_examples.json | 三类正例/反例与失败/跳过的可展示结果、准确解释和禁止表述 |
| reports/hengnao_compatible_examples.json | 与现有模拟 `/scan` 顶层及 finding 字段一致的 6 条响应 |
| reports/module_contract_samples.json | 实际函数输入输出示例；含合成输入，仅供本地接入与教学 |
| reports/actual_findings.json | 真实离线执行输出，展示前只选择必要 finding 与状态 |
| docs/rule_reference.md | 规则的业务成立条件、排除、脱敏、修复与复测 |
| docs/test_report.md | 当前固定集指标与未覆盖范围 |

## 智能体的调用与解释

1. 通过后端工具获取采集/检测任务状态与结构化发现；以服务端批准范围为准。
2. 先检查 status 与 coverage。failed/inconclusive 表述“未完成，无法判断”；skipped 表述“该项未执行”。
3. succeeded 且 [] 只能说“本次适用规则未发现异常”；注明可见文本等覆盖通道。
4. 有告警时展示 category、rule_id、脱敏 evidence、建议。手机号/邮箱需要公开性策略；秘密字段是候选；页面和外链变化须核对发布。
5. 解释不能把新外链称为恶意链接、把摘要差异称为已被攻击、把关键词命中称为有效凭据。
6. 修复建议由规则决定；复测失败不能判已修复，合法变更不能自动刷新基线。

## 演示

先运行本地评测，再使用 agent_examples 展示三个模块正反例与一条失败状态。现有恒脑工作流如暂时不改字段，可从 hengnao_compatible_examples 中选择某个 `response` 试运行；这些样例全部必须保留 `simulated=true`。若演示 HTTP 采集，可启动 test_site 并使用原有 /sensitive/...、/baseline/home、/external/page、/dynamic 路由，before/after 由测试操作者切换；并发测试不应共同修改 state.json。

兼容 finding 只有 category、url、evidence_masked、verification、severity 五个字段；内部 rule_id、说明和整改建议没有丢失，只是暂不发送给旧工作流。不要把兼容导出器描述为已经完成 HTTP 或恒脑联调。

28 条是规则级真值 case 数，不等于 28 个网站路由。活动评测有 4 条弱配置 skip；planned_cases 中的源码/内联脚本草案没有运行。指标 1.0 仅针对小型成功执行合成子集，不能包装为真实网站的检测成功率。

现有审阅目录 examples/hengxun-inspection/SKILL.md 是调用与解释草案。后端提供经确认的 OpenAPI 工具之后，再绑定实际 tool 名称、鉴权、状态与覆盖字段；skill 本身不会执行扫描。

素材中的号码、邮箱、秘密都是合成值；输出脱敏策略见契约。队友接收确认、演示录像与恒脑联调记录尚未产生。
