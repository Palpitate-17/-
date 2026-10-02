# 实际问题与回归台账

2026-09-29。删除原虚构“示例-001”关闭记录。以下关闭项有新增回归验证；已关闭不代表所有输入形式都能覆盖。

| 编号 | 类型 / 现象 | 修复 | 回归 / 状态 |
|---|---|---|---|
| R01 | 当前命中脱敏，旁边手机/邮箱/秘密泄露 | 完整文本先识别脱敏跨度，再生成片段 | test_every_exported_finding_masks_adjacent_values / 已关闭 |
| R03 | data-ignore 导致敏感值漏检 | 敏感可见文本和基线忽略行为分离 | test_baseline_dynamic_ignore_does_not_suppress_sensitive_scan / 已关闭 |
| R04 | form action 外链未采集 | 增加 form，严格 HTTP(S) | test_external_form_and_query_values_are_safe / 已关闭 |
| R05 | 证据和元数据输出外链查询凭据 | 所有查询值遮蔽、移除 userinfo/fragment；基线脚本展示同步处理 | test_external_form_and_query_values_are_safe、test_baseline_script_query_is_redacted / 已关闭 |
| R07 | before 的 FP 抵消 after 的 FN | case_id + phase + 分类/规则/URL 匹配 | test_wrong_phase_is_false_positive_and_false_negative / 已关闭 |
| R08 | 裸 findings 数组 .get 导致崩溃 | 验证数组/对象格式，支持 case_runs | test_array_object_and_invalid_findings / 已关闭 |
| R09 | Cookie 标注错误称 SameSite 缺失 | 修正 W-P02 reason 为缺 Secure/HttpOnly | 原 test_test_site Cookie 实测；弱配置检测仍未接入 / 已关闭（标注） |
| NEW01 | 密钥截到 64 字符后残余明文 | 赋值值完整识别，固定掩码，不保留前后缀 | test_long_secret_and_excluded_neighbor_are_still_redacted / 已关闭 |
| NEW02 | JSON 赋值未匹配、空值可能误报 | 支持引号/冒号并排除空字符串 | test_json_assignment_and_empty_value / 已关闭 |
| NEW03 | 畸形端口 URL 令外链解析失败 | 跳过 ValueError 地址与非 HTTP(S) | test_external_links_reject_non_http_and_malformed_urls / 已关闭 |
| R02 | 内联 script 秘密未检测 | 独立源码通道待实现，已准备正反例 | planned_cases.json / 待实现 |
| R06 | 内联脚本变化未纳入基线 | 摘要字段扩展待与 lcx 确认 | planned_cases.json / 待确认 |

新增 8 条检测回归初次运行：7 失败、1 通过；修复后全部通过。phase/数组问题在前次 characterization_results.json 已有复现，本次对应单元验证通过。补充 JSON 转义引号等边界后，最终全套 39 通过。

本次固定集 mismatches=[]，FP=0、FN=0；未执行的弱配置、源码/内联脚本拟新增能力不能由这一结果推断有效。
