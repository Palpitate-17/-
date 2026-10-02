# 规则与评测模块实际测试报告

日期：2026-10-02；工作包 v0.2.1。本次在原 ljy 模板内增加恒脑字段兼容导出并运行全部检测测试，未部署服务、未接入恒脑。目录没有 Git 提交号，输入/代码哈希见 reports/evaluation_results.json。队友独立复核仍待完成。

## 验证环境

| 项目 | 实测 |
|---|---|
| Python / OS | 3.11.15 / Windows |
| HTML / YAML | beautifulsoup4 4.15.0 / PyYAML 6.0.3 |
| pytest | 9.1.1 |
| 本地测试站 | fastapi 0.141.1、starlette 1.7.0、httpx 0.28.1、uvicorn 0.54.0 |
| 本次方式 | 固定 fixture 构造 PageInput；网站单元测试使用 TestClient |
| 网络与恒脑 | 本地评测没有网络采集，没有恒脑工具调用 |

实测环境为桌面临时 venv；复现命令见 README.md。requirements.txt 未锁定生产依赖；本次实际版本记在 reports/verification.json，不声称 Python 3.12 已验证。

## 实施与测试

- 新增检测回归初次运行 7 失败、1 通过，复现相邻敏感值泄露、动态区域漏检、长秘密残留、JSON 未匹配、form 漏采、非法 URL 异常、基线脚本 URL 未脱敏。
- 修复上述问题，补 phase/数组/执行覆盖、规则校验、空白与恢复、转义引号、URL IPv6/用户信息及超限回归。
- 最终 pytest：47 通过、0 失败，其中新增 8 项兼容导出测试。原始输出见 reports/pytest_results.txt。框架有 1 条 Starlette TestClient 对 httpx 的弃用提示，当前测试正常通过。
- 评测运行器真实调用 detect_sensitive、compare_baseline、compare_external_links；记录每个 case 状态，并保留未预期告警供 FP 统计。

## 固定集结果

原有 16 条真值保留，新增 12 条；共 28 条，17 正/11 反。实际执行 24 条（15 正/9 反），弱配置 4 条（2 正/2 反）显式 skipped。执行覆盖率 24/28=85.71%，failed=0、unrecorded=0。

| 分类 | 成功 / 总数 | TP | FP | FN | 负例 TN | Precision / Recall / F1 |
|---|---:|---:|---:|---:|---:|---|
| sensitive_info | 13 / 13 | 9 | 0 | 0 | 4 | 1.0 / 1.0 / 1.0 |
| page_baseline_change | 6 / 6 | 3 | 0 | 0 | 3 | 1.0 / 1.0 / 1.0 |
| external_link_change | 5 / 5 | 3 | 0 | 0 | 2 | 1.0 / 1.0 / 1.0 |
| weak_configuration | 0 / 4 | — | — | — | — | 未执行，指标 null |
| 成功执行子集 | 24 / 28 | 15 | 0 | 0 | 9 | 1.0 / 1.0 / 1.0 |

FDR=0，负例 case 误报率=0/9=0；mismatches=[]。这是小型合成集的当前结果，既不代表真实网站总体效果，也不代表完整集或弱配置已经通过。

固定集只对配置中的规则指标计量。状态码基线能力虽已有实现，本次未加入其独立固定评测用例；源码/内联脚本能力的草案样例未计入活动集。

## 运行与交接产物

- reports/actual_findings.json：实际发现、case_runs、环境、输入/代码快照。
- reports/evaluation_results.json / .csv：原始数量、分类指标、覆盖状态与差异。
- reports/module_contract_samples.json：三个模块各一正一反，共 6 条实际输入输出；不是完整效果报告。
- reports/agent_examples.json：6 条检测结果解释、1 条故意缺失 fixture 产生的失败、1 条实际弱配置 skip；HTTP 状态包装仍是拟接入格式。
- reports/hengnao_compatible_examples.json：6 条从实际离线检测结果转换的旧模拟 API 兼容响应；全部为合成数据、simulated=true。
- docs/interface_contract.md、handoff_to_lcx.md、handoff_to_wjy.md：接入行为与待确认事项。
- reports/false_cases.md：有回归依据的修复记录与尚未实现项。

## 性能

本次单次离线运行器总耗时 73.931 ms，包含加载规则/fixture 和本地检测，不包含网络采集、工具调用与报告写盘。每个共享场景耗时在 case_runs.scenario_elapsed_ms，不能按 case 相加。没有进行重复性能测量或 P50/P95 统计，不能据此承诺生产吞吐。

## 已知边界与下一步

1. HTML 敏感通道只处理可见文本，inline script 与独立 JS 秘密检测尚未实现；正反例已准备在 planned_cases.json。
2. 基线比较不含内联脚本摘要、外部脚本内容、资源删除项。内联字段扩展待与 lcx 确认。
3. data-ignore 是靶场约定，生产应改为可信资产配置的忽略策略，不能信任页面自报。
4. PII 正则不是公开性策略；字段关键词不证明凭据有效。需业务复核，不能给确认漏洞结论。
5. 脱敏只覆盖已配置类型与默认类型；未知或编码变体不保证识别。baseline、原正文和原 URL 属于受控内部数据。
6. 外链仅解析 HTTP(S) 引用，不访问目标、不做恶意信誉判断；畸形 URL 被忽略，覆盖统计待后续补充。
7. 不支持的 Content-Type 在底层返回 []，封装层必须标 skipped；超限抛错，不能将失败当无发现。
8. 原有 headers 字典不适合多条 Set-Cookie；弱配置由 lcx 接入后再统计。兼容导出器只生成 JSON 对象，HTTP 采集、鉴权、队列、审批、resolved 状态和恒脑调用未验证。
9. 真值由输入语义与既有规则定义编写，尚待队友独立复核；Python 3.12、生产页面、HTTP/OpenAPI 与恒脑工作流未验证。

本批成果可以用于三个模块的本地调用交接。下一批先确认接口与基线扩展，接入弱配置输出和实际 HTTP 工具，再补源码通道与恒脑流程的端到端用例。
