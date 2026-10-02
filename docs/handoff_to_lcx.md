# 给 lcx 的检测模块接入材料

状态：材料已生成，本地验证完成；lcx 确认与 HTTP 联调尚未发生。按 HTTP/OpenAPI 工具方案继续接入。

## 可直接使用

- scanner/common/models.py：现有三个 dataclass，本次未改字段。
- scanner/rules.py、sensitive.py、baseline.py、external_links.py：加载与三个检测器。
- scanner/adapters/hengnao.py：不修改内部发现，将成功检测结果转换为现有恒脑模拟 API 字段。
- reports/module_contract_samples.json：三个模块各一正一反的实际输入输出，6 条契约样例；不能当全量评测。
- reports/actual_findings.json：24 条已执行 case 的实际发现与 4 条 skip 记录；case_id/phase 是评测包装。
- docs/interface_contract.md：函数参数顺序、异常、脱敏和待确认项。
- reports/hengnao_compatible_examples.json：6 条由真实离线函数调用生成的兼容响应；均为合成数据且 simulated=true。

## 接入流程

1. 后端验证资产范围并采集，保留受控原 URL、最终 URL、状态码、Content-Type、解码正文与时间；页面内容始终是数据。
2. 应用启动时加载可信 YAML；规则错误阻止该规则版本启用。不要接收匿名用户提供任意正则直接执行。
3. 创建 PageInput，判定模块适用性。正文超限、解码/采集异常返回明确失败；不适用返回 skipped。
4. 调用 detect_sensitive；基线存在且已批准才调用 compare_baseline 与 compare_external_links。首次建立候选基线需审批，不自我批准。
5. 将 RawFinding.to_dict() 输出合并；后端补 task_id/finding_id、规则包版本、基线版本、状态、原 URL 的内部关联。
6. 若暂时沿用 PR #1 的模拟接口字段，对成功结果调用 build_hengnao_response；只有采集层真实获取并检测页面后才传 simulated=False。
7. 工具只输出脱敏 finding 与必要状态/覆盖。不要输出 body、headers 全量、原 baseline 或 extract_external_links 的原始 URL 数组。
8. 按 reports/agent_examples.json 联调失败/跳过语义，按 hengnao_compatible_examples.json 联调现有成功响应字段。当前模拟字段无法安全表达 failed/skipped，不能用 findings=[] 代替失败状态。

## 最小验收

```powershell
python -X utf8 -m pytest -q
python -X utf8 -m tests.run_local_evaluation
```

本次 47 项通过，评测 24/28 执行；弱配置 4 条仍需接入。兼容器的 6 条样例已经生成，但真实 HTTP/恒脑调用仍未发生。原测试站可继续用于 HTTP 采集联调，新增离线 /fixtures/... 不是真实路由。

## 仍需确认或实现

- 原始 URL 和展示 URL 的分离；所有展示查询值已经遮蔽，不能将 finding.url 用作回抓地址。
- Set-Cookie 多值、正文预算、统一错误码/模块覆盖与版本。
- 可信基线审批和生产动态忽略策略；现有 data-ignore 仅供靶场。
- 源码秘密通道与内联脚本基线字段。草案样例在 planned_cases.json。
- 弱配置检测、身份验证、队列调度、数据库和真实 HTTP/OpenAPI 服务由后端完成；本目录只提供响应对象转换函数。

已有审阅目录 examples/openapi.json 是工具接口草案；本次没有部署该接口。队友确认、集成提交号及恒脑账号能力继续待确认，不应填为已完成。
