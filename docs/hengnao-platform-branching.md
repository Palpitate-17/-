# 恒脑多节点实验工作流：路由与输出验收

> 记录日期：2026 年 10 月 22 日
>
> 平台实例：“安全测试”（ID `2111755398844555265`）
>
> 验收范围：无扫描工具的输入解析、路由和结束节点输出

本文件记录的是恒脑账号内的**另一条实验工作流**，不是仓库现有的“开始 → API 工具 → 大模型 → 结束”巡检报告流程。仓库 `main` 已有带密钥的 `POST /scan` 接口，使用部署主机上预先配置的目标策略；本实验工作流目前**没有绑定该 API 或扫描 MCP**。不要将下述 `status=not_run` 的试运行写成真实网站检测结果。

## 当前节点职责

```text
开始 → 模型1（输入提取）→ 代码_cklxPp（输入归一）→ 模型2（唯一需求判断）
     → 代码_cD64cQ（路由校验）→ 自规划_ZNkLGu（无工具答复）
     → 代码_T10JL6（待清理的冗余节点）→ 结束
```

| 节点 | 当前职责及关键输出 |
| --- | --- |
| 模型1 | 只提取 `user_text`、`document_text`、`image_text`、`document_status`、`image_status`，不再输出意图或下一动作。 |
| 代码_cklxPp | 合并和归一输入，供模型2读取 `combined_text`。 |
| 模型2 | 唯一产生 `intent`、`next_action`、`target_candidate`、`requested_checks` 等规划字段；不调用检测工具。 |
| 代码_cD64cQ | 校验规划结果并产生 `route`、`target_url`、`checks`、`message`；缺少目标网址时返回 `ask_user`。 |
| 自规划_ZNkLGu | 仅根据路由生成未执行状态的说明；MCP 配置为空，不执行扫描。 |
| 结束 | “回答内容”和隐藏的 `results.result_key` 均引用 `自规划_ZNkLGu.result_key`，不再引用下游返回 `null` 的 `代码_T10JL6.result_key`。 |

`代码_T10JL6` 仍在画布连线中，但其 `result_key` 曾为 `null`，不能当作最终回答。结束节点的其他隐藏字段 `route`、`target_url`、`checks`、`message` 仍引用 `代码_cD64cQ`；因此 `message` 是路由说明，可能不同于用户看到的完整答复，不要把二者当成同一字段。

## 本轮配置要点

- 模型2的规则明确：**用户要求扫描但未明确提供完整目标网址时**，`next_action=ask_user`，`clarification_question` 只追问网址；只有提供网址后才可提出 `call_scan` 候选。`call_scan` 本身不代表已获授权或已执行。
- 路由代码在 `route=scan` 分支、读取目标策略之前增加同一缺网址兜底；即使模型偶尔给出 `call_scan` 且 `target_candidate` 为空，也返回 `ask_user`。平台代码的原有目标策略和检查类别分支未因本轮修改而放宽。
- 自规划节点的提示词要求返回可直接解析的纯 JSON：首字符 `{`、末字符 `}`，不用 Markdown 代码围栏。其状态固定为 `not_run`，`tool_checks` 和 `findings` 为空数组，不得编造扫描结论。
- 结束节点的可见回答与 `results.result_key` 均选择“引用 → 自规划_ZNkLGu → result_key”。只连箭头而不改此引用，仍可能得到 `null`。

## 平台试运行

| 输入 | 最终结果 | 事实边界 |
| --- | --- | --- |
| `你能做什么？不要扫描网站。` | `status=not_run`、`route=reply`；结束节点返回非空、无代码围栏的 JSON 文本。 | 未调用检测工具。 |
| `请扫描网站` | `代码_cD64cQ` 返回 `route=ask_user`；结束节点返回 `status=not_run`、`route=ask_user`，询问具体网址。 | 没有目标，未扫描。 |

两种输入在保存后的恒脑画布上复测，结束节点显示运行成功。此前缺网址时曾观察到模型2输出 `call_scan`、路由返回 `error`；本轮修改后该集成用例已变为追问。**尚未单独注入“模型输出 `call_scan` 且网址为空”的代码节点单测**，不能把兜底分支写作独立验收通过。

## 与仓库 `/scan` 接口的后续衔接

仓库现有 [实时 API 部署说明](deploy-live-api.md) 使用 `POST /scan`、请求体 `{"target_url":"..."}` 与运行时 `X-API-Key`；服务端只接受部署主机策略中已配置的精确目标。要把这条实验工作流变成真实巡检，下一步需在 `route=scan` 之后接入 API 工具，将**经过策略校验的** `target_url` 传入工具，再让报告节点只解释本次 API 的实际返回值；工具失败或未运行时不得输出“已完成巡检”。密钥只保存在部署环境和平台工具配置中，不上传仓库。

本轮没有完成 API/MCP 调用、真实页面发现、告警、复测或报告导出；它们仍是赛题要求中的待验收项。画布上的冗余末端节点及“模型1：解读命令，判断类型”等旧说明也待后续清理。历史[模拟工作流](hengnao-workflow.md)和[API 联调记录](hengnao-api-integration.md)保持原状，不能用本文件覆盖其各自的测试范围。
