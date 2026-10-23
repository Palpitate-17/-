# Cloudflare 上的即时巡检接口

恒脑的用户私有 API 工具调用 Cloudflare Pages Functions 的 `POST /scan`。该请求实时读取预设的三个 Google Firing Range 测试靶场页面，返回实际 HTTP 状态、脱敏规则发现和被动配置观察。服务不依赖本机 Python API、隧道或用户电脑在线。

## 固定范围

目前只接受 `https://public-firing-range.appspot.com/`，只请求 `/`、`/mixedcontent/index.html` 和 `/clickjacking/index.html`。其他网址返回 HTTP 400，且不会请求该网址。请求为低影响 GET，不跟随重定向；单页最多读取 256 KiB。新增网站须先取得明确授权及范围，再修改服务端白名单并复核规则。

本接口只有本轮的发现和被动配置观察，没有持久化的前次基线，因此不会判定“本次已消失”或“内容变化”。`scan_status=partial` 表示至少一个页面没有正常完成；此时不能把空 `findings` 解释成安全。`result_key` 是同一结果的 JSON 字符串，供恒脑代码节点引用。

## 当前部署

- Pages 地址：`https://hengnao-authorized-scan.pages.dev/scan`，恒脑实际连接此地址。`/health` 返回 `{"status":"ok"}`。
- Pages 项目：`hengnao-authorized-scan`，Secret 名称 `SCAN_API_KEY`。
- 另有 Worker 地址：`https://hengnao-authorized-scan.repo-upload.workers.dev/scan`。该地址在本机可用，但恒脑平台自动调试无法连接，所以未用于恒脑工具。

Pages Functions 源码在 [`cloudflare/pages/functions/scan.js`](../cloudflare/pages/functions/scan.js)，共用 [`cloudflare/scan-core.mjs`](../cloudflare/scan-core.mjs) 的白名单和规则。使用 Wrangler 从 `cloudflare/pages` 目录部署：

```powershell
npx wrangler pages deploy public --project-name hengnao-authorized-scan --branch main
```

若在另一个 Cloudflare 账号首次部署，先建立 Pages 项目并配置加密 Secret `SCAN_API_KEY`。本地密钥文件为 `cloudflare/.dev.vars`，已被 Git 忽略；不要把值写进源码、文档或聊天。Pages Secret 与恒脑 API 工具请求头 `X-API-Key` 必须一致。工具请求头还需 `Content-Type: application/json`。

## 恒脑配置与验收

私有工具能力路径 `/scan`，方法 `POST`，必填 Body 字段 `target_url`。智能体工具节点引用路由代码节点的 `target_url`，报告代码节点的 `input` 引用路由结果，`scan_result` 引用工具输出 `result_key`；结束节点引用报告代码节点的 `result_key`。后者是已校验的可读文本。

试运行输入：`请对 https://public-firing-range.appspot.com/ 执行网站巡检，仅检查预设的三个公开测试页面，并报告实际请求结果。` 验收时核对工具节点输出新的 `scan_id`、`execution_mode=on_demand`、`scan_status` 和三个页面的 HTTP 状态，再核对结束节点报告使用同一时间。2026-10-23 的一次恒脑试运行已完成，三页均返回 200，规则发现 1 条、被动观察 3 条；规则命中仍待核实。

当前接口没有登录态扫描、组件版本识别、漏洞利用或任意网站的授权范围。
