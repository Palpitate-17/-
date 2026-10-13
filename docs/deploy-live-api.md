# 部署可由恒脑实时调用的巡检 API

当前支持的公开目标只有策略中列出的 Google Firing Range 测试靶场。恒脑传入 `target_url` 后，API 当次发起请求并返回 JSON；未配置的目标返回 400。只有在目标管理方允许测试且已确定具体范围后，才新增对应策略文件。

## Render 免费 Web Service 演示部署

1. 在 [Render](https://dashboard.render.com/) 注册或登录，选择 **New → Web Service**，连接团队仓库 `Palpitate-17/-`，分支选 `main`，Runtime 选 **Python 3**，实例选 **Free**。
2. Build Command 填 `python -m compileall -q prototype`；Start Command 填 `python prototype/local_scan_api.py --policy scan-public-policy.firing-range.json`。
3. 在 **Environment** 新增 `SCAN_API_KEY`，值为至少 32 个字符的随机密钥。只在 Render 和恒脑请求头中保存，不提交到 GitHub，也不要发到聊天。无需手工设置 `PORT`；程序会监听 Render 提供的端口。
4. 部署成功后，在浏览器访问 `https://你的服务名.onrender.com/health`，预期 `{"status":"ok"}`。这只说明 API 在线。
5. 在 PowerShell 中用同一密钥调用 `POST /scan`；把 `$apiBase` 改为 Render 给出的实际地址，`$scanKey` 只在当前终端会话中设置：

   ```powershell
   $apiBase = 'https://你的服务名.onrender.com'
   $scanKey = Read-Host '输入 SCAN_API_KEY'
   Invoke-RestMethod -Method Post -Uri "$apiBase/scan" -Headers @{ 'X-API-Key' = $scanKey } -ContentType 'application/json' -Body '{"target_url":"https://public-firing-range.appspot.com/"}' | ConvertTo-Json -Depth 10
   ```

6. 恒脑原来的 API 工具仍用 `POST /scan`；“请求地址”填 Render 服务**域名**，能力路径填 `/scan`，请求头填 `X-API-Key` 和 `Content-Type: application/json`。工具输入参数 `target_url` 必须引用开始节点的用户输入；试运行输入 `https://public-firing-range.appspot.com/`。模型节点引用工具的 `result_key`，用 [当前提示词](hengnao-current-prompt.md) 整理报告。

第一次请求只扫描 3 条已允许路径，返回 `data_kind=public_scanner_testbed`。同一目标在 300 秒内重复请求返回 429。若返回 503，先看 Render Logs 和目标出站连通性；`/health` 成功不能证明目标可达。

Render Free 服务空闲后会休眠，首次唤醒可能较慢；本地文件在重启或休眠后不持久，因此云端即时报告的 `resolved_findings` 和 `changes` 只对当前实例保留的基线有效。需要可靠的跨重启历史时再接持久存储。免费实例也有流量与运行时限制，部署前核对 [官方免费服务说明](https://render.com/docs/free)。
