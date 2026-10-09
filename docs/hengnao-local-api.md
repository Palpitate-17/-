# 本地巡检 API 接入恒脑

此 API 只接受 `http://127.0.0.1:8765/`，只读取本机自建站点。HTTP 请求真实发生，站点内容和密钥标记均为虚构演示数据。恒脑需要临时 HTTPS 地址才能访问电脑上的 API。

## 1. 窗口 A：启动测试站

```powershell
Set-Location -LiteralPath 'C:\Users\31716\Documents\Codex\2026-09-28\d-xwechat-files-wxid-x22ulosxeoi422-1453-4\outputs\repo-upload'
Set-Content -LiteralPath demo_site\public\config.txt -Value '# 仅供本地演示，不是真实密钥','api_key=DEMO-ONLY-12345' -Encoding utf8
Remove-Item -LiteralPath .demo-baseline.json,demo-result.json,demo-report.html -ErrorAction SilentlyContinue
& 'D:\AI\environ\python.exe' -m http.server 8765 --bind 127.0.0.1 --directory demo_site
```

保持窗口 A 开着。已有测试站在 8765 运行时，不要再启动第二个；只需在另一个窗口重置文件和基线。

## 2. 窗口 B：启动 API

```powershell
Set-Location -LiteralPath 'C:\Users\31716\Documents\Codex\2026-09-28\d-xwechat-files-wxid-x22ulosxeoi422-1453-4\outputs\repo-upload'
if (-not (Test-Path -LiteralPath '.local-api-key')) { & 'D:\AI\environ\python.exe' -c 'import secrets; print(secrets.token_urlsafe(32))' | Set-Content -LiteralPath '.local-api-key' -Encoding ascii }
& 'D:\AI\environ\python.exe' prototype\local_scan_api.py
```

看到 `Local demo API listening on http://127.0.0.1:8001/scan` 后保持窗口 B 开着。`.local-api-key` 已被 Git 忽略；不要把文件内容发在聊天中，也不要上传到仓库。重新启动 API 时复用这个文件，避免恒脑里的密钥失效。

## 3. 窗口 C：先验证本机 API

```powershell
Set-Location -LiteralPath 'C:\Users\31716\Documents\Codex\2026-09-28\d-xwechat-files-wxid-x22ulosxeoi422-1453-4\outputs\repo-upload'
$scanKey = (Get-Content -LiteralPath .local-api-key -Raw).Trim()
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/scan' -Headers @{ 'X-API-Key' = $scanKey } -ContentType 'application/json' -Body '{"target_url":"http://127.0.0.1:8765/"}' | ConvertTo-Json -Depth 10
```

应返回 `simulated: false`、`data_kind: synthetic_local_demo`、3 个页面，以及本地测试标记对应的发现。也可打开 `demo-report.html` 看报告。若失败，先确认 A、B 两个窗口都在运行。

## 4. 窗口 D：临时 HTTPS 隧道

```powershell
& 'C:\ngrok\cloudflared.exe' tunnel --url http://127.0.0.1:8001
```

记下打印的 `https://...trycloudflare.com` 域名。隧道窗口 D 必须一直开着。每次新建 Quick Tunnel，域名可能不同。

先在窗口 C 验证隧道可达：

```powershell
Invoke-RestMethod -Uri 'https://你这次得到的域名.trycloudflare.com/health'
```

应得到 `status: ok`。这里只测试连通性，不包含密钥。

## 5. 恒脑 API 工具与工作流

在原 API 工具中把“请求地址”改为当前 `https://...trycloudflare.com` **域名**，能力“接口路径”仍为 `/scan`，请求方法 `POST`。请求头保留 `Content-Type = application/json`，并把 `X-API-Key` 的值更新为 `.local-api-key` 的完整内容；不要加引号、空格或 `Bearer`。工具输入参数 `target_url` 的样例值改为 `http://127.0.0.1:8765/`。本地演示站在你电脑上，由 API 读取；恒脑只调用临时 HTTPS API。

先在 API 能力编辑页调试，确认返回 `scan_id`、`simulated: false`、`data_kind: synthetic_local_demo`、`pages`、`findings`、`resolved_findings`、`changes`。再回工作流，把开始节点的测试输入设为 `http://127.0.0.1:8765/`，工具节点 `target_url` 引用开始节点输入，大模型用户提示词通过变量选择器引用工具节点的 `result_key`。结束节点继续引用大模型的 `result_key`。

大模型提示词要明确：这是本机虚构测试站；`simulated: false` 仅表示实际发起了本地 HTTP 请求，不代表真实业务网站风险已被验证。只根据 API 返回的字段描述当前发现、已消失的发现和页面变化；不得把测试标记说成真实密钥，也不得把页面变化直接称为篡改。

## 6. 复测

在窗口 C 执行：

```powershell
Set-Content -LiteralPath demo_site\public\config.txt -Value '# Local demo: issue removed' -Encoding utf8
```

再在恒脑试运行一次。预期 `findings` 为空、`resolved_findings` 有 1 条、`changes` 有 1 条。API 仍会同步写入 `demo-result.json` 和 `demo-report.html`，可在浏览器查看。若工具显示 `connect fail`，先检查 `/health`、三个服务窗口，以及 API 工具中是否保存了当前隧道域名；若显示 `Unauthorized`，检查 `.local-api-key` 与 `X-API-Key` 是否完全一致。
