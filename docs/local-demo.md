# 本地巡检演示：逐步操作

下面只访问自己电脑上的 `127.0.0.1`。这一步先验证真实 HTTP 请求、页面发现、敏感字段脱敏与复测；它还不是完整参赛作品，也不用 Cloudflare 或恒脑。

## 1. 开第一个 PowerShell 窗口：启动测试站

```powershell
Set-Location -LiteralPath 'C:\Users\31716\Documents\Codex\2026-09-28\d-xwechat-files-wxid-x22ulosxeoi422-1453-4\outputs\repo-upload'
& 'D:\AI\environ\python.exe' -m http.server 8765 --bind 127.0.0.1 --directory demo_site
```

看到 `Serving HTTP on 127.0.0.1 port 8765` 后保持窗口打开。浏览器打开 `http://127.0.0.1:8765/`，应能看到“巡检本地演示站”。

## 2. 开第二个 PowerShell 窗口：首次巡检

```powershell
Set-Location -LiteralPath 'C:\Users\31716\Documents\Codex\2026-09-28\d-xwechat-files-wxid-x22ulosxeoi422-1453-4\outputs\repo-upload'
Set-Content -LiteralPath demo_site\public\config.txt -Value '# 仅供本地演示，不是真实密钥','api_key=DEMO-ONLY-12345' -Encoding utf8
Remove-Item -LiteralPath .demo-baseline.json,demo-result.json,demo-report.html -ErrorAction SilentlyContinue
& 'D:\AI\environ\python.exe' prototype\local_scan.py
Get-Content -LiteralPath demo-result.json -Raw -Encoding utf8
Invoke-Item -LiteralPath demo-report.html
```

首次应看到 `3 pages, 1 active, 0 resolved, 0 changed`。JSON 中 `simulated` 为 `false`，因为确实请求了本地网页；`data_kind` 为 `synthetic_local_demo`，表示页面内容仍是虚构测试数据。唯一当前发现应为 `sensitive_exposure`，证据仅显示 `api_key=[REDACTED]`。正常的 `about.html` 不应报问题。浏览器会打开 `demo-report.html`。

## 3. 修改演示页面并复测

仍在第二个 PowerShell 窗口运行：

```powershell
Set-Content -LiteralPath demo_site\public\config.txt -Value '# Local demo: issue removed' -Encoding utf8
& 'D:\AI\environ\python.exe' prototype\local_scan.py
Get-Content -LiteralPath demo-result.json -Raw -Encoding utf8
Invoke-Item -LiteralPath demo-report.html
```

这次应看到 `3 pages, 0 active, 1 resolved, 1 changed`。原来的 `sensitive_exposure` 出现在 `resolved_findings`，配置文件的哈希变化出现在 `changes`。这证明程序读到了刚修改的真实页面，并检测到原有测试问题已消失；真实风险仍须另外核实。

## 4. 定时复扫与历史记录

测试站窗口保持运行时，可以在另一个 PowerShell 窗口运行：

```powershell
& 'D:\AI\environ\python.exe' prototype\local_scan.py --interval 30
```

程序会立即巡检一次，此后每 30 秒复扫；按 `Ctrl+C` 停止。每次成功巡检都会覆盖最新的 `demo-result.json`、`demo-report.html`，并向 `demo-history.jsonl` 追加一条仅含时间、目标 URL 和数量统计的记录。查看历史：

```powershell
Get-Content -LiteralPath demo-history.jsonl -Encoding utf8
```

请勿同时运行命令行定时复扫和 API 工作流巡检，它们共用同一份本地基线。连接本地测试站失败时，定时程序会记录错误并在下一轮重试；失败的轮次不会写入历史。

## 5. 重置，方便下次演示

```powershell
Set-Content -LiteralPath demo_site\public\config.txt -Value '# 仅供本地演示，不是真实密钥','api_key=DEMO-ONLY-12345' -Encoding utf8
Remove-Item -LiteralPath .demo-baseline.json,demo-result.json,demo-report.html,demo-history.jsonl -ErrorAction SilentlyContinue
```

只删除本演示生成的基线和结果。第一个窗口用 `Ctrl+C` 停止测试站。不要将真实密钥写入测试页面或仓库。

当前脚本只允许 `http://127.0.0.1:<port>/`，最多读取 10 个页面、单页 256 KiB，不跟随跳转，也不请求外部链接。定时复扫仅在命令行进程运行期间生效；告警、自定义授权范围和真实网站验证仍是后续阶段。HTML 报告只覆盖本地演示结果。

文本内容比较会忽略 LF 与 CRLF 换行差异，避免 Windows 的 Git 换行转换产生误报；其他内容变化仍会记录。历史中已写入的旧记录不会被改写。
