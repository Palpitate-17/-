# 离线 MVP：在新电脑或新目录复现

本说明适用于 Windows PowerShell。只运行仓库自带的 `127.0.0.1` 演示站；页面、密钥标记均为虚构数据。程序确实向本机发送 HTTP 请求，但不检测真实业务网站。需要 Python 3、curl，以及 `requirements.txt` 中的 Beautiful Soup 4 和 PyYAML；Git 仅用于克隆。恒脑通过比赛内网地址联调时不需要公网隧道；下方 cloudflared 步骤只供历史公网演示，不适用于封闭赛场。

## 1. 获取代码并检查环境

在 PowerShell 中克隆仓库，或者下载 ZIP 并解压，然后进入**实际存放项目的目录**：

```powershell
git clone --branch codex/offline-agent-integration https://github.com/Palpitate-17/-.git
Set-Location -LiteralPath '.\-'
python --version
curl --version
```

若 `python` 不在 PATH 中，以下命令的 `python` 可统一改成 `py -3`，或换成该电脑上的 Python 完整路径。PowerShell 提示符里不需要输入 `(base) PS ...>`。用 ZIP 时应下载 `codex/offline-agent-integration` 分支。以下所有命令均在仓库根目录执行。

联网准备离线依赖包时，在与赛场相同 Python 版本和操作系统的电脑执行 `python -m pip download -r requirements.txt -d wheelhouse`，把源码和 `wheelhouse/` 一起复制到内网。然后在赛场电脑的项目目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --find-links wheelhouse -r requirements.txt
.\.venv\Scripts\python.exe tests\check_local_api.py
.\.venv\Scripts\python.exe tests\check_team_modules.py
```

后续命令里的 `python` 应换成 `.\.venv\Scripts\python.exe`。`wheelhouse/` 和 `.venv/` 均不上传 GitHub。真正比赛内网离线安装尚待异机验证，不应在报告里写为已完成。

## 2. 本机启动（两个窗口）

窗口 A 运行以下命令并保持打开：

```powershell
python -m http.server 8765 --bind 127.0.0.1 --directory demo_site
```

窗口 B 先进入同一个仓库目录，再生成本机 API 密钥并启动 API：

```powershell
if (-not (Test-Path -LiteralPath '.local-api-key')) {
    python -c 'import secrets; print(secrets.token_urlsafe(32))' |
        Set-Content -LiteralPath '.local-api-key' -Encoding ascii
}
python prototype\local_scan_api.py
```

窗口 B 应显示 `Local demo API listening on http://127.0.0.1:8001/scan`。已有 `.local-api-key` 时不要重新生成，否则原工具请求头中的密钥会失效。该文件在 `.gitignore` 中；不要粘贴密钥到群聊、文档或提交材料。

## 3. 本机首次巡检与复测

窗口 C 进入同一个仓库目录，然后执行：

```powershell
Set-Content -LiteralPath demo_site\public\config.txt -Value '# 仅供本地演示，不是真实密钥','api_key=DEMO-ONLY-12345' -Encoding utf8
$scanKey = (Get-Content -LiteralPath '.local-api-key' -Raw).Trim()
Invoke-RestMethod -Uri 'http://127.0.0.1:8001/health'
$first = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/scan' -Headers @{ 'X-API-Key' = $scanKey } -ContentType 'application/json' -Body '{"target_url":"http://127.0.0.1:8765/"}'
$first | ConvertTo-Json -Depth 10
```

**全新目录**写入上面的演示标记后，预期结果：`status=ok`、`pages` 3 条、`findings` 3 条（1 条虚构敏感字段、2 条 HTML 弱配置观察）、`resolved_findings` 0 条。虚构敏感字段的 `evidence_masked` 只应显示 `api_key=[REDACTED]`。`simulated=false` 表示进行了本机 HTTP 请求；`data_kind=synthetic_local_demo` 表示数据仍是演示内容。若同目录之前运行过，请先查看现有 `demo-result.json` 和 `.demo-baseline.json`，不要随意清除历史来凑数量。

修改虚构演示文件后，在窗口 C 复测：

```powershell
Set-Content -LiteralPath demo_site\public\config.txt -Value '# Local demo: issue removed' -Encoding utf8
$second = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/scan' -Headers @{ 'X-API-Key' = $scanKey } -ContentType 'application/json' -Body '{"target_url":"http://127.0.0.1:8765/"}'
$second | ConvertTo-Json -Depth 10
Invoke-Item -LiteralPath demo-report.html
```

预期 `findings` 2 条（弱配置观察仍在）、`resolved_findings` 1 条、`changes` 1 条。`resolution_status=rule_no_longer_matched` 仅说明本次规则未再命中；哈希改变仅说明内容变化。`verification`、`severity` 仍为 `pending`。结果文件、基线、历史和 HTML 报告都是本机生成文件，已被 Git 忽略。

## 4. 可选：让恒脑调用本机 API

比赛内网中应由赛方允许的网络路径访问本机或内网部署的 API，具体地址和凭据必须现场确认。下面是历史公网演示路径，不应作为赛场默认部署方式。本机巡检成功后，若需要复现历史演示，可在新窗口 D 启动 cloudflared。把下面的 `cloudflared` 改成该电脑上的可执行文件路径，保持窗口 D 打开：

```powershell
cloudflared tunnel --url http://127.0.0.1:8001
```

将本次生成的 `https://...trycloudflare.com` **域名**填入恒脑 API 工具的“请求地址”；能力接口路径填 `/scan`，方法 `POST`，请求头 `X-API-Key` 填 `.local-api-key` 的完整内容，`Content-Type` 填 `application/json`。输入参数 `target_url` 应固定为 `http://127.0.0.1:8765/`，不得填隧道域名或外部站点。每次重启 Quick Tunnel 都要更新工具中的域名；重启 API 后也要确认密钥未变化。模型节点使用 [当前工作流提示词](hengnao-current-prompt.md)。

先在窗口 C 测试 `https://本次域名.trycloudflare.com/health` 返回 `ok`，再测试 API 工具，最后试运行整个工作流。`connect fail` 先检查 A、B、D 三个窗口和当前域名；`Unauthorized` 检查请求头与本机密钥是否一致。临时隧道适合演示，不保证长期可用。

## 5. 交接验证

队友在**独立新目录**执行 `python tests\check_local_api.py`，应看到 `Local API check passed`。该测试用临时目录和自建本地 HTTP 服务，不更改正在演示的基线与页面。复现记录只需写明 Python/curl 版本、运行命令、首次与复测的数量、异常信息；不要上传密钥或原始响应头。
