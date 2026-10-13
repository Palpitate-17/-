# 公开数据与远端巡检路线

团队尚无获授权的业务站点和常驻服务器。当前已完成本地演示站的实际 HTTP 巡检。公开可读的网站或数据集不自动成为允许主动巡检的目标。

## 数据源各自的用途

| 来源 | 用途 | 对作品的帮助 | 边界 |
| --- | --- | --- | --- |
| [OWASP Benchmark](https://owasp.org/projects/benchmark) | 自建运行可标注真值的测试应用 | 后续量化规则命中与误报 | 本仓库目前只检测少量被动规则，不声称覆盖 Benchmark 的漏洞种类 |
| [OWASP VulnerableApp](https://owasp.org/projects/vulnerableapp) | 自建可复现的脆弱应用 | 后续扩展测试场景 | 应部署在自己控制的环境中；不对其公共演示站发起扫描 |
| [OSV API](https://google.github.io/osv.dev/api/) | 查询给定生态、包名、版本的公开漏洞记录 | 给明确识别的组件版本补充情报 | 不从网页文字猜测实际安装版本；命中不等于网站可利用 |
| [CISA KEV](https://github.com/cisagov/kev-data) | 标记已知被利用的 CVE | 对 OSV 命中做优先级提示 | KEV 不证明该站点部署了受影响组件 |

CNVD/CNNVD 同样可以作为漏洞情报的参考来源，不能把其记录涉及的站点当成自动扫描授权。[Google Firing Range](https://github.com/google/firing-range) 官方明确称其公开实例是供 Web 安全扫描器测试的靶场，因此本仓库只对其首页、`/mixedcontent/index.html` 和 `/clickjacking/index.html` 做低频、只读巡检；混合内容只在实际页面包含 HTTP 脚本时报告，结论保留待核实。该站不是团队自建站，也不是业务网站。若需要交互练习，[PortSwigger Web Security Academy](https://portswigger.net/web-security) 提供专门的在线实验环境；单个实验环境有独立生命周期，不适合长期定时巡检。

## 已做的能力

`prototype/local_scan.py` 现在接受两种策略。默认 `scan-policy.json` 仍只允许本地演示站。公开站点需要单独复制 `scan-public-policy.example.json`，填写团队控制或获得明确授权的精确 HTTPS 域名和路径。程序只请求最多 10 条白名单路径，不跟随跳转；公共 DNS 解析结果必须都是公网地址，并在连接时固定已检查的 IP，TLS 证书仍按原域名校验。每次最多读取每页 256 KiB，超时 3 秒。策略中的 `data_kind` 要如实填写：团队公开虚构演示站用 `public_synthetic_demo`，公开扫描器靶场用 `public_scanner_testbed`，获授权真实业务站用 `authorized_public_site`。

在仓库根目录运行：

```powershell
Copy-Item -LiteralPath scan-public-policy.example.json -Destination scan-public-policy.json
# 编辑副本中的 target_url 与 allowed_paths；只填已获授权的网站。
& 'D:\AI\environ\python.exe' prototype\local_scan.py --policy scan-public-policy.json --baseline .public-baseline.json --output public-result.json --report public-report.html --history public-history.jsonl
```

这仍是在执行命令的机器上运行。仓库另有 `Scan public Firing Range testbed` 工作流，在 GitHub Actions 运行器每天 03:00 UTC 请求策略中允许的公开靶场页面，并把结果写入 `scan-results` 分支；也可在 Actions 页面手动运行。首次云端运行于 2026-10-14 成功：HTTP 200、读取 1 页、0 条规则发现、1 条响应头配置观察。恒脑可 GET `https://raw.githubusercontent.com/Palpitate-17/-/scan-results/results/latest.json` 读取最近一次结果；这不是实时 POST 扫描 API。若想在恒脑触发实时扫描，仍需要常驻云端 API 服务。

## OSV 与 KEV 查询

已知准确包名和版本时，可以查询公开漏洞库。以下是**数据库功能演示**，不代表本项目网站部署了 Jinja2：

```powershell
& 'D:\AI\environ\python.exe' prototype\vuln_intel.py --ecosystem PyPI --name jinja2 --version 2.4.1 --output vuln-intel.json
```

结果中的 `matches` 是该包版本的公开情报匹配；`cisa_kev` 仅标记对应 CVE 是否出现在 CISA 清单。报告必须保留 `assessment` 原文。没有可靠的组件版本证据时，跳过此查询，不生成网站漏洞结论。查询失败时应保持“情报查询未完成”，不能把网络错误解释成“没有漏洞”。

## 下一步验收

1. 确认 GitHub Actions 中 `Scan public Firing Range testbed` 成功，`scan-results` 分支出现 `results/latest.json`；核对请求页数和靶场域名。
2. 恒脑新增 GET 工具读取上述 JSON，在本机 API 与 Quick Tunnel 关闭的情况下复测；报告应标为“公开测试靶场”，不写真实业务风险。
3. 要演示可控的“新增、消失、变化”，继续使用团队自己的本地虚构站；若以后有自有公开站，再迁移到 HTTPS 环境。
4. 将 OSV/KEV 数据作为独立的“组件情报”章节，前提是拿到准确的包与版本证据。

## 团队 GitHub Pages 云端演示准备

仓库中也准备了 `public_demo/` 虚构网站及 GitHub Pages 工作流，但首次自动发布因仓库未启用 Pages 而失败。Pages 工作流改为手动触发，不影响上述 Firing Range 方案。只有具备仓库 admin/maintainer 权限的人在 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions** 后，才能发布团队自建 HTTPS 演示站。
