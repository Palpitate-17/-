# 公开数据与远端巡检路线

截至 2026-10-12，团队尚无获授权的业务站点和常驻服务器。当前已完成本地演示站的实际 HTTP 巡检；本文件中的公开站点模式尚未在团队自有 HTTPS 站点验证。公开可读的网站或数据集不自动成为允许主动巡检的目标。

## 数据源各自的用途

| 来源 | 用途 | 对作品的帮助 | 边界 |
| --- | --- | --- | --- |
| [OWASP Benchmark](https://owasp.org/projects/benchmark) | 自建运行可标注真值的测试应用 | 后续量化规则命中与误报 | 本仓库目前只检测少量被动规则，不声称覆盖 Benchmark 的漏洞种类 |
| [OWASP VulnerableApp](https://owasp.org/projects/vulnerableapp) | 自建可复现的脆弱应用 | 后续扩展测试场景 | 应部署在自己控制的环境中；不对其公共演示站发起扫描 |
| [OSV API](https://google.github.io/osv.dev/api/) | 查询给定生态、包名、版本的公开漏洞记录 | 给明确识别的组件版本补充情报 | 不从网页文字猜测实际安装版本；命中不等于网站可利用 |
| [CISA KEV](https://github.com/cisagov/kev-data) | 标记已知被利用的 CVE | 对 OSV 命中做优先级提示 | KEV 不证明该站点部署了受影响组件 |

## 已做的能力

`prototype/local_scan.py` 现在接受两种策略。默认 `scan-policy.json` 仍只允许本地演示站。公开站点需要单独复制 `scan-public-policy.example.json`，填写团队控制或获得明确授权的精确 HTTPS 域名和路径。程序只请求最多 10 条白名单路径，不跟随跳转；公共 DNS 解析结果必须都是公网地址，并在连接时固定已检查的 IP，TLS 证书仍按原域名校验。每次最多读取每页 256 KiB，超时 3 秒。策略中的 `data_kind` 要如实填写：公开虚构演示站用 `public_synthetic_demo`，获授权真实业务站用 `authorized_public_site`。

在仓库根目录运行：

```powershell
Copy-Item -LiteralPath scan-public-policy.example.json -Destination scan-public-policy.json
# 编辑副本中的 target_url 与 allowed_paths；只填已获授权的网站。
& 'D:\AI\environ\python.exe' prototype\local_scan.py --policy scan-public-policy.json --baseline .public-baseline.json --output public-result.json --report public-report.html --history public-history.jsonl
```

这仍是在执行命令的机器上运行。若要摆脱本机与 Quick Tunnel，下一步用 GitHub Actions 或团队服务器运行同一命令；恒脑读取其 HTTPS JSON 结果。GitHub Pages 可托管团队自建演示站和静态结果，但它本身不能处理当前的 `POST /scan`。因此恒脑工具届时需要改成读取静态 JSON 的 GET 接口，或接入真正的云端 API。仅把本机扫描脚本指向公开域名并不能解决本机依赖。

## OSV 与 KEV 查询

已知准确包名和版本时，可以查询公开漏洞库。以下是**数据库功能演示**，不代表本项目网站部署了 Jinja2：

```powershell
& 'D:\AI\environ\python.exe' prototype\vuln_intel.py --ecosystem PyPI --name jinja2 --version 2.4.1 --output vuln-intel.json
```

结果中的 `matches` 是该包版本的公开情报匹配；`cisa_kev` 仅标记对应 CVE 是否出现在 CISA 清单。报告必须保留 `assessment` 原文。没有可靠的组件版本证据时，跳过此查询，不生成网站漏洞结论。查询失败时应保持“情报查询未完成”，不能把网络错误解释成“没有漏洞”。

## 下一步验收

1. 由团队控制的 HTTPS 测试站上线，并取得项目组对精确域名和路径的同意；把虚构测试页面放在那里。
2. 用单独策略在该站做首次和修改后的复测，检查 `findings`、`resolved_findings`、`changes` 是否符合预期。
3. 在 GitHub Actions 或云主机重跑同一策略，保存 JSON/HTML 结果和执行日志；再让恒脑读取稳定 HTTPS 地址，关闭本机 API 和 Quick Tunnel 后复测。
4. 将 OSV/KEV 数据作为独立的“组件情报”章节，前提是拿到准确的包与版本证据。
