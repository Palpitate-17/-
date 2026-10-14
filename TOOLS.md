# 工具清单与运行状态

| 工具/组件 | 用途 | 是否由智能体调用 | 当前状态 |
| --- | --- | --- | --- |
| Python 标准库 | 精确白名单抓取、`/scan` API、报告 | 是，作为工作流 API | 已接入；本地 API 回归通过 |
| Beautiful Soup 4 | 页面正文、DOM、外链解析 | 间接，由 `/scan` 调用 | 已列入 `requirements.txt`；离线检测回归通过 |
| PyYAML | 加载本地敏感规则 | 间接，由 `/scan` 调用 | 已列入 `requirements.txt`；离线检测回归通过 |
| curl | 同一目标的被动 HEAD 检查 | 间接，由 `/scan` 调用 | PR 已接入；本地测试通过 |
| 恒脑 | 通过 API 工具调用 `/scan`，模型整理结果 | 是 | 仓库有历史调用记录；本次账号内实测待完成 |

本轮不会调用 DeepSeek、OSV/CISA 在线漏洞情报、Nuclei 或其他主动漏洞扫描工具。`prototype/vuln_intel.py` 是上游历史文件，不在本轮工作流中调用。团队检测器仅处理已获准抓取的页面，命中结果均为待核实。

离线部署时需先在联网电脑执行 `python -m pip download -r requirements.txt -d wheelhouse`，把 `wheelhouse/` 与源码复制到比赛内网，再用 `python -m pip install --no-index --find-links wheelhouse -r requirements.txt` 安装。wheelhouse 含第三方发行包，不提交 GitHub；2026-10-14 已在本机全新虚拟环境验证离线安装及三组回归，尚未在真正比赛内网或另一台电脑验证。
