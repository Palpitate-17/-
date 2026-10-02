# 检测规则与实施边界

工作包 v0.2.0；可执行规则配置 version=1。匹配与脱敏逻辑属于本项目实现，并非从 CWE 下载的检测规则。来源查阅日期 2026-09-29，来源条目用于解释风险类别。

## 敏感规则

| ID / 严重度 | 业务成立条件 | 实际匹配 / 位置 | 排除与误报 | 证据、修复与复测 |
|---|---|---|---|---|
| SENSITIVE_PHONE_CN / medium | 业务要求该手机号不公开；当前没有自动判断公开性策略 | 可见 HTML、纯文本、JSON；大陆手机号边界正则 | 排除 13800138000；近邻示例/占位/测试上下文；公开客服电话需人工核对 | 139****5678，周边值同步脱敏；确认后删除/脱敏，同一 URL 成功采集后复测 |
| SENSITIVE_EMAIL / low | 邮箱按业务策略非公开 | 大小写不敏感邮箱正则，位置同上 | 排除 security@example.invalid 与近邻示例上下文；支持邮箱可能允许公开 | a***@corp.invalid；确认后替换入口/脱敏，复测原位置 |
| SENSITIVE_SECRET_KEYWORD / high | 页面非必要展示一个非空秘密字段候选 | api_secret/access_token/password；支持 key=value、带引号的 JSON key:value；字段名大小写不敏感 | 空字符串不告警；近邻示例/占位/测试上下文排除；无法证明候选有效 | 字段名加 ***，不保留凭据前后缀；确认是真实凭据后撤下并轮换；复测字段与页面 |

手机号与邮箱发现先作为“疑似非公开信息”处理。CWE-359 的风险涉及未经授权访问私有个人信息；仅匹配号码或邮箱无法证明该条件已成立。[CWE-359](https://cwe.mitre.org/data/definitions/359.html)

可公开访问文件中的秘密候选可参考 CWE-538；本模块没有验证真实凭据，也未实现源码通道。[CWE-538](https://cwe.mitre.org/data/definitions/538.html)

示例：正例写“值班电话：13912345678”；不要把“测试手机号”写进正例正文后期待它通过上下文排除规则。虚构说明放在用例元数据中。

## 统一脱敏

先在完整检测文本中找所有已配置匹配与默认手机/邮箱/秘密字段、URL，再截取安全证据。是否告警与是否脱敏分开：排除值、禁用规则匹配仍可能出现在其他证据中，因此也遮蔽。重叠匹配使用整段掩码；赋值秘密支持超过旧 64 字符限制的完整值。

所有查询参数值均遮蔽，不输出 userinfo 和 fragment。URL 查询字符串可能进入日志、历史记录等，这是采用默认遮蔽策略的依据。[OWASP：URL 查询字符串信息暴露](https://community.owasp.org/vulnerabilities/Information_exposure_through_query_strings_in_url)

脱敏覆盖本项目已配置的数据类型；无法识别任意未知秘密、加密/编码变体或路径中的任意敏感语义。内部原始页面与基线必须受控，不能直接给智能体或公开报告。手机号保留前 3 后 4 位，邮箱保留域名；业务要求更严格时将 mask 改为 full。

## 基线规则

| ID | 比较 / 严重度 | 证据与控制 |
|---|---|---|
| BASELINE_STATUS_CHANGED | 状态码 / medium | 输出旧→新状态；须先排除抓取失败 |
| BASELINE_TITLE_CHANGED | title 文本 / medium | 标题变化片段使用默认脱敏；合法发布可造成告警 |
| BASELINE_TEXT_CHANGED | 归一化可见文本 SHA-256 / low | 只输出摘要不同事实；忽略脚本/样式与 data-ignore 动态区域 |
| BASELINE_SCRIPT_ADDED | 新增 HTTP(S) script[src] URL / high | URL 查询值遮蔽；新增脚本不等于恶意脚本 |

成立条件：可信、已批准且同视图的基线。只报告变化候选，人工核对发布后更新基线；恢复后的空差异不自动更改后端 resolved。当前 data-ignore 是靶场约定，可能被页面修改者滥用，生产接入必须改为可信资产配置管理的忽略策略。

## 外链规则

EXTERNAL_LINK_ADDED / medium：从 a[href]、img[src]、script[src]、iframe[src]、link[href]、form[action] 提取 HTTP(S) URL，对允许域名之外且相对基线新增的引用告警。主机名按相等或点边界子域名比较；允许 test.local 不会放行 test.local.evil.invalid。

证据为脱敏 URL，metadata.added_url 同样脱敏。内部 URL 保留查询顺序与重复参数；合法 CDN、合作链接需要审批，不进行恶意信誉判断。修复后与原批准基线再次比较，不访问外部目的地。

## 扩展准备

- INTERNAL_PROJECT_KEYWORD：配置样例在 scanner/rules/internal_keywords.example.yaml，默认关闭；普通 keywords 是字面短语，已通过自定义关键词回归。只在业务定义为非公开后启用。
- SOURCE_SECRET_CANDIDATE：拟新增独立源码通道，HTML 内联 script 与已授权 JS/JSON，字段与值联合判定。匹配不得改变 visible_text 的手机号规则。正反例在 tests/fixtures/planned_cases.json，尚未实现。
- BASELINE_INLINE_SCRIPT_CHANGED：拟保存内联脚本摘要与位置，需与 lcx 对齐 BaselineRecord 扩展；只导出摘要与位置，待实现。

新增规则需同时准备稳定 ID、业务适用条件、输入位置、匹配方法、脱敏证据、排除/误报、修复/复测和至少一正一反用例。CWE/CVE 知识不是可直接执行的漏洞检测程序；工具负责确定性检测，skill 负责调用顺序、适用边界与解释。

规则来源记录：docs/rule_sources.json。当前已记录链接、查阅日期、来源版本及用途；正式发布前仍需团队复核与来源快照/许可确认，不能把草案卡片直接启用。
