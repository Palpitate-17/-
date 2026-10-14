from __future__ import annotations

from http.cookies import CookieError, SimpleCookie

from scanner.common.models import PageInput, RawFinding


REQUIRED_HTML_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
)
SESSION_COOKIE_MARKERS = ("session", "auth", "token", "sid", "jwt")


def detect_weak_configuration(page: PageInput) -> list[RawFinding]:
    """Check only observable response settings, without claiming exploitation."""
    if page.status_code != 200:
        return []
    headers = {key.lower(): value for key, value in page.headers.items()}
    findings: list[RawFinding] = []
    media_type = page.content_type.lower().split(";", 1)[0].strip()

    if media_type == "text/html":
        missing = [name for name in REQUIRED_HTML_HEADERS if not headers.get(name, "").strip()]
        if missing:
            findings.append(RawFinding(
                category="weak_configuration",
                rule_id="SECURITY_HEADERS_MISSING",
                severity="low",
                url=page.final_url,
                title="HTML 响应缺少约定的安全响应头",
                evidence="HTTP 200；缺少响应头：" + ", ".join(missing),
                description="该 HTML 响应缺少项目检查清单中的响应头；是否构成实际风险仍需结合站点用途和部署策略判断。",
                remediation="评估并设置适合本站的 CSP、X-Content-Type-Options 与 Referrer-Policy。",
                metadata={"source_kind": "response_headers", "missing_headers": missing},
            ))

    # The crawler preserves separate Set-Cookie fields with newline separators.
    # Only inspect session-like cookies; values are never stored or reported.
    raw_cookies = headers.get("set-cookie", "")
    for raw_cookie in raw_cookies.splitlines():
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except CookieError:
            continue
        for name, morsel in cookie.items():
            if not any(marker in name.lower() for marker in SESSION_COOKIE_MARKERS):
                continue
            missing_flags = [flag for flag in ("secure", "httponly") if not morsel[flag]]
            if not missing_flags:
                continue
            findings.append(RawFinding(
                category="weak_configuration",
                rule_id="COOKIE_FLAGS_MISSING",
                severity="medium",
                url=page.final_url,
                title="会话类 Cookie 缺少安全属性",
                evidence=f"HTTP 200；Cookie {name} 缺少 " + ", ".join(missing_flags),
                description="会话类 Cookie 缺少建议的属性；仅根据名称判断用途，需人工确认是否承载认证状态。",
                remediation="确认 Cookie 用途，并为认证会话启用 HttpOnly；在 HTTPS 部署时启用 Secure。",
                metadata={"source_kind": "response_headers", "cookie_name": name,
                          "missing_flags": missing_flags},
            ))
    return findings
