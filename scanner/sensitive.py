from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup, Comment

from .common.masking import iter_rule_matches, mask_match, mask_url, redaction_spans, redacted_excerpt
from .common.models import PageInput, RawFinding
from .common.text_utils import extract_visible_text, normalize_text


MAX_TEXT_LENGTH = 1_000_000
SUPPORTED_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
}


def _is_excluded(text_before: str, value: str, rule: dict[str, Any]) -> bool:
    excluded = {str(item).lower() for item in rule.get("exclude_values", [])}
    if value.lower() in excluded:
        return True
    context = text_before[-80:]
    return any(
        re.search(pattern, context, flags=re.IGNORECASE)
        for pattern in rule.get("exclude_context_regex", [])
    )


def _html_sources(source: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(source, "html.parser")
    visible = normalize_text(extract_visible_text(source))
    comments = normalize_text(" ".join(str(item) for item in soup.find_all(string=lambda value: isinstance(value, Comment))))
    inline_scripts = normalize_text(" ".join(
        script.get_text(" ", strip=True) for script in soup.find_all("script") if not script.get("src")
    ))
    return [
        ("visible_text", visible),
        ("html_comment", comments),
        ("inline_script", inline_scripts),
    ]


def detect_sensitive(
    page: PageInput,
    rules: list[dict[str, Any]],
    *,
    source_kinds: set[str] | None = None,
) -> list[RawFinding]:
    """检测页面中的敏感信息。输出证据必须脱敏。"""

    content_type = page.content_type.lower()
    if content_type.split(";", 1)[0].strip() not in SUPPORTED_CONTENT_TYPES:
        return []

    if len(page.body) > MAX_TEXT_LENGTH:
        raise ValueError("正文超过 1,000,000 字符，不能按完整扫描返回结果")
    if "html" in content_type:
        sources = _html_sources(page.body)
    else:
        kind = "javascript" if "javascript" in content_type else "response_text"
        sources = [(kind, normalize_text(page.body))]
    if source_kinds is not None:
        sources = [item for item in sources if item[0] in source_kinds]
    findings: list[RawFinding] = []
    seen: set[tuple[str, str]] = set()

    for source_kind, text in sources:
        if not text:
            continue
        spans = redaction_spans(text, rules)
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            for start, end, value in iter_rule_matches(text, rule):
                if _is_excluded(text[max(0, start - 80):start], value, rule):
                    continue
                dedupe_key = (rule["id"], value.lower())
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                masked = mask_match(value, rule)
                findings.append(
                    RawFinding(
                        category="sensitive_info",
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        url=mask_url(page.final_url or page.url),
                        title=rule.get("name", rule["id"]),
                        evidence=redacted_excerpt(text, max(0, start - 40), min(len(text), end + 40), spans),
                        description=rule.get("description", "发现疑似敏感信息"),
                        remediation=rule.get("remediation", "请人工确认并按需删除或脱敏。"),
                        metadata={"masked_value": masked, "source_kind": source_kind},
                    )
                )
    return findings
