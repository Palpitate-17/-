from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


def mask_phone(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 7:
        return "*" * len(value)
    return f"{digits[:3]}****{digits[-4:]}"


def mask_email(value: str) -> str:
    if "@" not in value:
        return "***"
    local, domain = value.split("@", 1)
    shown = local[:1] if local else ""
    return f"{shown}***@{domain}"


def mask_token(value: str) -> str:
    # 凭据候选不保留前后缀；短值和长值都使用固定长度掩码。
    return "***"


def mask_value(value: str, strategy: str) -> str:
    handlers = {
        "phone": mask_phone,
        "email": mask_email,
        "token": mask_token,
        "full": lambda item: "***",
    }
    return handlers.get(strategy, mask_token)(value)


DEFAULT_REDACTION_RULES = [
    {"match_type": "regex", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)", "mask": "phone"},
    {"match_type": "regex", "pattern": r"(?i)(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+(?![\w.-])", "mask": "email"},
    {"match_type": "keyword", "keywords": ["api_secret=", "access_token=", "password=", "api_key="], "mask": "full"},
]


def iter_rule_matches(text: str, rule: dict[str, Any]) -> Iterable[tuple[int, int, str]]:
    """赋值关键词支持 key=value 和 JSON key:value；普通关键词匹配字面量。"""
    if rule["match_type"] == "regex":
        for match in re.finditer(rule["pattern"], text):
            if match.end() > match.start():
                yield match.start(), match.end(), match.group(0)
        return
    for keyword in rule.get("keywords", []):
        if keyword.endswith("="):
            key = re.escape(keyword[:-1])
            pattern = (rf'''(?<![\w])(?:["']?{key}["']?)\s*(?:=|:)\s*'''
                       r'''(?:"(?:\\.|[^"\\\n])+"|'(?:\\.|[^'\\\n])+'|[^\s"'<>;,，。{}\[\]]+)''')
        else:
            pattern = re.escape(keyword)
        for match in re.finditer(pattern, text, re.IGNORECASE):
            yield match.start(), match.end(), match.group(0)


def mask_match(value: str, rule: dict[str, Any]) -> str:
    if rule["match_type"] == "keyword" and any(key.endswith("=") for key in rule.get("keywords", [])):
        assignment = re.match(r'''^(.*?\s*[=:]\s*)(.*)$''', value, re.DOTALL)
        if assignment:
            return assignment.group(1) + "***"
    return mask_value(value, str(rule.get("mask", "token")))


def mask_url(url: str) -> str:
    """展示用 URL：去除 userinfo/fragment，遮蔽所有查询值，不改内部比较输入。"""
    try:
        parts = urlsplit(url)
        # 触发非法端口检查，错误 URL 不原样导出。
        _ = parts.port
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = "&".join(
            (part.split("=", 1)[0] + "=***") if "=" in part else "***"
            for part in parts.query.split("&") if part
        )
        return urlunsplit((parts.scheme, netloc, redact_text(parts.path), query, ""))
    except ValueError:
        return "[invalid URL]"


def redaction_spans(text: str, rules: list[dict[str, Any]] | None = None) -> list[tuple[int, int, str]]:
    spans = []
    # 是否告警与是否脱敏分开：排除值、禁用规则的匹配仍须遮蔽。
    for rule in DEFAULT_REDACTION_RULES + (rules or []):
        for start, end, value in iter_rule_matches(text, rule):
            spans.append((start, end, mask_match(value, rule)))
    for match in re.finditer(r'''https?://[^\s<>"']+''', text, re.IGNORECASE):
        spans.append((match.start(), match.end(), mask_url(match.group(0))))
    merged: list[tuple[int, int, str]] = []
    for start, end, replacement in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            previous = merged.pop()
            if (start, end, replacement) == previous:
                merged.append(previous)
            else:
                merged.append((previous[0], max(previous[1], end), "***"))
        else:
            merged.append((start, end, replacement))
    return merged


def redacted_excerpt(text: str, left: int, right: int, spans: list[tuple[int, int, str]]) -> str:
    chunks: list[str] = []
    cursor = left
    for start, end, replacement in spans:
        if end <= left or start >= right:
            continue
        chunks.extend((text[cursor:max(cursor, start)], replacement))
        cursor = min(right, end)
    chunks.append(text[cursor:right])
    return "".join(chunks)


def redact_text(text: str, rules: list[dict[str, Any]] | None = None) -> str:
    return redacted_excerpt(text, 0, len(text), redaction_spans(text, rules))
