from __future__ import annotations

import base64
import binascii
import re

from bs4 import BeautifulSoup, Comment

from .common.masking import mask_url
from .common.models import PageInput, RawFinding
from .sensitive import MAX_TEXT_LENGTH


# Only an explicitly named encoded secret field is decoded. Arbitrary base64 in a page
# is not evidence of a credential and would produce many false positives.
ENCODED_SECRET = re.compile(
    r'''(?<![\w])['"]?(?P<key>(?:api_?secret|access_?token|client_?secret|api_?key|password|pwd)'''
    r'''(?:_b64|_base64))['"]?\s*(?:=|:)\s*(?P<quote>['"])(?P<value>[A-Za-z0-9+/_=-]{16,512})(?P=quote)''',
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(r"demo|example|fake|test|synthetic|placeholder|changeme|dummy", re.IGNORECASE)
SUPPORTED_MEDIA_TYPES = {
    "text/html", "application/javascript", "text/javascript", "application/x-javascript",
    "application/json", "text/plain",
}


def _code_sources(page: PageInput) -> list[tuple[str, str]]:
    media_type = page.content_type.lower().split(";", 1)[0].strip()
    if media_type == "text/html":
        soup = BeautifulSoup(page.body, "html.parser")
        scripts = "\n".join(
            script.get_text(" ", strip=True)
            for script in soup.find_all("script") if not script.get("src")
        )
        comments = "\n".join(
            str(item) for item in soup.find_all(string=lambda item: isinstance(item, Comment))
        )
        return [("inline_script", scripts), ("html_comment", comments)]
    if "javascript" in media_type:
        return [("javascript", page.body)]
    return [("response_text", page.body)]


def _decoded_candidate(value: str) -> bool:
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeError, ValueError):
        return False
    return (
        12 <= len(decoded) <= 256
        and all(32 <= ord(char) <= 126 for char in decoded)
        and len(set(decoded)) >= 8
        and not PLACEHOLDER.search(decoded)
    )


def detect_encoded_secret_candidates(page: PageInput) -> list[RawFinding]:
    """Find named Base64 credential candidates in authorized text responses.

    This does not prove that a credential is real, active, or improperly published.
    Neither the encoded nor decoded value is returned in findings or metadata.
    """
    media_type = page.content_type.lower().split(";", 1)[0].strip()
    if not 200 <= page.status_code < 300 or media_type not in SUPPORTED_MEDIA_TYPES:
        return []
    if len(page.body) > MAX_TEXT_LENGTH:
        raise ValueError("正文超过 1,000,000 字符，不能按完整扫描返回结果")

    findings: list[RawFinding] = []
    seen: set[tuple[str, str]] = set()
    for source_kind, text in _code_sources(page):
        for match in ENCODED_SECRET.finditer(text):
            key = match.group("key").lower()
            if not _decoded_candidate(match.group("value")):
                continue
            if (source_kind, key) in seen:
                continue
            seen.add((source_kind, key))
            findings.append(RawFinding(
                category="sensitive_info",
                rule_id="SENSITIVE_ENCODED_SECRET_B64",
                severity="high",
                url=mask_url(page.final_url or page.url),
                title="编码凭据候选",
                evidence=f"{key}=***（Base64 解码后为非占位的可打印文本）",
                description="代码或文本资源中出现显式标注为 Base64 的凭据字段；尚未验证其真实性或公开授权。",
                remediation="核实该值是否为有效凭据；若确认为误发布，撤下资源并轮换凭据。",
                metadata={"source_kind": source_kind, "encoding": "base64", "field_name": key},
            ))
    return findings
