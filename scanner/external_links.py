from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .common.masking import mask_url
from .common.models import PageInput, RawFinding
from .common.text_utils import normalize_url


URL_ATTRIBUTES = {
    "a": "href",
    "img": "src",
    "script": "src",
    "iframe": "src",
    "link": "href",
    "form": "action",
}


def _allowed(hostname: str, allowed_domains: list[str]) -> bool:
    host = hostname.lower().rstrip(".")
    for domain in allowed_domains:
        allowed = domain.lower().strip().lstrip(".").rstrip(".")
        if not allowed:
            continue
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def extract_external_links(html: str, page_url: str, allowed_domains: list[str]) -> list[str]:
    """只解析链接，不对外链发起网络访问。"""

    return sorted({item["url"] for item in extract_external_link_records(html, page_url, allowed_domains)})


def extract_external_link_records(
    html: str, page_url: str, allowed_domains: list[str]
) -> list[dict[str, str]]:
    """解析外链及其 HTML 来源，不主动访问外部地址。"""

    soup = BeautifulSoup(html, "html.parser")
    records: dict[tuple[str, str, str], dict[str, str]] = {}
    for tag_name, attribute in URL_ATTRIBUTES.items():
        for tag in soup.find_all(tag_name):
            raw = tag.get(attribute)
            if not isinstance(raw, str) or not raw.strip() or raw.strip().startswith("#"):
                continue
            try:
                normalized = normalize_url(raw.strip(), page_url)
                parts = urlsplit(normalized)
                if parts.scheme not in {"http", "https"}:
                    continue
                hostname = parts.hostname or ""
            except ValueError:
                continue
            if hostname and not _allowed(hostname, allowed_domains):
                key = (normalized, tag_name, attribute)
                records[key] = {"url": normalized, "source_tag": tag_name, "attribute": attribute}
    return [records[key] for key in sorted(records)]


def _risk_reasons(url: str, blacklist_domains: list[str]) -> list[str]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    reasons: list[str] = []
    if any(host == item.lower().lstrip(".").rstrip(".") or
           host.endswith(f".{item.lower().lstrip('.').rstrip('.')}")
           for item in blacklist_domains if item.strip()):
        reasons.append("local_blocklist")
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append("punycode_hostname")
    try:
        ipaddress.ip_address(host)
        reasons.append("ip_literal_hostname")
    except ValueError:
        pass
    if parts.username or parts.password:
        reasons.append("embedded_credentials")
    return reasons


def detect_external_link_risks(
    page: PageInput,
    allowed_domains: list[str],
    blacklist_domains: list[str],
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for record in extract_external_link_records(
        page.body, page.final_url or page.url, allowed_domains
    ):
        reasons = _risk_reasons(record["url"], blacklist_domains)
        if not reasons:
            continue
        high_confidence = "local_blocklist" in reasons
        findings.append(
            RawFinding(
                category="external_link_risk",
                rule_id="EXTERNAL_LINK_RISK",
                severity="high" if high_confidence else "medium",
                url=mask_url(page.final_url or page.url),
                title="页面包含高风险特征外链" if high_confidence else "页面包含需复核的外链特征",
                evidence=mask_url(record["url"]),
                description="外链命中本地风险规则；系统没有主动访问该外部地址。",
                remediation="核对外链来源、业务必要性和引入时间；确认恶意后从页面移除并排查发布链路。",
                metadata={
                    "external_url": mask_url(record["url"]),
                    "source_tag": record["source_tag"],
                    "attribute": record["attribute"],
                    "risk_reasons": reasons,
                },
            )
        )
    return findings


def compare_external_links(
    page: PageInput,
    previous_links: list[str],
    allowed_domains: list[str],
    *,
    blacklist_domains: list[str] | None = None,
) -> list[RawFinding]:
    records = extract_external_link_records(
        page.body, page.final_url or page.url, allowed_domains
    )
    current = sorted({item["url"] for item in records})
    record_by_url = {item["url"]: item for item in records}
    added = sorted(set(current) - set(previous_links))
    changes = [
        RawFinding(
            category="external_link_change",
            rule_id="EXTERNAL_LINK_ADDED",
            severity="medium",
            url=mask_url(page.final_url or page.url),
            title="页面新增外部链接",
            evidence=mask_url(link),
            description="当前页面相对已确认基线新增了外部域名资源或链接。",
            remediation="核对该域名、用途和引入时间；确认无误后再更新基线。",
            metadata={
                "added_url": mask_url(link),
                "source_tag": record_by_url[link]["source_tag"],
                "attribute": record_by_url[link]["attribute"],
            },
        )
        for link in added
    ]
    return changes + detect_external_link_risks(
        page, allowed_domains, blacklist_domains or []
    )
