from __future__ import annotations

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

    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()
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
                links.add(normalized)
    return sorted(links)


def compare_external_links(
    page: PageInput,
    previous_links: list[str],
    allowed_domains: list[str],
) -> list[RawFinding]:
    current = extract_external_links(page.body, page.final_url or page.url, allowed_domains)
    added = sorted(set(current) - set(previous_links))
    return [
        RawFinding(
            category="external_link_change",
            rule_id="EXTERNAL_LINK_ADDED",
            severity="medium",
            url=mask_url(page.final_url or page.url),
            title="页面新增外部链接",
            evidence=mask_url(link),
            description="当前页面相对已确认基线新增了外部域名资源或链接。",
            remediation="核对该域名、用途和引入时间；确认无误后再更新基线。",
            metadata={"added_url": mask_url(link)},
        )
        for link in added
    ]
