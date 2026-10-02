from __future__ import annotations

from datetime import datetime, timezone

from bs4 import BeautifulSoup

from .common.masking import mask_url, redact_text
from .common.models import BaselineRecord, PageInput, RawFinding
from .common.text_utils import normalize_url, text_hash
from .external_links import extract_external_links


def _title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.title.get_text(" ", strip=True) if soup.title else ""


def _scripts(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    scripts = set()
    for script in soup.find_all("script", src=True):
        try:
            url = normalize_url(str(script["src"]).strip(), page_url)
            if url.lower().startswith(("http://", "https://")):
                scripts.add(url)
        except ValueError:
            continue
    return sorted(scripts)


def build_baseline(page: PageInput, allowed_domains: list[str]) -> BaselineRecord:
    page_url = page.final_url or page.url
    return BaselineRecord(
        url=normalize_url(page_url),
        status_code=page.status_code,
        title=_title(page.body),
        text_hash=text_hash(page.body),
        external_links=extract_external_links(page.body, page_url, allowed_domains),
        scripts=_scripts(page.body, page_url),
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def compare_baseline(
    page: PageInput,
    baseline: BaselineRecord,
    allowed_domains: list[str],
) -> list[RawFinding]:
    current = build_baseline(page, allowed_domains)
    url = mask_url(page.final_url or page.url)
    findings: list[RawFinding] = []

    def add(rule_id: str, title: str, evidence: str, severity: str = "medium") -> None:
        findings.append(
            RawFinding(
                category="page_baseline_change",
                rule_id=rule_id,
                severity=severity,
                url=url,
                title=title,
                evidence=redact_text(evidence),
                description="当前页面状态与已确认基线不一致。",
                remediation="人工核对变化原因；合法发布则审批后更新基线，否则回滚并排查。",
            )
        )

    if current.status_code != baseline.status_code:
        add("BASELINE_STATUS_CHANGED", "HTTP 状态码变化", f"{baseline.status_code} -> {current.status_code}")
    if current.title != baseline.title:
        add("BASELINE_TITLE_CHANGED", "页面标题变化", f"{baseline.title!r} -> {current.title!r}")
    if current.text_hash != baseline.text_hash:
        add("BASELINE_TEXT_CHANGED", "页面正文变化", "归一化正文 SHA-256 与基线不同", "low")
    for script in sorted(set(current.scripts) - set(baseline.scripts)):
        add("BASELINE_SCRIPT_ADDED", "页面新增脚本", mask_url(script), "high")
    return findings
