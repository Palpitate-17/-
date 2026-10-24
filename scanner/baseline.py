from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .common.masking import mask_url, redact_text
from .common.models import BaselineRecord, PageInput, RawFinding
from .common.text_utils import extract_visible_text, normalize_text, normalize_url
from .external_links import extract_external_links


DEFAULT_IGNORE_SELECTORS = ['[data-ignore="dynamic"]']


def _filtered_soup(html: str, ignore_selectors: list[str]) -> BeautifulSoup:
    soup = BeautifulSoup(html, "html.parser")
    for selector in ignore_selectors:
        try:
            for element in soup.select(selector):
                element.decompose()
        except Exception as exc:
            raise ValueError(f"基线忽略选择器无效：{selector}") from exc
    return soup


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _title(soup: BeautifulSoup) -> str:
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


def _dom_hash(soup: BeautifulSoup) -> str:
    signature: list[dict[str, object]] = []
    for tag in soup.find_all(True):
        attributes = {
            key: sorted(value) if isinstance(value, list) else str(value)
            for key, value in tag.attrs.items()
            if key in {"id", "class", "name", "type", "role"}
        }
        signature.append({"tag": tag.name, "attributes": attributes})
    return _sha256(json.dumps(signature, ensure_ascii=False, sort_keys=True))


def _inline_script_hashes(soup: BeautifulSoup) -> list[str]:
    return sorted({
        _sha256(normalize_text(script.get_text(" ", strip=True)))
        for script in soup.find_all("script")
        if not script.get("src") and normalize_text(script.get_text(" ", strip=True))
    })


def _attribute_urls(soup: BeautifulSoup, tag_name: str, attribute: str, page_url: str) -> list[str]:
    values: set[str] = set()
    for tag in soup.find_all(tag_name):
        raw = tag.get(attribute)
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            normalized = normalize_url(urljoin(page_url, raw.strip()))
        except ValueError:
            continue
        if normalized.lower().startswith(("http://", "https://")):
            values.add(normalized)
    return sorted(values)


def _meta_refresh(soup: BeautifulSoup) -> list[str]:
    values = set()
    for tag in soup.find_all("meta"):
        if str(tag.get("http-equiv", "")).lower() == "refresh" and tag.get("content"):
            values.add(normalize_text(str(tag["content"])))
    return sorted(values)


def build_baseline(
    page: PageInput,
    allowed_domains: list[str],
    *,
    ignore_selectors: list[str] | None = None,
) -> BaselineRecord:
    page_url = page.final_url or page.url
    selectors = list(DEFAULT_IGNORE_SELECTORS if ignore_selectors is None else ignore_selectors)
    soup = _filtered_soup(page.body, selectors)
    visible_text = normalize_text(extract_visible_text(str(soup)))
    return BaselineRecord(
        url=normalize_url(page_url),
        status_code=page.status_code,
        title=_title(soup),
        text_hash=_sha256(visible_text),
        external_links=extract_external_links(str(soup), page_url, allowed_domains),
        scripts=_scripts(str(soup), page_url),
        created_at=datetime.now(timezone.utc).isoformat(),
        dom_hash=_dom_hash(soup),
        inline_script_hashes=_inline_script_hashes(soup),
        forms=_attribute_urls(soup, "form", "action", page_url),
        iframes=_attribute_urls(soup, "iframe", "src", page_url),
        meta_refresh=_meta_refresh(soup),
        ignore_selectors=selectors,
    )


def compare_baseline(
    page: PageInput,
    baseline: BaselineRecord,
    allowed_domains: list[str],
    *,
    ignore_selectors: list[str] | None = None,
) -> list[RawFinding]:
    selectors = baseline.ignore_selectors if ignore_selectors is None else ignore_selectors
    current = build_baseline(page, allowed_domains, ignore_selectors=selectors)
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
    if baseline.dom_hash and current.dom_hash != baseline.dom_hash:
        add("BASELINE_DOM_CHANGED", "页面 DOM 结构变化", "页面标签结构或关键属性与基线不同", "medium")
    for script in sorted(set(current.scripts) - set(baseline.scripts)):
        add("BASELINE_SCRIPT_ADDED", "页面新增脚本", mask_url(script), "high")
    for script in sorted(set(baseline.scripts) - set(current.scripts)):
        add("BASELINE_SCRIPT_REMOVED", "页面脚本被删除", mask_url(script), "medium")
    if current.inline_script_hashes != baseline.inline_script_hashes:
        add("BASELINE_INLINE_SCRIPT_CHANGED", "页面内联脚本变化", "内联脚本摘要与基线不同", "high")
    if current.forms != baseline.forms:
        add("BASELINE_FORM_ACTION_CHANGED", "表单提交地址变化", "表单 action 集合与基线不同", "high")
    if current.iframes != baseline.iframes:
        add("BASELINE_IFRAME_CHANGED", "内嵌页面地址变化", "iframe 地址集合与基线不同", "high")
    if current.meta_refresh != baseline.meta_refresh:
        add("BASELINE_META_REFRESH_CHANGED", "页面跳转配置变化", "meta refresh 配置与基线不同", "high")
    return findings
