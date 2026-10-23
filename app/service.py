from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit

import httpx

from scanner.baseline import build_baseline, compare_baseline
from scanner.common.masking import mask_url, redact_text
from scanner.common.models import BaselineRecord, PageInput, RawFinding
from scanner.external_links import compare_external_links, detect_external_link_risks
from scanner.rules import load_rules, validate_rules
from scanner.sensitive import SUPPORTED_CONTENT_TYPES, detect_sensitive

from .contracts import API_VERSION, DETECTOR_VERSION, ScanRequest
from .crawler import WebCrawler
from .security import ScopeError, validate_request_scope
from .store import ScanStore


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_fingerprint(finding: RawFinding, source_url: str) -> str:
    identity = {
        "url": source_url,
        "category": finding.category,
        "rule_id": finding.rule_id,
        "evidence": finding.evidence,
        "masked_value": finding.metadata.get("masked_value"),
        "added_url": finding.metadata.get("added_url"),
        "external_url": finding.metadata.get("external_url"),
    }
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _impact(finding: RawFinding) -> str:
    impacts = {
        "sensitive_info": "公开页面中的信息可能被未授权人员获取并用于进一步攻击或隐私侵害。",
        "page_baseline_change": "未经确认的页面变化可能影响网站可信性或表明内容完整性异常。",
        "external_link_change": "新增外部资源可能引入供应链、跳转或内容完整性风险。",
    }
    return impacts.get(finding.category, "该发现可能影响网站的安全性或可信性，需结合证据复核。")


class ScanService:
    def __init__(self, store: ScanStore, *, rules_path: str | Path,
                 allow_lab_mode: bool = False,
                 crawler_transport: httpx.AsyncBaseTransport | None = None):
        self.store = store
        self.rules_path = Path(rules_path)
        self.allow_lab_mode = allow_lab_mode
        self.crawler_transport = crawler_transport

    def create_scan(self, request: ScanRequest) -> str:
        scan_id = f"scan_{uuid.uuid4().hex}"
        now = utcnow()
        self.store.create_scan(
            {
                "scan_id": scan_id,
                "api_version": API_VERSION,
                "status": "queued",
                "target_url": str(request.target_url),
                "request": request.model_dump(mode="json"),
                "created_at": now,
            }
        )
        self.store.audit("scan.created", now, scan_id=scan_id,
                         detail={"target_url": mask_url(str(request.target_url))})
        return scan_id

    def _set_status(self, scan_id: str, status: str, **changes: Any) -> None:
        self.store.update_scan(scan_id, status=status, **changes)
        self.store.audit("scan.status_changed", utcnow(), scan_id=scan_id,
                         detail={"status": status})

    def _rules_for(self, request: ScanRequest) -> list[dict[str, Any]]:
        defaults = load_rules(self.rules_path)
        custom = validate_rules([
            item.model_dump(exclude_none=True) for item in request.custom_sensitive_rules
        ])
        default_ids = {item["id"] for item in defaults}
        duplicate = default_ids & {item["id"] for item in custom}
        if duplicate:
            raise ValueError(f"自定义规则 ID 与内置规则重复：{sorted(duplicate)}")
        return defaults + custom

    def _store_raw_finding(self, scan_id: str, finding: RawFinding,
                           source_url: str) -> dict[str, Any]:
        now = utcnow()
        fingerprint = finding_fingerprint(finding, source_url)
        previous = self.store.get_latest_finding_by_fingerprint(fingerprint)
        payload = {
            "finding_id": f"fnd_{uuid.uuid4().hex}",
            "scan_id": scan_id,
            "fingerprint": fingerprint,
            "category": finding.category,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "confidence": "medium",
            "url": mask_url(source_url),
            "title": finding.title,
            "evidence_masked": redact_text(finding.evidence),
            "description": finding.description,
            "impact": _impact(finding),
            "remediation": finding.remediation,
            "verification": "pending",
            "status": "open",
            "detector": finding.category,
            "detector_version": DETECTOR_VERSION,
            "first_seen": previous["first_seen"] if previous else now,
            "last_seen": now,
            "metadata": finding.metadata,
            "_source_url": source_url,
        }
        self.store.save_finding(payload)
        return payload

    def _detect_page(self, page: PageInput, request: ScanRequest,
                     rules: list[dict[str, Any]]) -> tuple[list[RawFinding], dict[str, str]]:
        allowed_hosts = request.allowed_hosts or [urlsplit(str(request.target_url)).hostname or ""]
        findings: list[RawFinding] = []
        states: dict[str, str] = {}
        media_type = page.content_type.lower().split(";", 1)[0].strip()
        if media_type in SUPPORTED_CONTENT_TYPES:
            findings.extend(detect_sensitive(page, rules))
            states["sensitive"] = "succeeded"
        else:
            states["sensitive"] = "skipped"

        baseline_entry = self.store.get_baseline(page.final_url)
        findings.extend(detect_external_link_risks(
            page, allowed_hosts, request.external_link_blocklist
        ))
        if baseline_entry is None:
            record = build_baseline(
                page, allowed_hosts, ignore_selectors=request.baseline_ignore_selectors
            )
            self.store.save_initial_baseline(page.final_url, asdict(record), utcnow())
            states["baseline"] = "succeeded"
            states["external_links"] = "succeeded"
        else:
            baseline = BaselineRecord(**baseline_entry["record"])
            findings.extend(compare_baseline(
                page, baseline, allowed_hosts,
                ignore_selectors=request.baseline_ignore_selectors,
            ))
            findings.extend(compare_external_links(
                page, baseline.external_links, allowed_hosts,
                blacklist_domains=[],
            ))
            states["baseline"] = "succeeded"
            states["external_links"] = "succeeded"
        return findings, states

    async def run_scan(self, scan_id: str) -> None:
        record = self.store.get_scan(scan_id)
        if record is None:
            return
        started = utcnow()
        coverage: list[dict[str, Any]] = []
        try:
            request = ScanRequest.model_validate(record["request"])
            self._set_status(scan_id, "validating", started_at=started)
            await validate_request_scope(request, allow_lab_mode=self.allow_lab_mode)
            rules = self._rules_for(request)

            self._set_status(scan_id, "crawling")
            crawl_started = perf_counter()
            crawl = await WebCrawler(
                request, allow_lab_mode=self.allow_lab_mode,
                transport=self.crawler_transport,
            ).crawl()
            coverage.append({
                "module": "crawler",
                "status": "succeeded" if crawl.pages else "failed",
                "checked_items": len(crawl.discovered_urls),
                "findings": 0,
                "duration_ms": round((perf_counter() - crawl_started) * 1000, 3),
                "reason": None if crawl.pages else "没有成功获取任何页面",
                "version": DETECTOR_VERSION,
            })
            if not crawl.pages:
                raise RuntimeError("没有成功获取任何授权范围内页面")

            self.store.update_scan(
                scan_id, pages_discovered=len(crawl.discovered_urls), pages_scanned=len(crawl.pages)
            )
            self._set_status(scan_id, "scanning")
            counts = {"sensitive": 0, "baseline": 0, "external_links": 0}
            module_findings = {"sensitive": 0, "baseline": 0, "external_links": 0}
            scan_started = perf_counter()
            total_findings = 0
            for page in crawl.pages:
                page_findings, states = self._detect_page(page, request, rules)
                for module, state in states.items():
                    if state == "succeeded":
                        counts[module] += 1
                for finding in page_findings:
                    self._store_raw_finding(scan_id, finding, page.final_url)
                    total_findings += 1
                    if finding.category == "sensitive_info":
                        module_findings["sensitive"] += 1
                    elif finding.category == "page_baseline_change":
                        module_findings["baseline"] += 1
                    elif finding.category == "external_link_change":
                        module_findings["external_links"] += 1
                    elif finding.category == "external_link_risk":
                        module_findings["external_links"] += 1
            elapsed = round((perf_counter() - scan_started) * 1000, 3)
            for module in ("sensitive", "baseline", "external_links"):
                status = "succeeded" if counts[module] else "skipped"
                coverage.append({
                    "module": module,
                    "status": status,
                    "checked_items": counts[module],
                    "findings": module_findings[module],
                    "duration_ms": elapsed,
                    "reason": None if counts[module] else "抓取内容不适用于该检测器",
                    "version": DETECTOR_VERSION,
                })
            coverage.extend([
                {
                    "module": "weak_configuration", "status": "skipped", "checked_items": 0,
                    "findings": 0, "duration_ms": 0.0,
                    "reason": "该检测器由 lcx 模块提供，本次尚未接入", "version": DETECTOR_VERSION,
                },
                {
                    "module": "common_vulnerability", "status": "skipped", "checked_items": 0,
                    "findings": 0, "duration_ms": 0.0,
                    "reason": "安全模板工具尚未接入", "version": DETECTOR_VERSION,
                },
            ])

            self._set_status(scan_id, "analyzing")
            self.store.update_scan(scan_id, findings_count=total_findings, coverage_json=coverage)
            self._set_status(scan_id, "reporting")
            self._set_status(scan_id, "completed", completed_at=utcnow())
        except Exception as exc:
            error_code = "SCOPE_VALIDATION_FAILED" if isinstance(exc, ScopeError) else "SCAN_FAILED"
            self.store.update_scan(
                scan_id,
                status="failed",
                completed_at=utcnow(),
                coverage_json=coverage,
                error_code=error_code,
                error_message=str(exc)[:500],
            )
            self.store.audit("scan.failed", utcnow(), scan_id=scan_id,
                             detail={"error_code": error_code, "message": str(exc)[:500]})

    async def retest_finding(self, finding_id: str) -> dict[str, Any]:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise KeyError(finding_id)
        scan = self.store.get_scan(finding["scan_id"])
        if scan is None:
            raise KeyError(finding["scan_id"])
        request = ScanRequest.model_validate(scan["request"])
        await validate_request_scope(request, allow_lab_mode=self.allow_lab_mode)
        retest_request = request.model_copy(update={
            "target_url": finding["_source_url"], "max_pages": 1, "max_depth": 0
        })
        crawl = await WebCrawler(
            retest_request, allow_lab_mode=self.allow_lab_mode,
            transport=self.crawler_transport,
        ).crawl()
        if not crawl.pages:
            return {"status": finding["status"], "reason": "复测抓取失败，原状态保持不变"}
        current, _ = self._detect_page(crawl.pages[0], retest_request, self._rules_for(request))
        fingerprints = {finding_fingerprint(item, crawl.pages[0].final_url) for item in current}
        new_status = "open" if finding["fingerprint"] in fingerprints else "resolved"
        now = utcnow()
        self.store.update_finding_status(finding_id, new_status, now)
        self.store.audit("finding.retested", now, scan_id=finding["scan_id"], detail={
            "finding_id": finding_id, "previous_status": finding["status"], "status": new_status,
        })
        return {
            "previous_status": finding["status"], "status": new_status,
            "checked_at": now,
            "reason": "同一发现仍存在" if new_status == "open" else "原发现证据已消失",
        }
