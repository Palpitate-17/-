"""Run the team's offline detectors on pages already fetched by local_scan.

This module never fetches a URL. The PR policy remains the only authority for
which pages may be requested. All detector output is treated as unverified.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.advanced_sensitive import detect_encoded_secret_candidates
from scanner.baseline import build_baseline, compare_baseline
from scanner.common.masking import mask_url, redact_text
from scanner.common.models import BaselineRecord, PageInput, RawFinding
from scanner.external_links import compare_external_links, detect_external_link_risks
from scanner.rules import load_rules
from scanner.sensitive import detect_sensitive
from scanner.weak_configuration import detect_weak_configuration


VERSION = "team-passive-0.1"
MODULES = frozenset({"sensitive", "encoded_secret", "baseline", "external_links", "weak_configuration"})
RULES_PATH = ROOT / "scanner" / "rules" / "sensitive_rules.yaml"


def load_team_rules() -> list[dict]:
    return load_rules(RULES_PATH)


def _serialize(finding: RawFinding, module: str) -> dict:
    # A detector match is a candidate, not proof of a vulnerability or a real secret.
    evidence = ("页面标题与首次观测基线不同"
                if finding.rule_id == "BASELINE_TITLE_CHANGED" else redact_text(finding.evidence))
    return {
        "category": finding.category,
        "rule_id": finding.rule_id,
        "source_module": module,
        "url": mask_url(finding.url),
        "title": finding.title,
        "evidence_masked": evidence,
        "description": ("当前页面与首次观测基线不同；基线尚未经业务方审批。"
                        if module == "baseline" else finding.description),
        "verification": "pending",
        "severity": "pending",
        "priority_hint": finding.severity,
        "potential_impact": "规则命中仍需结合授权范围、业务语境和原始证据人工核实。",
        "remediation_if_confirmed": finding.remediation,
    }


def analyze_page(
    *, url: str, status: int, content_type: str, body: str,
    headers: dict[str, str], policy: dict, previous_baseline: dict | None,
    rules: list[dict],
) -> tuple[list[dict], dict | None, list[dict]]:
    """Return safe findings, unchanged first-observation baseline, and coverage."""
    page = PageInput(url=url, final_url=url, status_code=status,
                     content_type=content_type, body=body, headers=headers)
    host = urlsplit(url).hostname or ""
    allowed_domains = [host]
    enabled = policy["team_modules"]
    baseline = BaselineRecord(**previous_baseline) if previous_baseline else None
    next_baseline = previous_baseline
    findings: list[dict] = []
    runs: list[dict] = []

    for module in enabled:
        raw: list[RawFinding] = []
        applicable = True
        reason = None
        try:
            if module == "sensitive":
                raw = detect_sensitive(page, rules) if status == 200 else []
                applicable = status == 200
            elif module == "encoded_secret":
                raw = detect_encoded_secret_candidates(page)
                applicable = status == 200
            elif module == "weak_configuration":
                raw = detect_weak_configuration(page)
                applicable = status == 200
            elif module in {"baseline", "external_links"}:
                applicable = status == 200 and "text/html" in content_type.lower()
                if applicable:
                    if baseline is None:
                        baseline = build_baseline(
                            page, allowed_domains,
                            ignore_selectors=policy["baseline_ignore_selectors"],
                        )
                        next_baseline = baseline.to_dict()
                    elif module == "baseline":
                        raw = compare_baseline(
                            page, baseline, allowed_domains,
                            ignore_selectors=policy["baseline_ignore_selectors"],
                        )
                    if module == "external_links":
                        raw = (compare_external_links(
                            page, baseline.external_links, allowed_domains,
                            blacklist_domains=policy["external_link_blocklist"],
                        ) if previous_baseline else detect_external_link_risks(
                            page, allowed_domains, policy["external_link_blocklist"],
                        ))
                else:
                    reason = "仅检查成功获取的 HTML 页面"
            else:
                raise ValueError(f"Unsupported team module: {module}")
            serialized = [_serialize(item, module) for item in raw]
            findings.extend(serialized)
            runs.append({"module": module, "status": "succeeded" if applicable else "skipped",
                         "checked_items": int(applicable), "findings": len(serialized),
                         "reason": reason, "version": VERSION})
        except (ValueError, TypeError, KeyError) as exc:
            runs.append({"module": module, "status": "failed", "checked_items": 0,
                         "findings": 0, "reason": f"检测器输入或基线错误：{type(exc).__name__}",
                         "version": VERSION})
    return findings, next_baseline, runs
