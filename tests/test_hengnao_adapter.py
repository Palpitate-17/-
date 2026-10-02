from __future__ import annotations

import copy

import pytest

from scanner.adapters.hengnao import build_hengnao_response, to_hengnao_finding
from scanner.common.models import RawFinding


def finding(**overrides) -> RawFinding:
    values = {
        "category": "sensitive_info",
        "rule_id": "SENSITIVE_PHONE_CN",
        "severity": "medium",
        "url": "https://fixture.example.invalid/page?token=synthetic-value",
        "title": "中国大陆手机号",
        "evidence": "值班电话：139****5678",
        "description": "页面疑似展示手机号",
        "remediation": "请人工确认并按需脱敏",
        "metadata": {},
    }
    values.update(overrides)
    return RawFinding(**values)


def test_finding_matches_existing_hengnao_five_field_shape():
    exported = to_hengnao_finding(finding())
    assert exported == {
        "category": "sensitive_exposure",
        "url": "https://fixture.example.invalid/page?token=***",
        "evidence_masked": "值班电话：139****5678",
        "verification": "pending",
        "severity": "medium",
    }


def test_category_mapping_for_all_current_detectors():
    assert to_hengnao_finding(finding(category="page_baseline_change"))["category"] == "integrity_change"
    assert to_hengnao_finding(finding(category="external_link_change"))["category"] == "external_link_change"
    assert to_hengnao_finding(finding(category="future_category"))["category"] == "future_category"


def test_response_matches_mock_top_level_and_supports_empty_findings():
    response = build_hengnao_response(
        "scan-test-001",
        "https://fixture.example.invalid/clean?session=synthetic-session",
        [],
        simulated=True,
    )
    assert response == {
        "scan_id": "scan-test-001",
        "simulated": True,
        "target_url": "https://fixture.example.invalid/clean?session=***",
        "findings": [],
    }


def test_adapter_does_not_mutate_internal_finding():
    original = finding()
    snapshot = copy.deepcopy(original)
    build_hengnao_response("scan-test-002", original.url, [original], simulated=True)
    assert original == snapshot


def test_adapter_defensively_redacts_unexpected_raw_evidence():
    exported = to_hengnao_finding(finding(evidence="误传电话：13912345678"))
    assert "13912345678" not in exported["evidence_masked"]
    assert "139****5678" in exported["evidence_masked"]


@pytest.mark.parametrize(
    ("scan_id", "target_url", "simulated", "exception"),
    [
        ("", "https://fixture.example.invalid/", True, ValueError),
        ("scan-test", "", True, ValueError),
        ("scan-test", "https://fixture.example.invalid/", "true", TypeError),
    ],
)
def test_invalid_wrapper_arguments_are_rejected(scan_id, target_url, simulated, exception):
    with pytest.raises(exception):
        build_hengnao_response(scan_id, target_url, [], simulated=simulated)
