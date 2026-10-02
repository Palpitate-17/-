from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.main import Settings, create_app
from test_site.app import app as lab_app, set_phase


def _payload() -> dict:
    return {
        "target_url": "http://test.local/",
        "authorization_confirmed": True,
        "allowed_hosts": ["test.local"],
        "allowed_paths": ["/"],
        "denied_paths": ["/__test__"],
        "max_pages": 20,
        "max_depth": 2,
        "rate_limit_rps": 5,
        "timeout_seconds": 5,
        "lab_mode": True,
        "external_link_blocklist": ["malicious.example.invalid"],
    }


def _client(tmp_path) -> TestClient:
    application = create_app(
        Settings(database_path=tmp_path / "test.db", api_key="demo-api-key", allow_lab_mode=True),
        crawler_transport=httpx.ASGITransport(app=lab_app),
    )
    return TestClient(application, headers={"X-API-Key": "demo-api-key"})


def _scan(client: TestClient) -> tuple[str, dict, list[dict]]:
    accepted = client.post("/api/v1/scans", json=_payload())
    assert accepted.status_code == 202
    body = accepted.json()
    assert body["api_version"] == "1.0"
    scan_id = body["scan_id"]
    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    return scan_id, detail, findings


def test_api_requires_key_and_exposes_versioned_contract(tmp_path):
    application = create_app(
        Settings(database_path=tmp_path / "auth.db", api_key="required-key", allow_lab_mode=True),
        crawler_transport=httpx.ASGITransport(app=lab_app),
    )
    client = TestClient(application)
    assert client.post("/api/v1/scans", json=_payload()).status_code == 401
    openapi = client.get("/openapi.json").json()
    assert openapi["info"]["version"] == "1.0"
    assert "/api/v1/findings/{finding_id}/retest" in openapi["paths"]


def test_failed_scope_is_not_reported_as_empty_success(tmp_path):
    client = _client(tmp_path)
    payload = _payload()
    payload["authorization_confirmed"] = False
    accepted = client.post("/api/v1/scans", json=payload)
    assert accepted.status_code == 202
    detail = client.get(accepted.json()["status_url"]).json()
    assert detail["status"] == "failed"
    assert detail["error"]["code"] == "SCOPE_VALIDATION_FAILED"


def test_api_accepts_validated_custom_sensitive_rule(tmp_path):
    client = _client(tmp_path)
    payload = _payload()
    payload.update({
        "max_pages": 1,
        "max_depth": 0,
        "custom_sensitive_rules": [{
            "id": "CUSTOM_INTERNAL_TITLE",
            "name": "自定义标题词",
            "match_type": "regex",
            "pattern": "授权巡检测试站点",
            "severity": "low",
            "mask": "full"
        }]
    })
    accepted = client.post("/api/v1/scans", json=payload)
    findings = client.get(accepted.json()["findings_url"]).json()["items"]
    custom = next(item for item in findings if item["rule_id"] == "CUSTOM_INTERNAL_TITLE")
    assert custom["metadata"]["masked_value"] == "***"
    assert "授权巡检测试站点" not in custom["evidence_masked"]


def test_full_scan_change_and_retest_closure(tmp_path):
    client = _client(tmp_path)
    set_phase("before")
    try:
        first_id, first_detail, first_findings = _scan(client)
        assert first_detail["status"] == "completed"
        assert first_detail["pages_scanned"] >= 7
        assert any(item["category"] == "sensitive_info" for item in first_findings)
        assert any(item["metadata"].get("source_kind") == "javascript" for item in first_findings)
        assert {item["status"] for item in first_detail["coverage"]} >= {"succeeded", "skipped"}

        set_phase("after")
        second_id, second_detail, second_findings = _scan(client)
        assert second_detail["status"] == "completed"
        assert any(item["category"] == "page_baseline_change" for item in second_findings)
        assert any(item["category"] == "external_link_change" for item in second_findings)
        assert any(
            "local_blocklist" in item["metadata"].get("risk_reasons", [])
            for item in second_findings
        )
        first_phone = next(item for item in first_findings if item["rule_id"] == "SENSITIVE_PHONE_CN")
        second_phone = next(item for item in second_findings if item["fingerprint"] == first_phone["fingerprint"])
        assert second_phone["first_seen"] == first_phone["first_seen"]

        target = next(
            item for item in second_findings
            if item["rule_id"] == "EXTERNAL_LINK_ADDED"
            and "malicious.example.invalid" in item["metadata"].get("added_url", "")
        )
        set_phase("before")
        retest = client.post(f"/api/v1/findings/{target['finding_id']}/retest")
        assert retest.status_code == 200
        assert retest.json()["status"] == "resolved"
        updated = client.get(f"/api/v1/scans/{second_id}/findings").json()["items"]
        assert next(item for item in updated if item["finding_id"] == target["finding_id"])["status"] == "resolved"

        report = client.get(f"/api/v1/scans/{second_id}/report")
        assert report.status_code == 200
        assert report.json()["scan"]["scan_id"] == second_id
    finally:
        set_phase("before")
