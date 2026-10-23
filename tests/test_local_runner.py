import json

import pytest

from tests.run_local_evaluation import ROOT, run_local


def test_runner_rejects_missing_or_duplicate_cases():
    truth = {"cases": [{"case_id": "one"}]}
    with pytest.raises(ValueError, match="覆盖"):
        run_local(truth, {"scenarios": []})


def test_unexpected_rule_is_preserved_and_failed_run_is_recorded():
    case = {"case_id": "one", "url": "/fixture", "phase": "none", "category": "sensitive_info",
            "rule_id": "SENSITIVE_EMAIL", "positive": False, "expected_count": 0}
    manifest = {"scenarios": [{"id": "fixture", "case_ids": ["one"], "module": "sensitive",
                               "page": {"body": "值班电话：13912345678"}}]}
    output = run_local({"base_url": "http://fixture.invalid", "cases": [case]}, manifest)
    assert output["findings"][0]["rule_id"] == "SENSITIVE_PHONE_CN"
    manifest["scenarios"][0]["page"] = {"file": "tests/fixtures/missing.html"}
    output = run_local({"base_url": "http://fixture.invalid", "cases": [case]}, manifest)
    assert output["findings"] == []
    assert output["case_runs"][0]["status"] == "failed"


def test_manifest_uses_real_detectors_and_records_weak_config_skips():
    truth = json.loads((ROOT / "tests/ground_truth.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "tests/fixtures/local_cases.json").read_text(encoding="utf-8"))
    output = run_local(truth, manifest)
    assert len(output["case_runs"]) == len(truth["cases"])
    assert {run["case_id"] for run in output["case_runs"] if run["status"] == "skipped"} == {
        "W-P01", "W-P02", "W-N01", "W-N02"
    }
    assert all(run["status"] != "failed" for run in output["case_runs"])
