import pytest

from tests.evaluate import calculate, parse_findings


def truth():
    return {"base_url": "http://fixture.invalid", "cases": [
        {"case_id": "before-negative", "category": "external_link_change", "rule_id": "EXTERNAL_LINK_ADDED",
         "url": "/page", "phase": "before", "positive": False, "expected_count": 0},
        {"case_id": "after-positive", "category": "external_link_change", "rule_id": "EXTERNAL_LINK_ADDED",
         "url": "/page", "phase": "after", "positive": True, "expected_count": 1},
    ]}


def test_wrong_phase_is_false_positive_and_false_negative():
    result = calculate(truth(), [{"category": "external_link_change", "rule_id": "EXTERNAL_LINK_ADDED",
                                 "url": "/page", "phase": "before"}])
    assert result["summary"]["tp"] == 0
    assert result["summary"]["fp"] == 1
    assert result["summary"]["fn"] == 1


def test_ambiguous_missing_phase_is_rejected():
    with pytest.raises(ValueError, match="phase"):
        calculate(truth(), [{"category": "external_link_change", "rule_id": "EXTERNAL_LINK_ADDED", "url": "/page"}])


def test_array_object_and_invalid_findings():
    assert parse_findings([]) == ([], None)
    assert parse_findings({"findings": [], "case_runs": []}) == ([], [])
    with pytest.raises(ValueError):
        parse_findings({"findings": "not-a-list"})


def test_skipped_positive_is_not_silently_counted_as_executed():
    runs = [{"case_id": "before-negative", "status": "succeeded"},
            {"case_id": "after-positive", "status": "skipped", "reason": "未实现"}]
    result = calculate(truth(), [], runs)
    assert result["summary"]["fn"] == 0
    assert result["coverage"]["succeeded"] == 1
    assert result["coverage"]["skipped"] == 1
    assert result["case_metrics"]["tn"] == 1
    assert result["case_metrics"]["negative_case_fpr"] == 0


def test_no_execution_records_means_unverified_coverage():
    result = calculate(truth(), [])
    assert result["coverage"]["verified"] is False
    assert result["case_metrics"] is None


def test_duplicate_execution_records_are_rejected():
    with pytest.raises(ValueError):
        calculate(truth(), [], [{"case_id": "before-negative", "status": "succeeded"}] * 2)


def test_duplicate_findings_are_counted_as_surplus_and_negative_case_fp():
    finding = {"case_id": "before-negative", "category": "external_link_change",
               "rule_id": "EXTERNAL_LINK_ADDED", "url": "/page", "phase": "before"}
    result = calculate(truth(), [finding, finding], [
        {"case_id": "before-negative", "status": "succeeded"},
        {"case_id": "after-positive", "status": "failed"},
    ])
    assert result["summary"]["fp"] == 2
    assert result["summary"]["fn"] == 0
    assert result["case_metrics"]["negative_cases_with_fp"] == 1
    assert result["case_metrics"]["negative_case_fpr"] == 1
