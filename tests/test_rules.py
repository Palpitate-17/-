import pytest

from scanner.rules import RuleConfigError, load_rules
from scanner.sensitive import detect_sensitive


@pytest.mark.parametrize("body", [
    "[]", "rules: not-a-list", "rules: [{id: a, match_type: keyword, severity: low, keywords: scalar}]",
    "rules: [{id: a, match_type: regex, severity: low, pattern: '[bad'}]",
    "rules: [{id: a, match_type: regex, severity: low, pattern: x, exclude_context_regex: ['[bad']}]",
    "rules: [{id: a, match_type: regex, severity: low, pattern: x, enabled: 'false'}]",
    "rules: [{id: a, match_type: regex, severity: low, pattern: x, mask: unknown}]",
])
def test_invalid_rule_files_fail_at_load(tmp_path, body):
    path = tmp_path / "rules.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(RuleConfigError):
        load_rules(path)


def test_internal_keyword_can_be_configured_without_new_shared_schema(tmp_path, page_factory):
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n- id: INTERNAL_PROJECT_KEYWORD\n  match_type: keyword\n  severity: medium\n  keywords: ['合成内部代号甲']\n  mask: full\n", encoding="utf-8")
    rules = load_rules(path)
    result = detect_sensitive(page_factory("内部事项：合成内部代号甲"), rules)
    assert len(result) == 1
    assert "合成内部代号甲" not in result[0].evidence
    assert detect_sensitive(page_factory("公开业务介绍"), rules) == []
