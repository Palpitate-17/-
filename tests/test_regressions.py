import json

import pytest

from scanner.baseline import build_baseline, compare_baseline
from scanner.external_links import compare_external_links, extract_external_links
from scanner.sensitive import detect_sensitive
from scanner.common.masking import mask_url
from scanner.common.text_utils import normalize_url


def test_every_exported_finding_masks_adjacent_values(page_factory, rules):
    values = ["13912345678", "alice@corp.invalid", "synthetic-secret-123456"]
    page = page_factory("<p>电话：13912345678 邮箱：alice@corp.invalid "
                        "api_secret=synthetic-secret-123456</p>")
    findings = detect_sensitive(page, rules)
    assert len(findings) == 3
    exported = json.dumps([item.to_dict() for item in findings])
    assert all(value not in exported for value in values)


def test_baseline_dynamic_ignore_does_not_suppress_sensitive_scan(page_factory, rules):
    page = page_factory('<p data-ignore="dynamic">值班电话：13912345678</p>')
    assert [item.rule_id for item in detect_sensitive(page, rules)] == ["SENSITIVE_PHONE_CN"]


def test_long_secret_and_excluded_neighbor_are_still_redacted(page_factory, rules):
    secret = "synthetic-" + "x" * 160
    page = page_factory(f"<p>api_secret={secret}; 联系：13800138000</p>")
    exported = json.dumps([item.to_dict() for item in detect_sensitive(page, rules)])
    assert "x" * 16 not in exported
    assert "13800138000" not in exported


def test_json_assignment_and_empty_value(page_factory, rules):
    page = page_factory('{"api_secret": "synthetic-json-secret"}')
    page.content_type = "application/json"
    findings = detect_sensitive(page, rules)
    assert len(findings) == 1
    assert "synthetic-json-secret" not in json.dumps(findings[0].to_dict())
    page.body = '{"api_secret": ""}'
    assert detect_sensitive(page, rules) == []


def test_json_escaped_quotes_do_not_leave_secret_suffix(page_factory, rules):
    value = 'synthetic-"quoted"-secret-suffix'
    page = page_factory(json.dumps({"access_token": value}))
    page.content_type = "application/json"
    findings = detect_sensitive(page, rules)
    assert len(findings) == 1
    assert "secret-suffix" not in json.dumps(findings[0].to_dict())


def test_external_form_and_query_values_are_safe(page_factory):
    page = page_factory('<form action="https://outside.example.invalid/send?token=synthetic-token&amp;x=synthetic-value"></form>',
                        url="http://test.local/page?session=synthetic-session")
    links = extract_external_links(page.body, page.final_url, ["test.local"])
    assert len(links) == 1
    assert "synthetic-token" in links[0]  # 内部比较保留 URL 语义。
    findings = compare_external_links(page, [], ["test.local"])
    exported = json.dumps([item.to_dict() for item in findings])
    assert len(findings) == 1
    for value in ["synthetic-token", "synthetic-value", "synthetic-session"]:
        assert value not in exported


def test_external_links_reject_non_http_and_malformed_urls():
    html = '<a href="JAVASCRIPT:alert(1)">x</a><a href="ftp://outside.invalid/x">x</a>'
    html += '<a href="https://outside.invalid:bad/x">bad</a><a href="https://test.local.evil.invalid/x">x</a>'
    assert extract_external_links(html, "https://test.local", ["test.local"]) == [
        "https://test.local.evil.invalid/x"
    ]


def test_baseline_script_query_is_redacted(page_factory):
    before = page_factory("<title>主页</title>")
    after = page_factory('<title>主页</title><script src="https://outside.invalid/a.js?key=synthetic-key"></script>')
    findings = compare_baseline(after, build_baseline(before, ["test.local"]), ["test.local"])
    assert "synthetic-key" not in json.dumps([item.to_dict() for item in findings])


def test_whitespace_and_restoration_match_approved_baseline(page_factory):
    before = page_factory("<title>主页</title><p>固定 正文</p>")
    baseline = build_baseline(before, ["test.local"])
    whitespace = page_factory("<title>主页</title><p>固定\n   正文</p>")
    assert compare_baseline(whitespace, baseline, ["test.local"]) == []
    assert compare_baseline(before, baseline, ["test.local"]) == []


def test_over_limit_page_does_not_return_partial_success(page_factory, rules):
    with pytest.raises(ValueError, match="完整扫描"):
        detect_sensitive(page_factory("x" * 1_000_001), rules)


def test_url_mask_keeps_query_order_but_removes_all_values_and_userinfo():
    url = "https://user:synthetic-password@[::1]:8443/path?x=synthetic-one&x=synthetic-two#token"
    assert normalize_url(url) == "https://user:synthetic-password@[::1]:8443/path?x=synthetic-one&x=synthetic-two"
    assert mask_url(url) == "https://[::1]:8443/path?x=***&x=***"
