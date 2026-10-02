from scanner.sensitive import detect_sensitive


def test_detects_and_masks_phone(page_factory, rules):
    page = page_factory("<html><body>值班电话：13912345678</body></html>")
    findings = detect_sensitive(page, rules)
    phone = next(item for item in findings if item.rule_id == "SENSITIVE_PHONE_CN")
    assert "13912345678" not in phone.evidence
    assert "139****5678" in phone.evidence


def test_placeholder_values_are_excluded(page_factory, rules):
    page = page_factory(
        "<html><body>测试示例手机号：13800138000；"
        "占位邮箱：security@example.invalid；"
        "占位示例 access_token=placeholder。</body></html>"
    )
    assert detect_sensitive(page, rules) == []


def test_detects_inline_script_content(page_factory, rules):
    page = page_factory("<html><script>const password='synthetic-js-secret'</script><body>普通正文</body></html>")
    findings = detect_sensitive(page, rules)
    assert [item.metadata["source_kind"] for item in findings] == ["inline_script"]
    assert "synthetic-js-secret" not in findings[0].evidence


def test_detects_html_comment_and_javascript_response(page_factory, rules):
    comment = page_factory("<html><!-- access_token=synthetic-comment-token --><body>普通正文</body></html>")
    assert [item.metadata["source_kind"] for item in detect_sensitive(comment, rules)] == ["html_comment"]
    script = page_factory("const api_secret = 'synthetic-file-secret';")
    script.content_type = "application/javascript"
    assert [item.metadata["source_kind"] for item in detect_sensitive(script, rules)] == ["javascript"]
