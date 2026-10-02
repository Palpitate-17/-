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


def test_ignores_script_content(page_factory, rules):
    page = page_factory("<html><script>const x='13912345678'</script><body>普通正文</body></html>")
    assert detect_sensitive(page, rules) == []
