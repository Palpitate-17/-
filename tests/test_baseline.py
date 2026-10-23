from scanner.baseline import build_baseline, compare_baseline


def test_detects_title_text_and_script_changes(page_factory):
    before = page_factory("<html><head><title>主页</title></head><body>正常正文</body></html>")
    after = page_factory(
        "<html><head><title>维护页</title>"
        '<script src="https://unknown.example.invalid/demo.js"></script>'
        "</head><body>维护正文</body></html>"
    )
    baseline = build_baseline(before, ["test.local"])
    rule_ids = {item.rule_id for item in compare_baseline(after, baseline, ["test.local"])}
    assert {
        "BASELINE_TITLE_CHANGED",
        "BASELINE_TEXT_CHANGED",
        "BASELINE_SCRIPT_ADDED",
    } <= rule_ids


def test_ignores_marked_dynamic_region(page_factory):
    before = page_factory('<html><body><h1>不变</h1><p data-ignore="dynamic">10:00</p></body></html>')
    after = page_factory('<html><body><h1>不变</h1><p data-ignore="dynamic">10:01</p></body></html>')
    baseline = build_baseline(before, ["test.local"])
    assert compare_baseline(after, baseline, ["test.local"]) == []


def test_detects_dom_inline_script_form_iframe_and_removed_script(page_factory):
    before = page_factory(
        '<html><body><script src="/old.js"></script><form action="/submit"></form></body></html>'
    )
    after = page_factory(
        '<html><body><section></section><script>const mode="changed";</script>'
        '<form action="https://outside.invalid/collect"></form>'
        '<iframe src="https://outside.invalid/frame"></iframe></body></html>'
    )
    baseline = build_baseline(before, ["test.local"])
    rule_ids = {item.rule_id for item in compare_baseline(after, baseline, ["test.local"])}
    assert {
        "BASELINE_DOM_CHANGED",
        "BASELINE_SCRIPT_REMOVED",
        "BASELINE_INLINE_SCRIPT_CHANGED",
        "BASELINE_FORM_ACTION_CHANGED",
        "BASELINE_IFRAME_CHANGED",
    } <= rule_ids


def test_supports_trusted_css_ignore_selector(page_factory):
    before = page_factory('<html><body><span class="clock">10:00</span><p>固定</p></body></html>')
    after = page_factory('<html><body><span class="clock">10:01</span><p>固定</p></body></html>')
    baseline = build_baseline(before, ["test.local"], ignore_selectors=[".clock"])
    assert compare_baseline(after, baseline, ["test.local"], ignore_selectors=[".clock"]) == []
