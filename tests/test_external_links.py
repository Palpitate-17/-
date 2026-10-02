from scanner.external_links import compare_external_links, extract_external_links


def test_extracts_only_external_links(page_factory):
    html = """
    <a href="/inside">站内</a>
    <img src="https://cdn.test.local/logo.png">
    <a href="https://partner.example.invalid/path#top">外部</a>
    """
    links = extract_external_links(html, "http://test.local/page", ["test.local"])
    assert links == ["https://partner.example.invalid/path"]


def test_reports_only_new_external_links(page_factory):
    previous = ["https://old.example.invalid/docs"]
    page = page_factory(
        '<a href="https://old.example.invalid/docs">旧</a>'
        '<script src="https://new.example.invalid/app.js"></script>'
    )
    findings = compare_external_links(page, previous, ["test.local"])
    assert [item.metadata["added_url"] for item in findings] == [
        "https://new.example.invalid/app.js"
    ]
