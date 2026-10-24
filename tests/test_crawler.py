from __future__ import annotations

import asyncio

import httpx

from app.contracts import ScanRequest
from app.crawler import WebCrawler
from test_site.app import app as lab_app, set_phase


def test_real_crawler_discovers_and_fetches_lab_pages():
    set_phase("before")
    request = ScanRequest(
        target_url="http://test.local/",
        authorization_confirmed=True,
        allowed_hosts=["test.local"],
        max_pages=20,
        max_depth=2,
        rate_limit_rps=5,
        lab_mode=True,
    )
    crawler = WebCrawler(
        request,
        allow_lab_mode=True,
        transport=httpx.ASGITransport(app=lab_app),
    )
    result = asyncio.run(crawler.crawl())
    fetched = {page.final_url for page in result.pages}
    assert "http://test.local/" in fetched
    assert "http://test.local/sensitive/leak" in fetched
    assert "http://test.local/assets/app.js" in fetched
    assert "http://test.local/data/config.json" in fetched
    assert not result.errors


def test_crawler_never_fetches_external_link():
    set_phase("after")
    try:
        request = ScanRequest(
            target_url="http://test.local/external/page",
            authorization_confirmed=True,
            allowed_hosts=["test.local"],
            max_pages=10,
            max_depth=2,
            rate_limit_rps=5,
            lab_mode=True,
        )
        result = asyncio.run(WebCrawler(
            request,
            allow_lab_mode=True,
            transport=httpx.ASGITransport(app=lab_app),
        ).crawl())
        assert all("example.invalid" not in page.final_url for page in result.pages)
        assert {page.final_url for page in result.pages} == {
            "http://test.local/external/page", "http://test.local/about"
        }
    finally:
        set_phase("before")


def test_crawler_stops_at_out_of_scope_redirect():
    request = ScanRequest(
        target_url="http://test.local/redirect-external",
        authorization_confirmed=True,
        allowed_hosts=["test.local"],
        max_pages=2,
        max_depth=0,
        rate_limit_rps=5,
        lab_mode=True,
    )
    result = asyncio.run(WebCrawler(
        request,
        allow_lab_mode=True,
        transport=httpx.ASGITransport(app=lab_app),
    ).crawl())
    assert result.pages == []
    assert "重定向目标超出授权范围" in result.errors[0]["error"]
