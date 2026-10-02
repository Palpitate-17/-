from __future__ import annotations

from pathlib import Path

import pytest

from scanner.common.models import PageInput
from scanner.rules import load_rules


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rules():
    return load_rules(ROOT / "scanner" / "rules" / "sensitive_rules.yaml")


@pytest.fixture
def page_factory():
    def create(body: str, url: str = "http://test.local/page", status_code: int = 200) -> PageInput:
        return PageInput(
            url=url,
            final_url=url,
            status_code=status_code,
            content_type="text/html; charset=utf-8",
            body=body,
            headers={},
            fetched_at="2026-09-29T00:00:00Z",
        )

    return create
