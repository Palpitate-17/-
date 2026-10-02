from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class PageInput:
    """lcx 的采集模块交给检测模块的最小页面对象。"""

    url: str
    final_url: str
    status_code: int
    content_type: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    fetched_at: str = ""


@dataclass(slots=True)
class RawFinding:
    """检测模块输出的统一原始发现。"""

    category: str
    rule_id: str
    severity: str
    url: str
    title: str
    evidence: str
    description: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BaselineRecord:
    url: str
    status_code: int
    title: str
    text_hash: str
    external_links: list[str]
    scripts: list[str]
    created_at: str
    dom_hash: str = ""
    inline_script_hashes: list[str] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    meta_refresh: list[str] = field(default_factory=list)
    ignore_selectors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
