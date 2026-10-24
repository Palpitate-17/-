from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


API_VERSION = "1.0"
DETECTOR_VERSION = "0.3.0"


class StrictModel(BaseModel):
    model_config = {"extra": "forbid"}


class ScanStatus(str, Enum):
    queued = "queued"
    validating = "validating"
    crawling = "crawling"
    scanning = "scanning"
    analyzing = "analyzing"
    reporting = "reporting"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class RunStatus(str, Enum):
    succeeded = "succeeded"
    skipped = "skipped"
    failed = "failed"
    inconclusive = "inconclusive"


class CustomSensitiveRule(StrictModel):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=120)
    match_type: Literal["regex", "keyword"]
    pattern: str | None = Field(default=None, max_length=500)
    keywords: list[str] = Field(default_factory=list, max_length=50)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    mask: Literal["phone", "email", "token", "full"] = "full"
    exclude_values: list[str] = Field(default_factory=list, max_length=50)
    exclude_context_regex: list[str] = Field(default_factory=list, max_length=20)
    enabled: bool = True
    description: str = Field(default="发现用户自定义敏感信息", max_length=300)
    remediation: str = Field(default="请人工确认并按需删除或脱敏。", max_length=300)


class ScanRequest(StrictModel):
    target_url: HttpUrl
    authorization_confirmed: bool
    allowed_hosts: list[str] = Field(default_factory=list, max_length=20)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"], max_length=30)
    denied_paths: list[str] = Field(default_factory=list, max_length=30)
    max_pages: int = Field(default=30, ge=1, le=300)
    max_depth: int = Field(default=2, ge=0, le=5)
    rate_limit_rps: float = Field(default=2.0, ge=0.2, le=5.0)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    max_response_bytes: int = Field(default=1_000_000, ge=10_000, le=5_000_000)
    lab_mode: bool = False
    sensitive_file_extensions: list[str] = Field(
        default_factory=lambda: [".html", ".htm", ".js", ".json", ".txt"],
        max_length=20,
    )
    custom_sensitive_rules: list[CustomSensitiveRule] = Field(default_factory=list, max_length=50)
    baseline_ignore_selectors: list[str] = Field(
        default_factory=lambda: ['[data-ignore="dynamic"]'], max_length=30
    )
    external_link_blocklist: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            host = value.strip().lower().lstrip(".").rstrip(".")
            if not host or "/" in host or "://" in host:
                raise ValueError("allowed_hosts 只能填写主机名")
            if host not in normalized:
                normalized.append(host)
        return normalized

    @field_validator("allowed_paths", "denied_paths")
    @classmethod
    def normalize_paths(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            path = value.strip()
            if not path.startswith("/") or ".." in path:
                raise ValueError("路径必须以 / 开头且不能包含 ..")
            if path not in normalized:
                normalized.append(path)
        return normalized

    @field_validator("sensitive_file_extensions")
    @classmethod
    def normalize_extensions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            extension = value.strip().lower()
            if not extension.startswith(".") or not extension[1:].isalnum():
                raise ValueError("文件扩展名格式应类似 .js")
            if extension not in normalized:
                normalized.append(extension)
        return normalized


class ScanAccepted(StrictModel):
    api_version: str = API_VERSION
    scan_id: str
    status: ScanStatus
    status_url: str
    findings_url: str
    report_url: str


class CoverageItem(StrictModel):
    module: str
    status: RunStatus
    checked_items: int = 0
    findings: int = 0
    duration_ms: float = 0.0
    reason: str | None = None
    version: str = DETECTOR_VERSION


class FindingResponse(StrictModel):
    finding_id: str
    scan_id: str
    fingerprint: str
    category: str
    rule_id: str
    severity: str
    confidence: Literal["low", "medium", "high"] = "medium"
    url: str
    title: str
    evidence_masked: str
    description: str
    impact: str
    remediation: str
    verification: Literal["pending", "verified", "rejected"] = "pending"
    status: Literal["open", "resolved", "false_positive", "accepted_risk"] = "open"
    detector: str
    detector_version: str = DETECTOR_VERSION
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanDetail(StrictModel):
    api_version: str = API_VERSION
    scan_id: str
    simulated: bool = False
    status: ScanStatus
    target_url: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    pages_discovered: int = 0
    pages_scanned: int = 0
    findings_count: int = 0
    coverage: list[CoverageItem] = Field(default_factory=list)
    error: dict[str, str] | None = None


class FindingList(StrictModel):
    api_version: str = API_VERSION
    scan_id: str
    scan_status: ScanStatus
    items: list[FindingResponse]


class RetestResponse(StrictModel):
    api_version: str = API_VERSION
    finding_id: str
    previous_status: str
    status: str
    checked_at: datetime
    reason: str
