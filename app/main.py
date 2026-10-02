from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, status

from scanner.common.masking import mask_url

from .contracts import (
    API_VERSION,
    FindingList,
    FindingResponse,
    RetestResponse,
    ScanAccepted,
    ScanDetail,
    ScanRequest,
)
from .service import ScanService
from .store import ScanStore


ROOT = Path(__file__).resolve().parents[1]


@dataclass(slots=True)
class Settings:
    database_path: Path = ROOT / ".runtime" / "hengxun.db"
    api_key: str = ""
    allow_lab_mode: bool = False

    @classmethod
    def from_environment(cls) -> "Settings":
        raw_path = os.getenv("HENGXUN_DATABASE_PATH")
        return cls(
            database_path=Path(raw_path) if raw_path else ROOT / ".runtime" / "hengxun.db",
            api_key=os.getenv("HENGXUN_API_KEY", ""),
            allow_lab_mode=os.getenv("HENGXUN_ALLOW_LAB_MODE", "false").lower() == "true",
        )


def create_app(
    settings: Settings | None = None,
    *,
    crawler_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    settings = settings or Settings.from_environment()
    application = FastAPI(
        title="恒巡网站安全巡检 API",
        version=API_VERSION,
        description="仅用于已获授权目标的非破坏性网站安全巡检。",
    )
    store = ScanStore(settings.database_path)
    service = ScanService(
        store,
        rules_path=ROOT / "scanner" / "rules" / "sensitive_rules.yaml",
        allow_lab_mode=settings.allow_lab_mode,
        crawler_transport=crawler_transport,
    )
    application.state.settings = settings
    application.state.store = store
    application.state.service = service

    def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key 无效")

    auth = Depends(require_api_key)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "api_version": API_VERSION}

    @application.post(
        "/api/v1/scans", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED,
        dependencies=[auth], tags=["scans"],
    )
    async def create_scan_endpoint(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanAccepted:
        scan_id = service.create_scan(request)
        background_tasks.add_task(service.run_scan, scan_id)
        return ScanAccepted(
            scan_id=scan_id,
            status="queued",
            status_url=f"/api/v1/scans/{scan_id}",
            findings_url=f"/api/v1/scans/{scan_id}/findings",
            report_url=f"/api/v1/scans/{scan_id}/report",
        )

    def require_scan(scan_id: str) -> dict:
        record = store.get_scan(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="扫描任务不存在")
        return record

    @application.get(
        "/api/v1/scans/{scan_id}", response_model=ScanDetail,
        dependencies=[auth], tags=["scans"],
    )
    async def get_scan_endpoint(scan_id: str) -> ScanDetail:
        record = require_scan(scan_id)
        error = None
        if record["error_code"]:
            error = {"code": record["error_code"], "message": record["error_message"]}
        return ScanDetail(
            scan_id=scan_id,
            status=record["status"],
            target_url=mask_url(record["target_url"]),
            created_at=record["created_at"],
            started_at=record["started_at"],
            completed_at=record["completed_at"],
            pages_discovered=record["pages_discovered"],
            pages_scanned=record["pages_scanned"],
            findings_count=record["findings_count"],
            coverage=record["coverage"],
            error=error,
        )

    @application.get(
        "/api/v1/scans/{scan_id}/findings", response_model=FindingList,
        dependencies=[auth], tags=["findings"],
    )
    async def get_findings_endpoint(scan_id: str) -> FindingList:
        record = require_scan(scan_id)
        return FindingList(
            scan_id=scan_id,
            scan_status=record["status"],
            items=[FindingResponse.model_validate(item) for item in store.get_findings(scan_id)],
        )

    @application.post(
        "/api/v1/findings/{finding_id}/retest", response_model=RetestResponse,
        dependencies=[auth], tags=["findings"],
    )
    async def retest_endpoint(finding_id: str) -> RetestResponse:
        finding = store.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="发现不存在")
        result = await service.retest_finding(finding_id)
        return RetestResponse(finding_id=finding_id, **result)

    @application.get(
        "/api/v1/scans/{scan_id}/report", dependencies=[auth], tags=["reports"],
    )
    async def report_endpoint(scan_id: str) -> dict:
        record = require_scan(scan_id)
        return {
            "api_version": API_VERSION,
            "scan": (await get_scan_endpoint(scan_id)).model_dump(mode="json"),
            "findings": store.get_findings(scan_id),
            "notice": "所有发现均需人工复核；未执行或失败的模块见 coverage。",
        }

    return application


app = create_app()
