from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse


BASE_DIR = Path(__file__).resolve().parent
PAGES_DIR = BASE_DIR / "pages"
STATE_FILE = BASE_DIR / "state.json"

app = FastAPI(title="授权安全巡检测试站点", version="1.0.0")


def read_page(name: str) -> str:
    return (PAGES_DIR / name).read_text(encoding="utf-8")


def current_phase() -> str:
    return json.loads(STATE_FILE.read_text(encoding="utf-8")).get("phase", "before")


def set_phase(phase: str) -> None:
    if phase not in {"before", "after"}:
        raise ValueError("phase 必须是 before 或 after")
    STATE_FILE.write_text(
        json.dumps({"phase": phase}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": current_phase()}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return read_page("normal.html")


@app.get("/sensitive/leak", response_class=HTMLResponse)
def sensitive_leak() -> str:
    return read_page("sensitive_leak.html")


@app.get("/sensitive/placeholder", response_class=HTMLResponse)
def sensitive_placeholder() -> str:
    return read_page("sensitive_placeholder.html")


@app.get("/baseline/home", response_class=HTMLResponse)
def baseline_home() -> str:
    return read_page(f"baseline_{current_phase()}.html")


@app.get("/external/page", response_class=HTMLResponse)
def external_page() -> str:
    return read_page(f"external_{current_phase()}.html")


@app.get("/dynamic", response_class=HTMLResponse)
def dynamic_page() -> str:
    now = datetime.now(timezone.utc).isoformat()
    return read_page("dynamic.html").replace("{{NOW}}", now)


@app.get("/assets/app.js")
def demo_javascript() -> Response:
    return Response(read_page("app.js"), media_type="application/javascript")


@app.get("/data/config.json")
def demo_json() -> dict[str, str]:
    return {"environment": "demo", "access_token": "synthetic-json-token-987654"}


@app.post("/__test__/phase/{phase}")
def switch_phase(phase: str) -> dict[str, str]:
    """仅供本地授权靶场演示状态切换，不应部署为生产目标站点。"""
    try:
        set_phase(phase)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"phase": current_phase()}


@app.get("/redirect-external")
def redirect_external() -> RedirectResponse:
    return RedirectResponse("https://outside.example.invalid/should-not-be-requested", status_code=302)


@app.get("/weak/missing-headers", response_class=HTMLResponse)
def missing_headers() -> str:
    return "<html><title>缺少安全响应头</title><body>测试页</body></html>"


@app.get("/weak/secure", response_class=HTMLResponse)
def secure_headers(response: Response) -> str:
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return "<html><title>安全响应头齐全</title><body>测试页</body></html>"


@app.get("/weak/insecure-cookie", response_class=HTMLResponse)
def insecure_cookie(response: Response) -> str:
    response.set_cookie("demo_session", "not-a-real-session")
    return "<html><title>Cookie 缺少安全属性</title><body>测试页</body></html>"


@app.get("/weak/secure-cookie", response_class=HTMLResponse)
def secure_cookie(response: Response) -> str:
    response.set_cookie(
        "demo_session",
        "not-a-real-session",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    return "<html><title>Cookie 安全属性齐全</title><body>测试页</body></html>"
