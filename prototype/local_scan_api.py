"""Authenticated local-demo API for HengNao; scans only this machine's test site."""

import json
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from local_scan import html_report, scan

ROOT = Path(__file__).resolve().parents[1]
KEY_FILE = ROOT / ".local-api-key"
TARGET_URL = "http://127.0.0.1:8765/"
BASELINE = ROOT / ".demo-baseline.json"
RESULT = ROOT / "demo-result.json"
REPORT = ROOT / "demo-report.html"
API_KEY = ""


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/scan":
            return self.send_json(404, {"error": "Not found"})
        if not compare_digest(self.headers.get("X-API-Key", ""), API_KEY):
            return self.send_json(401, {"error": "Unauthorized"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError("Request body must be 1-4096 bytes")
            request = json.loads(self.rfile.read(size))
            if not isinstance(request, dict) or request.get("target_url") != TARGET_URL:
                raise ValueError(f"Only {TARGET_URL} is allowed")
            result = scan(TARGET_URL, BASELINE)
            RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            REPORT.write_text(html_report(result), encoding="utf-8")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {"error": str(exc)})
        except OSError:
            return self.send_json(503, {"error": "Local demo site unavailable"})
        return self.send_json(200, result)


if __name__ == "__main__":
    if not KEY_FILE.exists():
        raise SystemExit("Create .local-api-key before starting; see docs/hengnao-local-api.md")
    API_KEY = KEY_FILE.read_text(encoding="utf-8").strip()
    if len(API_KEY) < 32:
        raise SystemExit(".local-api-key must contain at least 32 characters")
    server = HTTPServer(("127.0.0.1", 8001), Handler)
    print("Local demo API listening on http://127.0.0.1:8001/scan", flush=True)
    server.serve_forever()
