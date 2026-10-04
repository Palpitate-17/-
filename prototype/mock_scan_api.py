"""Offline fixture API for testing HengNao's /scan integration.

Run in PowerShell:
    $env:SCAN_API_KEY = "<a-long-random-test-key>"
    python mock_scan_api.py
"""

import json
import os
import re
import sys
from hashlib import sha256
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TEST_TARGET = "https://demo.example.test/"
FIXTURE = Path(__file__).with_name("offline_fixture.json")
SECRET_PATTERN = re.compile(r"\b(api[_-]?key|token|secret)\s*[:=]\s*([A-Za-z0-9._-]{6,})", re.I)


def mock_scan(target_url):
    if target_url.rstrip("/") != TEST_TARGET.rstrip("/"):
        raise ValueError("Only the simulated test target is supported")
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if fixture["target_url"] != TEST_TARGET:
        raise ValueError("Fixture target does not match the test target")
    findings = []
    for page in fixture["pages"]:
        url = page["url"]
        if not url.startswith(TEST_TARGET):
            raise ValueError("Fixture page is outside the test target")
        if page["status"] != 200:
            continue
        body = page["body"]
        match = SECRET_PATTERN.search(body)
        if match:
            findings.append(
                {
                    "category": "sensitive_exposure",
                    "url": url,
                    "evidence_masked": f"{match.group(1)}=[REDACTED] (simulated HTTP 200)",
                    "verification": "pending",
                    "severity": "pending",
                }
            )
        expected = page.get("baseline_sha256")
        actual = sha256(body.encode("utf-8")).hexdigest()
        if expected and expected != actual:
            findings.append(
                {
                    "category": "content_changed",
                    "url": url,
                    "evidence_masked": f"SHA-256 mismatch: expected {expected[:12]}, actual {actual[:12]} (fixture)",
                    "verification": "pending",
                    "severity": "pending",
                }
            )
    return {
        "scan_id": "mock-001",
        "simulated": True,
        "target_url": TEST_TARGET,
        "findings": findings,
    }


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/scan":
            return self.send_json(404, {"error": "Not found"})
        expected_key = os.environ["SCAN_API_KEY"]
        supplied_key = self.headers.get("X-API-Key", "")
        if not compare_digest(supplied_key, expected_key):
            return self.send_json(401, {"error": "Unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Request body must be 1-4096 bytes")
            request = json.loads(self.rfile.read(length))
            result = mock_scan(request.get("target_url", ""))
        except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {"error": str(exc)})
        return self.send_json(200, result)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        result = mock_scan(TEST_TARGET)
        assert result["simulated"] is True
        assert {item["category"] for item in result["findings"]} == {
            "sensitive_exposure", "content_changed"
        }
        assert all(item["verification"] == "pending" for item in result["findings"])
        assert "DEMO-ONLY-12345" not in json.dumps(result)
        assert all("/about" not in item["url"] for item in result["findings"])
        try:
            mock_scan("https://other.example.test/")
        except ValueError:
            pass
        else:
            raise AssertionError("out-of-scope target accepted")
        print("Self-test passed")
    else:
        if not os.environ.get("SCAN_API_KEY"):
            raise SystemExit("Set SCAN_API_KEY before starting the server")
        server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
        print("Mock API listening on http://127.0.0.1:8000/scan", flush=True)
        server.serve_forever()
