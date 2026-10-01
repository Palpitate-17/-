"""Local-only mock API for testing HengNao's /scan integration.

Run in PowerShell:
    $env:SCAN_API_KEY = "<a-long-random-test-key>"
    python mock_scan_api.py
"""

import json
import os
import sys
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEST_TARGET = "https://demo.example.test/"


def mock_scan(target_url):
    if target_url.rstrip("/") != TEST_TARGET.rstrip("/"):
        raise ValueError("Only the simulated test target is supported")
    return {
        "scan_id": "mock-001",
        "simulated": True,
        "target_url": TEST_TARGET,
        "findings": [
            {
                "category": "sensitive_exposure",
                "url": TEST_TARGET + "public/config.txt",
                "evidence_masked": "api_key=DEMO-****",
                "verification": "pending",
                "severity": "pending",
            }
        ],
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
        assert mock_scan(TEST_TARGET)["simulated"] is True
        assert mock_scan(TEST_TARGET)["findings"][0]["verification"] == "pending"
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
