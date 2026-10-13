"""Authenticated scan API for explicitly configured local or public targets."""

import argparse
import json
import time
from hashlib import sha256
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from local_scan import load_policy, save_result, scan

ROOT = Path(__file__).resolve().parents[1]
KEY_FILE = ROOT / ".local-api-key"
POLICY = load_policy(ROOT / "scan-policy.json")
BASELINE = ROOT / ".demo-baseline.json"
RESULT = ROOT / "demo-result.json"
REPORT = ROOT / "demo-report.html"
HISTORY = ROOT / "demo-history.jsonl"
API_KEY = ""
ACTIVE_POLICIES = None
LAST_PUBLIC_SCAN = {}


def result_paths(policy):
    if policy["mode"] == "local_demo":
        return BASELINE, RESULT, REPORT, HISTORY
    directory = ROOT / ".live-scans" / sha256(policy["target_url"].encode()).hexdigest()[:16]
    directory.mkdir(parents=True, exist_ok=True)
    return (directory / "baseline.json", directory / "latest.json",
            directory / "latest.html", directory / "history.jsonl")


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
            target_url = request.get("target_url") if isinstance(request, dict) else None
            policies = ACTIVE_POLICIES if ACTIVE_POLICIES is not None else [POLICY]
            policy = next((p for p in policies if target_url == p["target_url"]), None)
            if policy is None:
                raise ValueError("Target is not in the configured scan scope")
            now = time.monotonic()
            if policy["mode"] == "public_https" and now - LAST_PUBLIC_SCAN.get(target_url, float("-inf")) < policy["interval_seconds"]:
                return self.send_json(429, {"error": "Scan interval has not elapsed"})
            baseline, output, report, history = result_paths(policy)
            result = scan(target_url, baseline, policy)
            save_result(result, output, report, history)
            if policy["mode"] == "public_https":
                LAST_PUBLIC_SCAN[target_url] = now
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {"error": str(exc)})
        except OSError:
            return self.send_json(503, {"error": "Scan target unavailable"})
        return self.send_json(200, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, action="append",
                        help="allow this exact policy target; repeat for multiple targets")
    args = parser.parse_args()
    if args.policy:
        ACTIVE_POLICIES = [load_policy(path) for path in args.policy]
        if len({p["target_url"] for p in ACTIVE_POLICIES}) != len(ACTIVE_POLICIES):
            raise SystemExit("Duplicate target_url in policies")
    if not KEY_FILE.exists():
        raise SystemExit("Create .local-api-key before starting; see docs/hengnao-local-api.md")
    API_KEY = KEY_FILE.read_text(encoding="utf-8").strip()
    if len(API_KEY) < 32:
        raise SystemExit(".local-api-key must contain at least 32 characters")
    server = HTTPServer(("127.0.0.1", 8001), Handler)
    print("Scan API listening on http://127.0.0.1:8001/scan", flush=True)
    server.serve_forever()
