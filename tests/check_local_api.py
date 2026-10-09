"""One end-to-end check for local API authorization and first/retest results."""

import json
import shutil
import subprocess
import sys
import tempfile
import time
from functools import partial
from http.client import HTTPConnection
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
import local_scan_api as api  # noqa: E402


def post(port, key, target):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("POST", "/scan", json.dumps({"target_url": target}),
                           {"Content-Type": "application/json", "X-API-Key": key})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    shutil.copytree(ROOT / "demo_site", root / "site")
    config = root / "site" / "public" / "config.txt"
    config.write_text("api_key=DEMO-ONLY-12345\n", encoding="utf-8")
    site = HTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(root / "site")))
    api.TARGET_URL = f"http://127.0.0.1:{site.server_address[1]}/"
    api.BASELINE = root / "baseline.json"
    api.RESULT = root / "result.json"
    api.REPORT = root / "report.html"
    api.HISTORY = root / "history.jsonl"
    api.API_KEY = "k" * 32
    endpoint = HTTPServer(("127.0.0.1", 0), api.Handler)
    for server in (site, endpoint):
        Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = endpoint.server_address[1]
        assert post(port, "wrong", api.TARGET_URL)[0] == 401
        assert post(port, api.API_KEY, "https://example.com/")[0] == 400
        status, first = post(port, api.API_KEY, api.TARGET_URL)
        assert status == 200 and len(first["pages"]) == 3 and len(first["findings"]) == 1
        assert "DEMO-ONLY-12345" not in json.dumps(first)
        for name in ("index.html", "about.html"):
            page = root / "site" / name
            body = page.read_bytes()
            page.write_bytes(body.replace(b"\r\n", b"\n") if b"\r\n" in body else body.replace(b"\n", b"\r\n"))
        config.write_text("# issue removed\n", encoding="utf-8")
        status, second = post(port, api.API_KEY, api.TARGET_URL)
        assert status == 200 and len(second["findings"]) == 0
        assert len(second["resolved_findings"]) == len(second["changes"]) == 1
        assert second["changes"][0]["url"].endswith("/public/config.txt")
        assert api.REPORT.exists()
        history = [json.loads(line) for line in api.HISTORY.read_text(encoding="utf-8").splitlines()]
        assert len(history) == 2
        assert [entry["findings"] for entry in history] == [1, 0]
        assert [entry["resolved_findings"] for entry in history] == [0, 1]
        assert "DEMO-ONLY-12345" not in api.HISTORY.read_text(encoding="utf-8")
        interval_history = root / "interval-history.jsonl"
        process = subprocess.Popen([
            sys.executable, str(ROOT / "prototype" / "local_scan.py"),
            "--url", api.TARGET_URL, "--interval", "1",
            "--baseline", str(root / "interval-baseline.json"),
            "--output", str(root / "interval-result.json"),
            "--report", str(root / "interval-report.html"),
            "--history", str(interval_history),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if interval_history.exists() and len(interval_history.read_text(encoding="utf-8").splitlines()) >= 2:
                    break
                time.sleep(0.1)
            assert len(interval_history.read_text(encoding="utf-8").splitlines()) >= 2
        finally:
            process.terminate()
            process.wait(timeout=3)
        print("Local API check passed")
    finally:
        endpoint.shutdown()
        site.shutdown()
