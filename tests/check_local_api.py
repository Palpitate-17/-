"""One end-to-end check for local API authorization and first/retest results."""

import json
import shutil
import sys
import tempfile
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
        config.write_text("# issue removed\n", encoding="utf-8")
        status, second = post(port, api.API_KEY, api.TARGET_URL)
        assert status == 200 and len(second["findings"]) == 0
        assert len(second["resolved_findings"]) == len(second["changes"]) == 1
        assert api.REPORT.exists()
        print("Local API check passed")
    finally:
        endpoint.shutdown()
        site.shutdown()
