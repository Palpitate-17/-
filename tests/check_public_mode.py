"""Check public target scoping without sending any external requests."""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
import local_scan  # noqa: E402
import vuln_intel  # noqa: E402

pages_policy = local_scan.load_policy(ROOT / "scan-public-policy.github-pages.json")
assert pages_policy["target_url"] == "https://palpitate-17.github.io/-/"
assert pages_policy["allowed_paths"] == {"/-/", "/-/about.html", "/-/public/config.txt"}


class FakeResponse:
    status = 200

    def __init__(self, path):
        self.path = path

    def read(self, _):
        if self.path == "/demo/":
            return b'<a href="/demo/config.txt">config</a><a href="https://elsewhere.test/">other</a>'
        return b"api_key=DEMO-ONLY-12345"

    def getheader(self, *_):
        return "text/html" if self.path == "/demo/" else "text/plain"

    def getheaders(self):
        return [("Content-Type", self.getheader("Content-Type"))]


class FakeConnection:
    paths = []

    def __init__(self, host, address):
        assert host == "owned.example" and address == "203.0.113.9"

    def request(self, method, path):
        assert method == "GET"
        self.path = path
        self.paths.append(path)

    def getresponse(self):
        return FakeResponse(self.path)

    def close(self):
        pass


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    policy = json.loads((ROOT / "scan-policy.json").read_text(encoding="utf-8"))
    policy.update(mode="public_https", data_kind="public_synthetic_demo",
                  target_url="https://owned.example/demo/",
                  allowed_paths=["/demo/", "/demo/config.txt"], team_modules=[])
    path = root / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    loaded = local_scan.load_policy(path)
    with patch.object(local_scan, "public_address", return_value="203.0.113.9"), \
         patch.object(local_scan, "PinnedHTTPSConnection", FakeConnection), \
         patch.object(local_scan, "probe_headers", return_value={"status": "ok", "observations": []}):
        result = local_scan.scan(policy["target_url"], root / "baseline.json", loaded)
    assert FakeConnection.paths == ["/demo/", "/demo/config.txt"]
    assert len(result["findings"]) == 1
    assert "DEMO-ONLY" not in json.dumps(result)
    assert result["data_kind"] == "public_synthetic_demo"
    assert "公开演示站" in local_scan.html_report(result)
    policy["target_url"] = "https://127.0.0.1/demo/"
    path.write_text(json.dumps(policy), encoding="utf-8")
    try:
        local_scan.load_policy(path)
        raise AssertionError("Public policy accepted loopback IP")
    except ValueError:
        pass

    def fake_json(request, limit):
        if not isinstance(request, str) and request.full_url == vuln_intel.OSV_URL:
            assert json.loads(request.data)["package"] == {"ecosystem": "PyPI", "name": "demo"}
            return {"vulns": [{"id": "GHSA-demo", "aliases": ["CVE-2020-12345"]}]}
        assert request == vuln_intel.KEV_URL
        return {"vulnerabilities": [{"cveID": "CVE-2020-12345"}]}

    with patch.object(vuln_intel, "read_json", side_effect=fake_json):
        intel = vuln_intel.lookup("PyPI", "demo", "1.0")
    assert intel["matches"][0]["cisa_kev"] is True
    assert "未证明" in intel["assessment"]
print("Public mode and intelligence checks passed")
