"""Offline detector integration: initial baseline, change, and retest."""

import base64
import json
import sys
import tempfile
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
from local_scan import load_policy, save_result, scan  # noqa: E402


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    site_root = root / "site"
    site_root.mkdir()
    site = HTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(site_root)))
    Thread(target=site.serve_forever, daemon=True).start()
    try:
        clean = ('<!doctype html><title>demo</title><main>Public demo</main>'
                 '<span data-ignore="dynamic">1</span>')
        page = site_root / "index.html"
        page.write_text(clean, encoding="utf-8")
        policy = json.loads((ROOT / "scan-policy.json").read_text(encoding="utf-8"))
        policy["target_url"] = f"http://127.0.0.1:{site.server_address[1]}/"
        policy["allowed_paths"] = ["/"]
        policy["team_modules"] = ["sensitive", "encoded_secret", "baseline", "external_links"]
        policy_file = root / "policy.json"
        policy_file.write_text(json.dumps(policy), encoding="utf-8")
        loaded = load_policy(policy_file)
        baseline = root / "baseline.json"

        first = scan(loaded["target_url"], baseline, loaded)
        assert not first["findings"]
        assert len(first["module_runs"]) == 4
        assert all(run["status"] == "succeeded" for run in first["module_runs"])

        # A dynamic-only change must not trigger the DOM/text baseline detector.
        page.write_text(clean.replace('>1</span>', '>2</span>'), encoding="utf-8")
        dynamic = scan(loaded["target_url"], baseline, loaded)
        assert not any(item["category"] == "page_baseline_change" for item in dynamic["findings"])

        # All values and the linked domain are synthetic. The link must never be fetched.
        fake_value = "q4R!t7Y#k2M$p9N%v6X&"
        encoded = base64.b64encode(fake_value.encode()).decode()
        altered = (clean + '<a href="https://blocked.example.invalid/landing?token=fake">outside</a>'
                   '<script>const api_secret_b64 = "' + encoded + '";</script>')
        page.write_text(altered, encoding="utf-8")
        changed = scan(loaded["target_url"], baseline, loaded)
        categories = {item["category"] for item in changed["findings"]}
        assert {"sensitive_info", "page_baseline_change", "external_link_change",
                "external_link_risk"} <= categories
        assert any(item.get("rule_id") == "SENSITIVE_ENCODED_SECRET_B64"
                   for item in changed["findings"])
        assert not any(run["status"] == "failed" for run in changed["module_runs"])
        serialized = json.dumps(changed, ensure_ascii=False)
        assert encoded not in serialized and fake_value not in serialized
        assert "token=fake" not in serialized
        assert all(item["verification"] == item["severity"] == "pending"
                   for item in changed["findings"])

        page.write_text(clean.replace('>1</span>', '>3</span>'), encoding="utf-8")
        retest = scan(loaded["target_url"], baseline, loaded)
        assert not retest["findings"]
        assert len(retest["resolved_findings"]) == len(changed["findings"])
        save_result(retest, root / "result.json", root / "report.html", root / "history.jsonl")
        assert (root / "report.html").exists()
        assert "本次已消失" in (root / "report.html").read_text(encoding="utf-8")
        assert encoded not in (root / "result.json").read_text(encoding="utf-8")
        print(f"Team modules passed: changed={len(changed['findings'])}, "
              f"retest_resolved={len(retest['resolved_findings'])}")
    finally:
        site.shutdown()
