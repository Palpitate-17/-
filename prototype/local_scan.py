"""Fetch only a local demo site and compare its pages with the previous run."""

import argparse
import json
import re
import shutil
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from html.parser import HTMLParser
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_PAGES = 10
MAX_BYTES = 262144
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "scan-policy.json"


def load_policy(path=DEFAULT_POLICY):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    target = urlsplit(policy["target_url"])
    try:
        port = target.port
    except ValueError as exc:
        raise ValueError("Invalid local port") from exc
    if (target.scheme != "http" or target.hostname != "127.0.0.1" or not port
            or target.path != "/" or target.query or target.fragment
            or target.username or target.password or target.netloc != f"127.0.0.1:{port}"):
        raise ValueError("Policy target_url must be http://127.0.0.1:<port>/")
    paths = policy["allowed_paths"]
    if (not isinstance(paths, list) or not paths or len(paths) > MAX_PAGES
            or "/" not in paths or any(not isinstance(p, str) or not p.startswith("/")
            or p.startswith("//") or "?" in p or "#" in p
            or any(segment in (".", "..") for segment in p.split("/")) for p in paths)
            or len(set(paths)) != len(paths)):
        raise ValueError("allowed_paths must list up to 10 distinct local paths, including /")
    interval = policy["interval_seconds"]
    if type(interval) is not int or interval < 1:
        raise ValueError("interval_seconds must be a positive integer")
    rules = policy["sensitive_rules"]
    if not isinstance(rules, list) or not rules or len(rules) > 20:
        raise ValueError("sensitive_rules must contain 1-20 rules")
    compiled = []
    for rule in rules:
        if (not isinstance(rule, dict) or not isinstance(rule.get("name"), str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", rule["name"])
                or not isinstance(rule.get("pattern"), str)
                or not rule["pattern"] or len(rule["pattern"]) > 500):
            raise ValueError("Each sensitive rule needs a name and pattern")
        compiled.append((rule["name"], re.compile(rule["pattern"], re.I)))
    return {"target_url": policy["target_url"], "allowed_paths": set(paths),
            "interval_seconds": interval, "sensitive_rules": compiled}


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href" and value)


def probe_headers(target_url, raw_output_path):
    """Read only the allowed demo root's headers with the open-source curl tool."""
    raw_output_path.unlink(missing_ok=True)
    executable = shutil.which("curl.exe") or shutil.which("curl")
    if not executable:
        return {"tool": "curl", "status": "unavailable", "observations": []}
    command = [executable, "-q", "--noproxy", "*", "--head", "--max-time", "3",
               "--proto", "=http", "--silent", "--show-error", target_url]
    try:
        process = subprocess.run(command, capture_output=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError):
        return {"tool": "curl", "status": "error", "observations": []}
    raw_output_path.write_bytes(process.stdout)
    lines = process.stdout.decode("iso-8859-1").splitlines()
    headers = {key.strip().lower(): value.strip() for line in lines if ":" in line
               for key, value in [line.split(":", 1)]}
    http_status = int(lines[0].split()[1]) if lines and re.match(r"HTTP/\S+ \d{3}", lines[0]) else None
    observations = []
    if http_status == 200 and "x-content-type-options" not in headers:
        observations.append({"category": "missing_security_header", "url": target_url,
                             "evidence_masked": "X-Content-Type-Options header absent",
                             "verification": "pending", "severity": "pending"})
    return {"tool": "curl", "status": "ok", "method": "HEAD", "url": target_url,
            "raw_output_file": raw_output_path.name,
            "http_status": http_status, "observations": observations}


def scan(target_url, baseline_path, policy=None):
    policy = policy or load_policy()
    if target_url != policy["target_url"]:
        raise ValueError("Target URL does not match local policy")
    target = urlsplit(target_url)
    if target.scheme != "http" or target.hostname != "127.0.0.1" or target.username or target.password:
        raise ValueError("Only http://127.0.0.1:<port>/ is allowed")
    try:
        port = target.port
    except ValueError as exc:
        raise ValueError("Invalid local port") from exc
    if not port or target.path != "/" or target.query or target.fragment:
        raise ValueError("Use a local root URL such as http://127.0.0.1:8765/")

    origin = f"http://127.0.0.1:{port}"
    saved = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else {}
    old = saved.get("hashes", saved)
    previous = saved.get("active_findings", [])
    new, pages, findings, changes = {}, [], [], []
    queue, seen = deque([origin + "/"]), set()

    while queue and len(pages) < MAX_PAGES:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        path = urlsplit(url).path
        if path not in policy["allowed_paths"]:
            continue
        connection = HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            status = response.status
            body = response.read(MAX_BYTES + 1)
            content_type = response.getheader("Content-Type", "")
        finally:
            connection.close()
        if len(body) > MAX_BYTES:
            raise ValueError(f"Page too large: {url}")
        pages.append({"url": url, "status": status})
        if status != 200 or not ("text/html" in content_type or "text/plain" in content_type):
            continue
        text = body.decode("utf-8", errors="replace")
        # Text line endings may change on Git checkout without changing page content.
        digest = sha256(body.replace(b"\r\n", b"\n")).hexdigest()
        raw_digest = sha256(body).hexdigest()
        new[url] = digest
        if url in old and old[url] not in (digest, raw_digest):
            changes.append({"url": url,
                            "evidence_masked": f"Text SHA-256 changed: {old[url][:12]} -> {digest[:12]}"})
        for name, pattern in policy["sensitive_rules"]:
            for _ in pattern.finditer(text):
                finding = {"category": "sensitive_exposure", "url": url,
                           "evidence_masked": f"{name}=[REDACTED]",
                           "verification": "pending", "severity": "pending"}
                if finding not in findings:
                    findings.append(finding)
        if "text/html" in content_type:
            links = Links()
            links.feed(text)
            for href in links.hrefs:
                candidate = urlsplit(urljoin(url, href))
                if (candidate.scheme == "http" and candidate.hostname == "127.0.0.1"
                        and candidate.port == port and candidate.path in policy["allowed_paths"]):
                    clean = urlunsplit(("http", f"127.0.0.1:{port}", candidate.path or "/", "", ""))
                    if clean not in seen and clean not in queue:
                        queue.append(clean)

    active = {(item["category"], item["url"], item["evidence_masked"]) for item in findings}
    resolved = [item for item in previous
                if item["url"] in new
                and (item["category"], item["url"], item["evidence_masked"]) not in active]
    baseline_path.write_text(json.dumps({"hashes": new, "active_findings": findings},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
    return {"scan_id": datetime.now(timezone.utc).isoformat(), "simulated": False,
            "data_kind": "synthetic_local_demo", "target_url": origin + "/",
            "pages": pages, "findings": findings, "resolved_findings": resolved,
            "changes": changes,
            "tool_checks": [probe_headers(origin + "/", baseline_path.parent / ".curl-headers.txt")]}


def html_report(result):
    def list_items(items):
        return "".join(f"<li>{escape(item['url'])}: {escape(item['evidence_masked'])}</li>"
                       for item in items) or "<li>无</li>"

    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>本地巡检报告</title><style>body{{font:16px/1.6 sans-serif;max-width:900px;margin:2em auto;padding:0 1em}}
li{{overflow-wrap:anywhere}}.note{{background:#eef5ff;padding:1em}}</style>
<h1>本地巡检报告</h1><p class="note">仅在本机执行 HTTP 请求；页面内容为虚构演示数据。
发现仅是规则命中，未经真实风险验证。</p>
<p>目标：{escape(result['target_url'])}<br>时间（UTC）：{escape(result['scan_id'])}<br>
读取页面：{len(result['pages'])}</p>
<h2>当前发现（{len(result['findings'])}）</h2><ul>{list_items(result['findings'])}</ul>
<h2>本次已消失（{len(result['resolved_findings'])}）</h2><ul>{list_items(result['resolved_findings'])}</ul>
<h2>内容变化（{len(result['changes'])}）</h2><ul>{list_items(result['changes'])}</ul>
<h2>被动配置观察</h2><p>curl HEAD：{escape(result['tool_checks'][0]['status'])}；
缺少响应头仅为配置观察，是否构成风险仍需核实。</p>
<ul>{list_items(result['tool_checks'][0]['observations'])}</ul>
</html>"""


def save_result(result, output_path, report_path, history_path):
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(html_report(result), encoding="utf-8")
    summary = {"scan_id": result["scan_id"], "target_url": result["target_url"],
               "pages": len(result["pages"]), "findings": len(result["findings"]),
               "resolved_findings": len(result["resolved_findings"]),
               "changes": len(result["changes"]),
               "tool_observations": len(result["tool_checks"][0]["observations"])}
    with history_path.open("a", encoding="utf-8") as history:
        history.write(json.dumps(summary, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--url", help="must match the policy target_url")
    parser.add_argument("--baseline", type=Path, default=Path(".demo-baseline.json"))
    parser.add_argument("--output", type=Path, default=Path("demo-result.json"))
    parser.add_argument("--report", type=Path, default=Path("demo-report.html"))
    parser.add_argument("--history", type=Path, default=Path("demo-history.jsonl"))
    parser.add_argument("--watch", action="store_true", help="repeat using policy interval_seconds")
    parser.add_argument("--interval", type=int, help="override policy interval; repeat until Ctrl+C")
    args = parser.parse_args()
    policy = load_policy(args.policy)
    target_url = args.url or policy["target_url"]
    if target_url != policy["target_url"]:
        parser.error("--url must match policy target_url")
    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1 second")
    interval = args.interval if args.interval is not None else policy["interval_seconds"] if args.watch else None
    try:
        while True:
            try:
                result = scan(target_url, args.baseline, policy)
                save_result(result, args.output, args.report, args.history)
                print(f"Saved {args.output} and {args.report}: {len(result['pages'])} pages, "
                      f"{len(result['findings'])} active, {len(result['resolved_findings'])} resolved, "
                      f"{len(result['changes'])} changed", flush=True)
            except OSError as exc:
                if interval is None:
                    raise
                print(f"Scan failed: {exc}", flush=True)
            if interval is None:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped")
