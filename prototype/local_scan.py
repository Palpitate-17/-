"""Fetch only a local demo site and compare its pages with the previous run."""

import argparse
import json
import re
import time
from collections import deque
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from html.parser import HTMLParser
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

KEY_PATTERN = re.compile(r"\b(api[_-]?key|token|secret)\s*[:=]\s*([A-Za-z0-9._-]{6,})", re.I)
MAX_PAGES = 10
MAX_BYTES = 262144


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href" and value)


def scan(target_url, baseline_path):
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
        for match in KEY_PATTERN.finditer(text):
            findings.append({"category": "sensitive_exposure", "url": url,
                             "evidence_masked": f"{match.group(1)}=[REDACTED]",
                             "verification": "pending", "severity": "pending"})
        if "text/html" in content_type:
            links = Links()
            links.feed(text)
            for href in links.hrefs:
                candidate = urlsplit(urljoin(url, href))
                if candidate.scheme == "http" and candidate.hostname == "127.0.0.1" and candidate.port == port:
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
            "changes": changes}


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
</html>"""


def save_result(result, output_path, report_path, history_path):
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(html_report(result), encoding="utf-8")
    summary = {"scan_id": result["scan_id"], "target_url": result["target_url"],
               "pages": len(result["pages"]), "findings": len(result["findings"]),
               "resolved_findings": len(result["resolved_findings"]),
               "changes": len(result["changes"])}
    with history_path.open("a", encoding="utf-8") as history:
        history.write(json.dumps(summary, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8765/")
    parser.add_argument("--baseline", type=Path, default=Path(".demo-baseline.json"))
    parser.add_argument("--output", type=Path, default=Path("demo-result.json"))
    parser.add_argument("--report", type=Path, default=Path("demo-report.html"))
    parser.add_argument("--history", type=Path, default=Path("demo-history.jsonl"))
    parser.add_argument("--interval", type=int, help="repeat every N seconds until Ctrl+C")
    args = parser.parse_args()
    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1 second")
    try:
        while True:
            try:
                result = scan(args.url, args.baseline)
                save_result(result, args.output, args.report, args.history)
                print(f"Saved {args.output} and {args.report}: {len(result['pages'])} pages, "
                      f"{len(result['findings'])} active, {len(result['resolved_findings'])} resolved, "
                      f"{len(result['changes'])} changed", flush=True)
            except OSError as exc:
                if args.interval is None:
                    raise
                print(f"Scan failed: {exc}", flush=True)
            if args.interval is None:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped")
