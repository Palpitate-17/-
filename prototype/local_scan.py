"""Fetch exact allowlisted paths on a local demo or authorized HTTPS site."""

import argparse
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_PAGES = 10
MAX_BYTES = 262144
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "scan-policy.json"
SENSITIVE_IMPACT = "若真实凭据以同样方式被未授权读取，可能导致凭据滥用；本地演示未验证这一条件。"
SENSITIVE_REMEDIATION = "仅在核实真实凭据暴露后，移除公开配置、限制访问并轮换受影响凭据。"
HEADER_IMPACT = "缺少该响应头可能允许浏览器进行 MIME 嗅探；是否影响实际业务需结合内容类型核实。"
HEADER_REMEDIATION = "若需禁止 MIME 嗅探，在对应响应中设置 X-Content-Type-Options: nosniff 并复查。"
REMOTE_IMPACT = "若核实为真实有效凭据且未经授权即可读取，可能导致凭据滥用；当前规则命中尚未验证这些条件。"


class PinnedHTTPSConnection(HTTPSConnection):
    """Connect to a checked public IP while verifying TLS for the original host."""

    def __init__(self, host, address):
        super().__init__(host, 443, timeout=3, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, 443), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def public_address(host):
    addresses = [row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("Public HTTPS target must resolve only to globally routable addresses")
    return addresses[0]


def load_policy(path=DEFAULT_POLICY):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    target = urlsplit(policy["target_url"])
    mode = policy.get("mode", "local_demo")
    try:
        port = target.port
    except ValueError as exc:
        raise ValueError("Invalid target port") from exc
    if mode == "local_demo":
        if (target.scheme != "http" or target.hostname != "127.0.0.1" or not port
                or target.path != "/" or target.query or target.fragment
                or target.username or target.password or target.netloc != f"127.0.0.1:{port}"):
            raise ValueError("Policy target_url must be http://127.0.0.1:<port>/")
        data_kind = "synthetic_local_demo"
    elif mode == "public_https":
        host = target.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Public target must use a DNS hostname, not an IP address")
        if (target.scheme != "https" or port not in (None, 443)
                or not re.fullmatch(r"[A-Za-z0-9.-]+", host) or "." not in host
                or not target.path.startswith("/") or not target.path.endswith("/")
                or target.query or target.fragment or target.username or target.password
                or target.netloc not in (host, f"{host}:443")
                or any(part in (".", "..") for part in target.path.split("/"))):
            raise ValueError("Public target must be an exact HTTPS site root")
        data_kind = policy.get("data_kind")
        if data_kind not in ("public_synthetic_demo", "public_scanner_testbed", "authorized_public_site"):
            raise ValueError("Public policy needs an explicit data_kind")
    else:
        raise ValueError("Unknown scan mode")
    paths = policy["allowed_paths"]
    if (not isinstance(paths, list) or not paths or len(paths) > MAX_PAGES
            or target.path not in paths or any(not isinstance(p, str) or not p.startswith("/")
            or p.startswith("//") or "?" in p or "#" in p
            or any(segment in (".", "..") for segment in p.split("/")) for p in paths)
            or len(set(paths)) != len(paths)):
        raise ValueError("allowed_paths must list up to 10 distinct paths, including the target path")
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
            "interval_seconds": interval, "sensitive_rules": compiled,
            "mode": mode, "data_kind": data_kind}


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href" and value)


def probe_headers(target_url, raw_output_path, resolved_ip=None):
    """Read only the configured target's headers with curl."""
    raw_output_path.unlink(missing_ok=True)
    executable = shutil.which("curl.exe") or shutil.which("curl")
    if not executable:
        return {"tool": "curl", "status": "unavailable", "observations": []}
    target = urlsplit(target_url)
    command = [executable, "-q", "--noproxy", "*", "--head", "--max-time", "3",
               "--proto", f"={target.scheme}", "--silent", "--show-error"]
    if resolved_ip:
        ip_for_curl = f"[{resolved_ip}]" if ":" in resolved_ip else resolved_ip
        command.extend(["--resolve", f"{target.hostname}:443:{ip_for_curl}"])
    command.append(target_url)
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
                             "verification": "pending", "severity": "pending",
                             "potential_impact": HEADER_IMPACT,
                             "remediation_if_confirmed": HEADER_REMEDIATION})
    return {"tool": "curl", "status": "ok", "method": "HEAD", "url": target_url,
            "raw_output_file": raw_output_path.name,
            "http_status": http_status, "observations": observations}


def scan(target_url, baseline_path, policy=None):
    policy = policy or load_policy()
    if target_url != policy["target_url"]:
        raise ValueError("Target URL does not match scan policy")
    target = urlsplit(target_url)
    if policy["mode"] == "local_demo":
        port = target.port
        resolved_ip = None
    else:
        resolved_ip = public_address(target.hostname)
    saved = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else {}
    old = saved.get("hashes", saved)
    previous = saved.get("active_findings", [])
    new, pages, findings, changes = {}, [], [], []
    queue, seen = deque([target_url]), set()

    while queue and len(pages) < MAX_PAGES:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        path = urlsplit(url).path
        if path not in policy["allowed_paths"]:
            continue
        connection = (HTTPConnection("127.0.0.1", port, timeout=3)
                      if policy["mode"] == "local_demo" else PinnedHTTPSConnection(target.hostname, resolved_ip))
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
                            "evidence_masked": f"Text SHA-256 changed: {old[url][:12]} -> {digest[:12]}",
                            "verification": "pending",
                            "interpretation": "仅表示页面内容变化，不证明发生未授权篡改。"})
        for name, pattern in policy["sensitive_rules"]:
            for _ in pattern.finditer(text):
                finding = {"category": "sensitive_exposure", "url": url,
                           "evidence_masked": f"{name}=[REDACTED]",
                           "verification": "pending", "severity": "pending",
                           "potential_impact": (SENSITIVE_IMPACT if policy["mode"] == "local_demo"
                                                else REMOTE_IMPACT),
                           "remediation_if_confirmed": SENSITIVE_REMEDIATION}
                if finding not in findings:
                    findings.append(finding)
        if "text/html" in content_type:
            links = Links()
            links.feed(text)
            for href in links.hrefs:
                try:
                    candidate = urlsplit(urljoin(url, href))
                    in_scope = (candidate.scheme == target.scheme
                                and candidate.netloc == target.netloc
                                and candidate.path in policy["allowed_paths"])
                except ValueError:
                    continue
                if in_scope:
                    clean = urlunsplit((target.scheme, target.netloc, candidate.path, "", ""))
                    if clean not in seen and clean not in queue:
                        queue.append(clean)

    active = {(item["category"], item["url"], item["evidence_masked"]) for item in findings}
    resolved = [{**item, "resolution_status": "rule_no_longer_matched"} for item in previous
                if item["url"] in new
                and (item["category"], item["url"], item["evidence_masked"]) not in active]
    tool_check = probe_headers(target_url, baseline_path.parent / ".curl-headers.txt", resolved_ip)
    baseline_path.write_text(json.dumps({"hashes": new, "active_findings": findings},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
    return {"scan_id": datetime.now(timezone.utc).isoformat(), "simulated": False,
            "data_kind": policy["data_kind"], "target_url": target_url,
            "pages": pages, "findings": findings, "resolved_findings": resolved,
            "changes": changes, "tool_checks": [tool_check]}


def html_report(result):
    data_kind = result["data_kind"]
    if data_kind == "synthetic_local_demo":
        title = "本地巡检报告"
        note = "本机访问虚构演示站；规则命中未经真实风险验证。"
    elif data_kind == "public_synthetic_demo":
        title = "公开演示站巡检报告"
        note = "访问了团队自建的公开演示站；页面和凭据均为演示数据，规则命中未经真实风险验证。"
    elif data_kind == "public_scanner_testbed":
        title = "公开测试靶场巡检报告"
        note = "访问了公开供扫描器测试的靶场；本报告只覆盖策略允许的路径，规则命中不代表真实业务风险。"
    else:
        title = "授权站点巡检报告"
        note = "仅访问策略允许的路径；规则命中与内容变化均需进一步核实。"

    def list_items(items):
        rows = []
        for item in items:
            details = "".join(f"<br>{label}：{escape(item[key])}" for key, label in (
                ("potential_impact", "潜在影响"),
                ("remediation_if_confirmed", "核实后建议"),
                ("interpretation", "解释")) if item.get(key))
            rows.append(f"<li>{escape(item['url'])}: {escape(item['evidence_masked'])}{details}</li>")
        return "".join(rows) or "<li>无</li>"

    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>{title}</title><style>body{{font:16px/1.6 sans-serif;max-width:900px;margin:2em auto;padding:0 1em}}
li{{overflow-wrap:anywhere}}.note{{background:#eef5ff;padding:1em}}</style>
<h1>{title}</h1><p class="note">{note}</p>
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
