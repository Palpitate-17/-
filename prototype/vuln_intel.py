"""Look up a known package/version in OSV, then flag CVEs listed in CISA KEV."""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


def read_json(request, limit):
    with urlopen(request, timeout=10) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Vulnerability feed exceeded size limit")
    return json.loads(body)


def lookup(ecosystem, name, version):
    for label, value in (("ecosystem", ecosystem), ("name", name), ("version", version)):
        if not value or len(value) > 160 or "\n" in value or "\r" in value:
            raise ValueError(f"Invalid {label}")
    query = json.dumps({"package": {"ecosystem": ecosystem, "name": name},
                        "version": version}).encode("utf-8")
    osv = read_json(Request(OSV_URL, data=query,
                            headers={"Content-Type": "application/json"}), 2_000_000)
    records = osv.get("vulns", [])
    if not isinstance(records, list):
        raise ValueError("Unexpected OSV response")
    cve_ids = {alias for item in records for alias in [item.get("id"), *item.get("aliases", [])]
               if isinstance(alias, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", alias)}
    kev_ids = set()
    if cve_ids:
        kev = read_json(KEV_URL, 10_000_000)
        kev_ids = {row["cveID"] for row in kev.get("vulnerabilities", [])
                   if row.get("cveID") in cve_ids}
    return {
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "package": {"ecosystem": ecosystem, "name": name, "version": version},
        "assessment": "公开情报匹配；未证明任何网站部署该版本或漏洞可利用",
        "matches": [{"id": item["id"], "aliases": item.get("aliases", []),
                     "modified": item.get("modified"),
                     "cisa_kev": bool(kev_ids.intersection([item["id"], *item.get("aliases", [])])),
                     "source_url": f"https://osv.dev/vulnerability/{item['id']}"}
                    for item in records],
        "sources": [OSV_URL, KEV_URL] if cve_ids else [OSV_URL],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", required=True, help="e.g. PyPI, npm, Maven")
    parser.add_argument("--name", required=True, help="exact package name")
    parser.add_argument("--version", required=True, help="known installed version")
    parser.add_argument("--output", type=Path, default=Path("vuln-intel.json"))
    args = parser.parse_args()
    result = lookup(args.ecosystem, args.name, args.version)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved {args.output}: {len(result['matches'])} public intelligence matches")
