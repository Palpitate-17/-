from __future__ import annotations

import argparse
import hashlib
import json
import platform
from time import perf_counter
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urljoin

from scanner.baseline import build_baseline, compare_baseline
from scanner.common.models import PageInput
from scanner.external_links import compare_external_links, extract_external_links
from scanner.rules import load_rules
from scanner.sensitive import detect_sensitive
from tests.evaluate import calculate, write_results


ROOT = Path(__file__).resolve().parents[1]


def read_body(spec: dict, root: Path) -> str:
    if "body" in spec:
        return spec["body"]
    path = (root / spec["file"]).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("fixture 路径不在项目目录内")
    return path.read_text(encoding="utf-8").replace("{{NOW}}", str(spec.get("now", "2026-09-29T00:00:00Z")))


def run_local(truth: dict, manifest: dict, root: Path = ROOT) -> dict:
    cases = {case["case_id"]: case for case in truth["cases"]}
    assigned = [case_id for scenario in manifest["scenarios"] for case_id in scenario["case_ids"]]
    if len(set(assigned)) != len(assigned) or set(assigned) != set(cases):
        raise ValueError("manifest 必须恰好覆盖每个真值 case 一次")
    rules = load_rules(root / "scanner/rules/sensitive_rules.yaml")
    allowed = json.loads((root / "tests/fixtures/allowed_domains.json").read_text(encoding="utf-8"))["allowed_domains"]
    findings, runs = [], []
    for scenario in manifest["scenarios"]:
        group = [cases[case_id] for case_id in scenario["case_ids"]]
        first = group[0]
        if len({(case["url"], case.get("phase", "none"), case["category"]) for case in group}) != 1:
            raise ValueError("同一 scenario 必须对应相同 URL/phase/category")
        if len({case["rule_id"] for case in group}) != len(group):
            raise ValueError("同一 scenario 不允许重复 rule_id，避免重复计数")
        run_base = {"phase": first.get("phase", "none"), "scenario_id": scenario["id"], "mode": "offline_fixture"}
        if "skip_reason" in scenario:
            runs.extend({**run_base, "case_id": case["case_id"], "status": "skipped", "reason": scenario["skip_reason"]} for case in group)
            continue
        try:
            started = perf_counter()
            url = urljoin(truth.get("base_url", ""), first["url"])

            def page(spec: dict) -> PageInput:
                return PageInput(url=url, final_url=url, status_code=spec.get("status_code", 200),
                                 content_type=spec.get("content_type", "text/html; charset=utf-8"),
                                 body=read_body(spec, root), headers={}, fetched_at="2026-09-29T00:00:00Z")

            current = page(scenario["page"])
            module = scenario["module"]
            if module == "sensitive":
                if current.content_type.split(";", 1)[0] not in {"text/html", "text/plain", "application/json"}:
                    raise ValueError("本模块不支持该 Content-Type")
                detected = detect_sensitive(current, rules)
            elif module == "baseline":
                detected = compare_baseline(current, build_baseline(page(scenario["baseline"]), allowed), allowed)
            elif module == "external_links":
                previous = page(scenario["baseline"])
                detected = compare_external_links(current, extract_external_links(previous.body, url, allowed), allowed)
            else:
                raise ValueError("未知检测 module")
            by_rule = {case["rule_id"]: case for case in group}
            for finding in detected:
                # 未预期的规则也进入评测；不能过滤掉后声称没有误报。
                target = by_rule.get(finding.rule_id, first)
                findings.append({**finding.to_dict(), "case_id": target["case_id"], "phase": run_base["phase"]})
            scenario_elapsed_ms = round((perf_counter() - started) * 1000, 3)
            runs.extend({**run_base, "case_id": case["case_id"], "status": "succeeded",
                         "scenario_elapsed_ms": scenario_elapsed_ms} for case in group)
        except Exception as exc:
            # 错误状态不能伪装成成功的空数组，异常参数可能含正文，避免导出。
            runs.extend({**run_base, "case_id": case["case_id"], "status": "failed",
                         "reason": f"{type(exc).__name__}: 输入构建或检测失败"} for case in group)
    return {"schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "offline_fixture", "findings": findings, "case_runs": runs,
            "environment": {"python": platform.python_version(), "platform": platform.system(),
                            "packages": {name: version(name) for name in ("beautifulsoup4", "PyYAML")}},
            "limitations": ["实际调用 Python 检测器，未通过网络采集，也未接入 HTTP 服务或恒脑。",
                            "基线由可信本地 fixture 提供；未验证后端审批、调度、身份鉴权与复测状态。"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="真实执行本地 fixture→检测器→结果→评测")
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "tests/ground_truth.json")
    parser.add_argument("--manifest", type=Path, default=ROOT / "tests/fixtures/local_cases.json")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "reports")
    args = parser.parse_args()
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    started = perf_counter()
    output = run_local(truth, manifest)
    output["elapsed_ms"] = round((perf_counter() - started) * 1000, 3)
    input_paths = {args.ground_truth, args.manifest, ROOT / "scanner/rules/sensitive_rules.yaml",
                   ROOT / "tests/fixtures/allowed_domains.json", ROOT / "tests/evaluate.py", Path(__file__).resolve()}
    input_paths.update((ROOT / "scanner").rglob("*.py"))
    for scenario in manifest["scenarios"]:
        for key in ("page", "baseline"):
            if "file" in scenario.get(key, {}):
                input_paths.add((ROOT / scenario[key]["file"]).resolve())
    output["input_sha256"] = {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else path.name:
                              hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(input_paths)}
    result = calculate(truth, output["findings"], output["case_runs"])
    result.update({key: output[key] for key in ("generated_at", "mode", "environment", "input_sha256", "limitations", "elapsed_ms")})
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "actual_findings.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_results(result, args.out_dir / "evaluation_results.json", args.out_dir / "evaluation_results.csv")
    print(json.dumps({"summary": result["summary"], "coverage": result["coverage"], "case_metrics": result["case_metrics"]}, ensure_ascii=False))
    if result["coverage"]["failed"] or result["summary"]["fp"] or result["summary"]["fn"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
