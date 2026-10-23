from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit


def normalize_url(url: str, base_url: str = "") -> str:
    parts = urlsplit(urljoin(base_url.rstrip("/") + "/", url) if base_url else url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def safe_div(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def metrics(tp: int, fp: int, fn: int) -> dict:
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": safe_div(tp, tp + fp), "recall": safe_div(tp, tp + fn),
            "f1": safe_div(2 * tp, 2 * tp + fp + fn), "fdr": safe_div(fp, tp + fp)}


def parse_findings(raw: object) -> tuple[list[dict], list[dict] | None]:
    if isinstance(raw, list):
        findings, runs = raw, None
    elif isinstance(raw, dict) and "findings" in raw:
        findings, runs = raw["findings"], raw.get("case_runs")
    else:
        raise ValueError("发现文件必须为数组或包含 findings 的对象")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("findings 必须为对象数组")
    if runs is not None and (not isinstance(runs, list) or any(not isinstance(item, dict) for item in runs)):
        raise ValueError("case_runs 必须为对象数组")
    return findings, runs


def calculate(ground_truth: dict, findings: list[dict], case_runs: list[dict] | None = None) -> dict:
    if not isinstance(ground_truth, dict) or not isinstance(ground_truth.get("cases"), list):
        raise ValueError("ground_truth 必须包含 cases 数组")
    base_url = ground_truth.get("base_url", "")
    cases = {}
    for case in ground_truth["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str) or not case["case_id"]:
            raise ValueError("每个 case 必须有非空 case_id")
        if case["case_id"] in cases:
            raise ValueError("case_id 重复")
        if not isinstance(case.get("positive"), bool):
            raise ValueError("positive 必须是布尔值")
        count = case.get("expected_count", 1 if case["positive"] else 0)
        if type(count) is not int or count < 0 or (case["positive"] != (count > 0)):
            raise ValueError("positive 与 expected_count 不一致")
        for field in ("category", "rule_id", "url"):
            if not isinstance(case.get(field), str) or not case[field]:
                raise ValueError(f"case 缺少 {field}")
        cases[case["case_id"]] = case

    runs = {}
    if case_runs is not None:
        for run in case_runs:
            case_id = run.get("case_id")
            if case_id not in cases or case_id in runs or run.get("status") not in {"succeeded", "failed", "skipped"}:
                raise ValueError("case_runs 包含未知/重复 case_id 或非法 status")
            runs[case_id] = run
    executed = set(cases) if case_runs is None else {key for key, run in runs.items() if run["status"] == "succeeded"}

    def identity(item: dict) -> tuple[str, str, str, str]:
        return (str(item.get("phase", "none")), item["category"], item["rule_id"], normalize_url(item["url"], base_url))

    expected = Counter()
    for case_id in executed:
        case = cases[case_id]
        expected[(case_id, *identity(case))] = case.get("expected_count", 1 if case["positive"] else 0)
    actual = Counter()
    actual_per_case = Counter()
    unassigned = 0
    for finding in findings:
        if not isinstance(finding, dict) or any(not isinstance(finding.get(field), str) or not finding[field]
                                               for field in ("category", "rule_id", "url")):
            raise ValueError("每个 finding 必须包含字符串 category/rule_id/url")
        case_id = finding.get("case_id")
        if case_id is None:
            candidates = [key for key, case in cases.items() if identity(case) == identity(finding)]
            same_location = [case for case in cases.values() if identity(case)[1:] == identity(finding)[1:]]
            if "phase" not in finding and any(case.get("phase", "none") != "none" for case in same_location):
                raise ValueError("finding 缺少 phase，不能匹配 before/after 用例")
            if len(candidates) > 1:
                raise ValueError("finding 缺少 case_id，存在多个相同匹配用例")
            case_id = candidates[0] if candidates else "__unassigned__"
        elif case_id not in cases:
            raise ValueError(f"finding 使用未知 case_id: {case_id}")
        if case_id in cases and case_id not in executed:
            raise ValueError("未成功执行的 case 不得提交 findings")
        if case_id == "__unassigned__":
            unassigned += 1
        else:
            actual_per_case[case_id] += 1
        actual[(case_id, *identity(finding))] += 1

    details = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    mismatches = []
    for key in sorted(set(expected) | set(actual)):
        exp, got = expected[key], actual[key]
        tp, fp, fn = min(exp, got), max(0, got - exp), max(0, exp - got)
        case_id, phase, category, rule_id, url = key
        for name, count in (("tp", tp), ("fp", fp), ("fn", fn)):
            details[category][name] += count
        if exp != got:
            mismatches.append({"case_id": case_id, "phase": phase, "category": category,
                               "rule_id": rule_id, "url": url, "expected": exp, "actual": got})
    categories = sorted({case["category"] for case in cases.values()} | set(details))
    rows = []
    for category in categories:
        category_cases = {key for key, case in cases.items() if case["category"] == category}
        rows.append({"category": category, **metrics(**details[category]),
                     "total_cases": len(category_cases),
                     "executed_cases": len(category_cases & executed) if case_runs is not None else None})
    totals = {name: sum(row[name] for row in rows) for name in ("tp", "fp", "fn")}
    coverage = {"verified": case_runs is not None, "total": len(cases),
                "succeeded": len(executed) if case_runs is not None else None,
                "failed": sum(run["status"] == "failed" for run in runs.values()),
                "skipped": sum(run["status"] == "skipped" for run in runs.values()),
                "unrecorded": len(cases) - len(runs),
                "ratio": safe_div(len(executed), len(cases)) if case_runs is not None else None}
    negative = {key for key in executed if not cases[key]["positive"]}
    negative_fp = sum(actual_per_case[key] > 0 for key in negative)
    case_metrics = None if case_runs is None else {
        "executed_positive_cases": len(executed) - len(negative), "executed_negative_cases": len(negative),
        "tn": len(negative) - negative_fp, "negative_cases_with_fp": negative_fp,
        "negative_case_fpr": safe_div(negative_fp, len(negative)),
        "unassigned_findings": unassigned,
    }
    return {"schema_version": 2, "summary": metrics(**totals), "coverage": coverage,
            "case_metrics": case_metrics, "by_category": rows, "mismatches": mismatches,
            "case_runs": list(runs.values()),
            "notes": ["finding 级 TP/FP/FN 与 case 级 TN/FPR 分开计算；null 表示分母为零或执行记录缺失。",
                      "跳过、失败、未记录的 case 不进入成功执行子集指标；必须同时查看 coverage。"]}


def write_results(result: dict, out_json: Path, out_csv: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with out_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["category", "tp", "fp", "fn", "precision", "recall", "f1",
                                                   "fdr", "total_cases", "executed_cases"])
        writer.writeheader()
        writer.writerows(result["by_category"])


def main() -> None:
    parser = argparse.ArgumentParser(description="比较实际发现与真值；不会默认使用示例结果冒充评测")
    parser.add_argument("--ground-truth", default="tests/ground_truth.json")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--out-json", default="reports/evaluation_results.json")
    parser.add_argument("--out-csv", default="reports/evaluation_results.csv")
    args = parser.parse_args()
    truth = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    findings, runs = parse_findings(json.loads(Path(args.findings).read_text(encoding="utf-8")))
    result = calculate(truth, findings, runs)
    write_results(result, Path(args.out_json), Path(args.out_csv))
    print(json.dumps({"summary": result["summary"], "coverage": result["coverage"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
