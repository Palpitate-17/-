from __future__ import annotations

import inspect
import json
from dataclasses import asdict, fields
from datetime import datetime, timezone
from pathlib import Path

from scanner.adapters.hengnao import build_hengnao_response
from scanner.baseline import build_baseline, compare_baseline
from scanner.common.models import BaselineRecord, PageInput, RawFinding
from scanner.external_links import compare_external_links, extract_external_links
from scanner.rules import load_rules
from scanner.sensitive import detect_sensitive
from tests.run_local_evaluation import run_local


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    allowed = ["fixture.example.invalid", "approved.example.invalid"]
    rules = load_rules(ROOT / "scanner/rules/sensitive_rules.yaml")
    samples = []

    def page(path: str, body: str) -> PageInput:
        url = f"http://fixture.example.invalid{path}"
        return PageInput(url=url, final_url=url, status_code=200,
                         content_type="text/html; charset=utf-8", body=body,
                         fetched_at="2026-09-29T00:00:00Z")

    def add(sample_id: str, module: str, input_data: dict, findings: list[RawFinding], expected_rules: list[str]) -> None:
        actual = [finding.to_dict() for finding in findings]
        if sorted(item["rule_id"] for item in actual) != sorted(expected_rules):
            raise ValueError(f"契约样例与预期不同: {sample_id}")
        samples.append({"sample_id": sample_id, "module": module, "input": input_data,
                        "expected_rule_ids": expected_rules, "result": {"findings": actual, "finding_count": len(actual)}})

    sensitive_positive = page("/sensitive/positive", "<p>值班电话：13912345678</p>")
    add("CONTRACT-S-P", "sensitive", {"page": asdict(sensitive_positive)},
        detect_sensitive(sensitive_positive, rules), ["SENSITIVE_PHONE_CN"])
    sensitive_negative = page("/sensitive/negative", "<p>占位示例 access_token=placeholder。</p>")
    add("CONTRACT-S-N", "sensitive", {"page": asdict(sensitive_negative)}, detect_sensitive(sensitive_negative, rules), [])
    before = page("/baseline/home", "<title>门户</title><p>服务正常</p><p>欢迎访问</p>")
    baseline = build_baseline(before, allowed)
    after = page("/baseline/home", '<title>维护</title><p>内容变化</p><script src="https://outside.example.invalid/app.js"></script>')
    add("CONTRACT-B-P", "baseline", {"page": asdict(after), "baseline": baseline.to_dict(), "allowed_domains": allowed},
        compare_baseline(after, baseline, allowed), [
            "BASELINE_TITLE_CHANGED", "BASELINE_TEXT_CHANGED", "BASELINE_DOM_CHANGED", "BASELINE_SCRIPT_ADDED"
        ])
    whitespace = page("/baseline/home", "<title>门户</title>\n<p>服务正常</p>\n  <p>欢迎访问</p>")
    add("CONTRACT-B-N", "baseline", {"page": asdict(whitespace), "baseline": baseline.to_dict(), "allowed_domains": allowed},
        compare_baseline(whitespace, baseline, allowed), [])
    external_before = page("/external/page", '<a href="https://old.example.invalid/help">已有</a>')
    previous = extract_external_links(external_before.body, external_before.final_url, allowed)
    external_after = page("/external/page", external_before.body + '<form action="https://new.example.invalid/send?token=synthetic-demo"></form>')
    add("CONTRACT-E-P", "external_links", {"page": asdict(external_after), "previous_links": previous, "allowed_domains": allowed},
        compare_external_links(external_after, previous, allowed), ["EXTERNAL_LINK_ADDED"])
    add("CONTRACT-E-N", "external_links", {"page": asdict(external_before), "previous_links": previous, "allowed_domains": allowed},
        compare_external_links(external_before, previous, allowed), [])
    generated_at = datetime.now(timezone.utc).isoformat()
    output = {"kind": "contract_samples_not_benchmark", "work_package_version": "v0.3.0",
              "generated_at": generated_at, "data_is_synthetic": True, "network_requests": 0,
              "functions": {fn.__name__: str(inspect.signature(fn)) for fn in
                            (load_rules, detect_sensitive, build_baseline, compare_baseline, extract_external_links, compare_external_links)},
              "model_fields": {model.__name__: [field.name for field in fields(model)] for model in
                               (PageInput, RawFinding, BaselineRecord)},
              "samples": samples,
              "limitations": ["输入与内部基线包含合成原始值；不得向智能体透传生产输入。",
                              "不是 tests.evaluate 的输入结构；真实 HTTP 契约以 docs/openapi.json 为准。",
                              "弱配置和常见漏洞检测器仍未接入。"]}
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "module_contract_samples.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    explanations = {
        "CONTRACT-S-P": ("本次可见文本命中手机号候选，已遮蔽。需结合公开性策略确认是否违规。", "已确认泄露真实个人信息"),
        "CONTRACT-S-N": ("当前规则将明示占位字段排除；本次可见文本规则未发现候选。", "该网站不存在任何敏感信息"),
        "CONTRACT-B-P": ("标题、正文和新增脚本与本地批准基线不同，请核对发布记录。", "网站已被攻击或篡改"),
        "CONTRACT-B-N": ("只改变空白换行，当前归一化比较未发现差异。", "所有脚本及资源内容都已校验安全"),
        "CONTRACT-E-P": ("相对基线出现新的表单外部目的地，查询值已遮蔽；请核对业务用途。", "已发现恶意外链"),
        "CONTRACT-E-N": ("相对提供的基线，当前页面未发现新增外部引用。", "所有外部域名都经过恶意信誉认证"),
    }
    examples = []
    for sample in samples:
        explanation, forbidden = explanations[sample["sample_id"]]
        examples.append({"sample_id": sample["sample_id"], "origin": "actual_offline_module_call",
                         "result": {"status": "succeeded", "findings": sample["result"]["findings"],
                                    "coverage": {"module": sample["module"], "mode": "offline_fixture"}},
                         "explanation": explanation, "forbidden_claim": forbidden})
    failed_truth = {"base_url": "http://fixture.example.invalid", "cases": [{"case_id": "DEMO-FAIL", "url": "/failed",
                    "phase": "none", "category": "sensitive_info", "rule_id": "SENSITIVE_PHONE_CN", "positive": False, "expected_count": 0}]}
    failure = run_local(failed_truth, {"scenarios": [{"id": "deliberate-missing-fixture", "case_ids": ["DEMO-FAIL"],
                        "module": "sensitive", "page": {"file": "tests/fixtures/deliberate_missing_demo.html"}}]})
    if failure["case_runs"][0]["status"] != "failed":
        raise ValueError("故意缺失 fixture 的失败样例没有产生 failed")
    examples.append({"sample_id": "WORKFLOW-FAILED", "origin": "actual_deliberate_fixture_failure",
                     "result": {"status": "failed", "findings": failure["findings"], "reason": failure["case_runs"][0]["reason"]},
                     "explanation": "本次输入构建失败，未完成检查，不能判定是否安全。", "forbidden_claim": "空结果证明安全或已修复"})
    actual = json.loads((reports / "actual_findings.json").read_text(encoding="utf-8"))
    skipped = next(run for run in actual["case_runs"] if run["status"] == "skipped")
    examples.append({"sample_id": "WORKFLOW-SKIPPED", "origin": "actual_evaluation_case_run",
                     "result": {"status": "skipped", "findings": [], "reason": skipped["reason"]},
                     "explanation": "弱配置检测器尚未接入，该项未执行。", "forbidden_claim": "安全响应头和 Cookie 检查已通过"})
    agent = {"kind": "agent_presentation_examples", "generated_at": generated_at,
             "wrapper_status": "legacy_offline_examples_use_openapi_for_live_api", "examples": examples}
    (reports / "agent_examples.json").write_text(json.dumps(agent, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    compatible_examples = []
    for sample in samples:
        page_input = sample["input"]["page"]
        response = build_hengnao_response(
            scan_id=f"compat-{sample['sample_id'].lower()}",
            target_url=page_input["final_url"],
            findings=[RawFinding(**item) for item in sample["result"]["findings"]],
            simulated=True,
        )
        if set(response) != {"scan_id", "simulated", "target_url", "findings"}:
            raise ValueError(f"恒脑兼容响应顶层字段不一致: {sample['sample_id']}")
        compatible_examples.append({
            "sample_id": sample["sample_id"],
            "origin": "actual_offline_module_call",
            "response": response,
        })
    compatible = {
        "kind": "hengnao_mock_api_compatible_examples",
        "generated_at": generated_at,
        "compatibility_target": "PR #1 mock /scan response",
        "data_is_synthetic": True,
        "deployment_status": "legacy_mock_adapter_only_live_api_uses_v1_contract",
        "notes": [
            "每个 response 只使用现有模拟 API 的 scan_id、simulated、target_url、findings 顶层字段。",
            "离线 fixture 必须保持 simulated=true；真实采集接入后才可由后端设置 false。",
            "verification=pending 表示规则候选仍需人工核实。",
        ],
        "examples": compatible_examples,
    }
    (reports / "hengnao_compatible_examples.json").write_text(
        json.dumps(compatible, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"contract_samples": len(samples), "agent_examples": len(examples),
                      "hengnao_compatible_examples": len(compatible_examples)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
