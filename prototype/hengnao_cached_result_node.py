"""Validate and explain the latest public testbed scan inside a HengNao code node."""

import json
from datetime import datetime, timezone

try:
    from runtime import Args
except ImportError:  # Local contract checks.
    Args = object


TARGET = "https://public-firing-range.appspot.com/"
RESULT_URL = "https://raw.githubusercontent.com/Palpitate-17/-/scan-results/results/latest.json"
ALLOWED_PAGES = {
    TARGET,
    TARGET + "clickjacking/index.html",
    TARGET + "mixedcontent/index.html",
}


def _object(raw):
    """Accept a JSON string, an object, or the platform's result_key wrapper."""
    for _ in range(3):
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (TypeError, ValueError):
                return None
        elif isinstance(raw, dict) and "result_key" in raw and "scan_id" not in raw:
            raw = raw["result_key"]
        else:
            break
    return raw if isinstance(raw, dict) else None


def inspect(plan_raw, result_raw):
    plan = _object(plan_raw)
    if not plan:
        return {"status": "invalid_input", "report": "路由输入无效，未生成巡检结论。"}
    if plan.get("route") != "scan":
        return {"status": "not_run", "report": plan.get("message", "本轮未安排巡检。")}
    if plan.get("target_url") != TARGET:
        return {"status": "out_of_scope", "report": "当前仅支持预设公开测试靶场，未对输入网址执行巡检。"}

    result = _object(result_raw)
    if not result:
        return {"status": "unavailable", "report": "最新巡检结果无法解析；不能据此判断目标安全状态。"}
    if result.get("target_url") != TARGET or result.get("data_kind") != "public_scanner_testbed":
        return {"status": "invalid_result", "report": "巡检结果的目标或数据类型与白名单不符，已拒绝生成结论。"}

    pages = result.get("pages")
    findings = result.get("findings")
    if not isinstance(pages, list) or not isinstance(findings, list):
        return {"status": "invalid_result", "report": "巡检结果缺少 pages 或 findings 列表。"}
    if any(not isinstance(p, dict) or p.get("url") not in ALLOWED_PAGES for p in pages):
        return {"status": "invalid_result", "report": "巡检结果包含白名单外的页面，已拒绝生成结论。"}

    scan_id = result.get("scan_id", "")
    try:
        scanned_at = datetime.fromisoformat(scan_id.replace("Z", "+00:00"))
        if scanned_at.tzinfo is None:
            raise ValueError("timestamp has no timezone")
        age_hours = (datetime.now(timezone.utc) - scanned_at).total_seconds() / 3600
    except (TypeError, ValueError):
        return {"status": "invalid_result", "report": "巡检记录缺少有效扫描时间。"}

    observations = [item for check in result.get("tool_checks", [])
                    if isinstance(check, dict) for item in check.get("observations", [])
                    if isinstance(item, dict)]
    stale = age_hours < -1 or age_hours > 48
    lines = [
        "公开测试靶场巡检记录",
        "目标：" + TARGET,
        "来源：GitHub Actions 的最近一次定时巡检；读取记录不等于本轮即时扫描。",
        "扫描时间（UTC）：" + scanned_at.astimezone(timezone.utc).isoformat(),
        "结果地址：" + RESULT_URL,
        "时效：" + ("超过 48 小时或时间异常，需重新运行云端巡检。" if stale else "48 小时内。"),
        "允许范围内的页面：" + str(len(pages)) + " 个；规则发现：" + str(len(findings))
        + " 项；被动配置观察：" + str(len(observations)) + " 项。",
    ]
    for page in pages:
        lines.append("页面：" + str(page["url"]) + "；HTTP " + str(page.get("status", "未知")))
    for item in findings:
        if isinstance(item, dict):
            lines.append("规则发现：" + str(item.get("category", "未知")) + "；"
                         + str(item.get("url", "")) + "；证据："
                         + str(item.get("evidence_masked", "无")) + "；待核实。")
    for item in observations:
        lines.append("配置观察：" + str(item.get("category", "未知")) + "；"
                     + str(item.get("url", "")) + "；证据："
                     + str(item.get("evidence_masked", "无")) + "；待核实。")
    lines.append("结论：这是扫描器测试靶场的只读观察，不能据此断言真实业务网站存在已确认漏洞。")
    return {"status": "stale_result" if stale else "cached_result",
            "scan_id": scan_id, "target_url": TARGET, "source": "github_actions_latest",
            "report": "\n".join(lines)}


def handler(args: Args) -> dict:
    return inspect(args.input.input, args.input.scan_result)
