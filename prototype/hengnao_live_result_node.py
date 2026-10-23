"""Validate a fresh Cloudflare Worker scan before presenting it in HengNao."""

import json
from datetime import datetime, timezone

try:
    from runtime import Args
except ImportError:  # Enables local contract checks.
    Args = object


TARGET = "https://public-firing-range.appspot.com/"
ALLOWED_PAGES = {TARGET, TARGET + "mixedcontent/index.html", TARGET + "clickjacking/index.html"}


def _object(value):
    for _ in range(3):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None
        elif isinstance(value, dict) and "result_key" in value and "scan_id" not in value:
            value = value["result_key"]
        else:
            break
    return value if isinstance(value, dict) else None


def inspect(plan_raw, result_raw):
    plan = _object(plan_raw)
    if not plan:
        return {"status": "invalid_input", "report": "输入参数无效，未执行巡检结论。"}
    if plan.get("route") != "scan":
        return {"status": "not_run", "report": plan.get("message", "本轮未安排巡检。")}
    if plan.get("target_url") != TARGET:
        return {"status": "out_of_scope", "report": "当前仅支持预设公开测试靶场，未对输入网址执行巡检。"}

    result = _object(result_raw)
    if not result:
        return {"status": "unavailable", "report": "实时巡检接口未返回可解析结果；不能判断目标安全状态。"}
    if (result.get("target_url") != TARGET or result.get("data_kind") != "public_scanner_testbed"
            or result.get("execution_mode") != "on_demand"):
        return {"status": "invalid_result", "report": "接口结果的目标、数据类型或执行模式不符合预期。"}

    pages, findings = result.get("pages"), result.get("findings")
    checks, errors = result.get("tool_checks"), result.get("errors")
    if not all(isinstance(part, list) for part in (pages, findings, checks, errors)):
        return {"status": "invalid_result", "report": "接口结果缺少页面、发现或错误列表。"}
    observations = [item for check in checks if isinstance(check, dict)
                    for item in check.get("observations", []) if isinstance(item, dict)]
    referenced = pages + findings + observations + errors
    if any(not isinstance(item, dict) or item.get("url") not in ALLOWED_PAGES for item in referenced):
        return {"status": "invalid_result", "report": "接口结果含白名单外的页面或证据，已拒绝生成结论。"}

    try:
        scanned_at = datetime.fromisoformat(result["scan_id"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - scanned_at).total_seconds()
        if scanned_at.tzinfo is None or not -60 <= age <= 300:
            raise ValueError("not a fresh timestamp")
    except (KeyError, TypeError, ValueError):
        return {"status": "invalid_result", "report": "扫描时间无效或结果不是本轮新生成的。"}

    partial = result.get("scan_status") != "complete" or bool(errors)
    lines = ["公开测试靶场即时巡检", "目标：" + TARGET,
             "来源：Cloudflare Pages Function；本轮实时请求预设白名单页面。",
             "扫描时间（UTC）：" + scanned_at.astimezone(timezone.utc).isoformat(),
             "执行状态：" + ("部分页面未成功，不能据此判断无发现。" if partial else "三个预设页面请求完成。"),
             "页面：" + str(len(pages)) + "；规则发现：" + str(len(findings))
             + "；被动配置观察：" + str(len(observations)) + "。"]
    for page in pages:
        lines.append("页面：" + page["url"] + "；HTTP " + str(page.get("status", "未知")))
    for item in findings:
        lines.append("规则发现：" + str(item.get("category", "未知")) + "；" + item["url"]
                     + "；脱敏证据：" + str(item.get("evidence_masked", "无")) + "；待核实。")
    for item in observations:
        lines.append("配置观察：" + str(item.get("category", "未知")) + "；" + item["url"]
                     + "；脱敏证据：" + str(item.get("evidence_masked", "无")) + "；待核实。")
    for item in errors:
        lines.append("请求未完成：" + item["url"] + "；原因：" + str(item.get("error", "未知")))
    lines.append("本接口没有跨次扫描基线；已消失项和内容变化均未判定。规则命中不等于确认漏洞。")
    return {"status": "partial_result" if partial else "live_result", "scan_id": result["scan_id"],
            "target_url": TARGET, "source": "cloudflare_pages_function", "report": "\n".join(lines)}


def handler(args: Args) -> dict:
    result = inspect(args.input.input, args.input.scan_result)
    return {"result_key": result["report"]}
