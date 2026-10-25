"""Validate a fresh Cloudflare Worker scan before presenting it in HengNao."""

import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    from runtime import Args
except ImportError:  # Enables local contract checks.
    Args = object


TARGET = "https://public-firing-range.appspot.com/"
ALLOWED_PAGES = {TARGET, TARGET + "mixedcontent/index.html", TARGET + "clickjacking/index.html"}


def _same_origin(url, target):
    if not isinstance(url, str):
        return False
    try:
        item, root = urlsplit(url), urlsplit(target)
        return (item.scheme, item.hostname, item.port) == (root.scheme, root.hostname, root.port)
    except ValueError:
        return False


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
    target = plan.get("target_url")
    if not isinstance(target, str) or not _same_origin(target, target):
        return {"status": "invalid_input", "report": "本轮未提供有效的网站目标。"}

    result = _object(result_raw)
    if not result:
        return {"status": "unavailable", "report": "实时巡检接口未返回可解析结果；不能判断目标安全状态。"}
    expected_kind = "public_scanner_testbed" if target == TARGET else "user_supplied_public_url"
    if (result.get("target_url") != target or result.get("data_kind") != expected_kind
            or result.get("execution_mode") != "on_demand"):
        return {"status": "invalid_result", "report": "接口结果的目标、数据类型或执行模式不符合预期。"}

    pages, findings = result.get("pages"), result.get("findings")
    checks, errors = result.get("tool_checks"), result.get("errors")
    if not all(isinstance(part, list) for part in (pages, findings, checks, errors)):
        return {"status": "invalid_result", "report": "接口结果缺少页面、发现或错误列表。"}
    if len(pages) + len(errors) > 3:
        return {"status": "invalid_result", "report": "接口结果超出本轮最多三个页面的限制。"}
    observations = [item for check in checks if isinstance(check, dict)
                    for item in check.get("observations", []) if isinstance(item, dict)]
    referenced = pages + findings + observations + errors
    if any(not isinstance(item, dict) or not _same_origin(item.get("url"), target) or
           (target == TARGET and item.get("url") not in ALLOWED_PAGES) for item in referenced):
        return {"status": "invalid_result", "report": "接口结果含目标站点以外的页面或证据，已拒绝生成结论。"}

    try:
        scanned_at = datetime.fromisoformat(result["scan_id"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - scanned_at).total_seconds()
        if scanned_at.tzinfo is None or not -60 <= age <= 300:
            raise ValueError("not a fresh timestamp")
    except (KeyError, TypeError, ValueError):
        return {"status": "invalid_result", "report": "扫描时间无效或结果不是本轮新生成的。"}

    partial = result.get("scan_status") != "complete" or bool(errors)
    lines = ["网站即时巡检", "目标：" + target,
             "来源：Cloudflare Pages Function；本轮按输入网址执行受限的同站点 GET 请求。",
             "扫描时间（UTC）：" + scanned_at.astimezone(timezone.utc).isoformat(),
             "执行状态：" + ("部分页面未成功，不能据此判断无发现。" if partial else "本轮页面请求完成。"),
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
            "target_url": target, "source": "cloudflare_pages_function", "report": "\n".join(lines)}


def handler(args: Args) -> dict:
    plan_raw = getattr(args.input, "input", None)
    scan_raw = getattr(args.input, "scan_result", None)
    result = inspect(plan_raw, scan_raw)
    plan = _object(plan_raw) or {}
    scan = _object(scan_raw) or {}
    wrapper = scan_raw if isinstance(scan_raw, dict) else {}

    # Diagnostic fields contain only metadata. Never echo request headers,
    # credentials, response bodies, or unmasked evidence into the workflow.
    tool_error_code = wrapper.get("_error_code", "")
    tool_error_message = wrapper.get("_error_message", "")
    if not isinstance(tool_error_code, (str, int)):
        tool_error_code = "invalid_type"
    if not isinstance(tool_error_message, str):
        tool_error_message = "invalid_type"
    diagnostics = {
        "route": plan.get("route", "missing"),
        "target_url": plan.get("target_url", ""),
        "tool_input_type": type(scan_raw).__name__,
        "tool_error_code": str(tool_error_code),
        "tool_error_message": tool_error_message[:300],
        "tool_result_parseable": bool(scan),
        "scan_status": scan.get("scan_status", "missing"),
        "result_target_url": scan.get("target_url", "missing"),
        "data_kind": scan.get("data_kind", "missing"),
        "execution_mode": scan.get("execution_mode", "missing"),
        "pages_count": len(scan["pages"]) if isinstance(scan.get("pages"), list) else "missing",
        "errors_count": len(scan["errors"]) if isinstance(scan.get("errors"), list) else "missing",
        "validation_status": result["status"],
    }
    return {
        "result_key": result["report"]
        + "\n\n【诊断信息】\n"
        + json.dumps(diagnostics, ensure_ascii=False, indent=2),
    }
