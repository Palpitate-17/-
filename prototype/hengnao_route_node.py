# coding=utf-8
"""HengNao code-node router for a URL explicitly named in this user turn.

This node decides what the workflow may attempt; it does not scan a target.
Tool-side scope and request controls remain necessary before a scan runs.
"""

import json
import ipaddress
from urllib.parse import urlsplit

try:
    from runtime import Args
except ImportError:  # Allow local unit tests without the HengNao runtime.
    Args = object


ENABLED_CHECKS = {"weak_config"}
# Exact hostnames authorized for the HengNao workflow. Add subdomains explicitly.
AUTHORIZED_DOMAINS = {
    "public-firing-range.appspot.com",
}
PROTECTED_HOST_SUFFIXES = ("gov.cn", "mil.cn", "政务.cn", "gov", "mil")
PROTECTED_EXACT_HOSTS = {"zwfw.cscse.edu.cn", "hengnao-authorized-scan.pages.dev"}
NONPUBLIC_SUFFIXES = ("localhost", "local", "internal", "test", "invalid", "onion")
ACTIONS = {
    "call_scan": "scan",
    "use_existing_result": "history",
    "ask_user": "ask_user",
    "reply_directly": "reply",
    "refuse": "refuse",
}


def is_protected_host(hostname):
    """Reject configured blacklisted hosts and nonpublic URL forms."""
    try:
        host = hostname.strip().rstrip(".").encode("idna").decode("ascii").lower()
        suffixes = (
            item.encode("idna").decode("ascii")
            for item in PROTECTED_HOST_SUFFIXES + NONPUBLIC_SUFFIXES
        )
    except (AttributeError, UnicodeError):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return (not host or "." not in host or host.replace(".", "").isdigit()
            or host in PROTECTED_EXACT_HOSTS or any(
        host == suffix or host.endswith("." + suffix) for suffix in suffixes
    ))


def result(route, target_url="", checks=None, message=""):
    return {
        "route": route,
        "target_url": target_url,
        "checks": checks if checks is not None else [],
        "message": message,
    }


def route_plan(raw_plan, user_message):
    try:
        plan = json.loads(raw_plan) if isinstance(raw_plan, str) else raw_plan
    except (ValueError, TypeError):
        return result("error", message="需求判断节点未输出有效 JSON")

    if not isinstance(plan, dict):
        return result("error", message="需求判断结果不是 JSON 对象")

    route = ACTIONS.get(plan.get("next_action"))
    if route is None:
        return result("error", message="无法识别 next_action")
    if route != "scan":
        return result(
            route,
            message=plan.get("clarification_question") or plan.get("reason") or "",
        )

    candidate = plan.get("target_candidate")
    if not isinstance(candidate, str) or not candidate.strip():
        return result("ask_user", message="请在本轮消息中明确填写要巡检的网址。")
    candidate = candidate.strip()
    if not isinstance(user_message, str) or candidate not in user_message:
        return result("ask_user", message="请在本轮消息中明确填写要巡检的网址。")

    try:
        parsed = urlsplit(candidate)
        # Accessing port also rejects malformed numeric ports. The node only
        # accepts an explicit HTTP(S) URL; network/scope checks belong to the
        # scanner before it sends any request.
        port = parsed.port
        valid_url = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and port is None
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
            and not any(char.isspace() for char in candidate)
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        return result("ask_user", message="请提供完整、有效的 HTTP(S) 网站网址。")
    if is_protected_host(parsed.hostname):
        return result("refuse", message="此目标属于已配置的特殊站点禁扫范围，本轮不安排扫描。")

    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if host not in AUTHORIZED_DOMAINS:
        return result("refuse", message="目标域名未列入授权白名单，本轮不安排扫描。")

    requested = plan.get("requested_checks", [])
    if not isinstance(requested, list):
        return result("error", message="requested_checks 格式错误")
    desired = requested if requested else sorted(ENABLED_CHECKS)
    checks = [
        item for item in desired
        if isinstance(item, str) and item in ENABLED_CHECKS
    ]
    if not checks:
        return result("ask_user", message="所请求的检查类别尚未接入可用工具")

    return result("scan", candidate, checks, "仅按用户本轮指定的网址安排检查")


def handler(args: Args) -> dict:
    return route_plan(
        getattr(args.input, "plan", None),
        getattr(args.input, "user_message", ""),
    )
