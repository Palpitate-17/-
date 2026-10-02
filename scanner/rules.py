from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


VALID_MATCH_TYPES = {"regex", "keyword"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_MASKS = {"phone", "email", "token", "full"}


class RuleConfigError(ValueError):
    pass


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    rule_path = Path(path)
    try:
        raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleConfigError("YAML 格式错误") from exc
    if not isinstance(raw, dict):
        raise RuleConfigError("规则文件根节点必须是对象")
    rules = raw.get("rules", [])
    if not isinstance(rules, list):
        raise RuleConfigError("rules 必须是列表")

    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise RuleConfigError(f"第 {index} 条规则不是对象")
        if not isinstance(rule.get("id"), str):
            raise RuleConfigError(f"第 {index} 条规则 ID 必须是字符串")
        rule = dict(rule)
        rule_id = rule["id"].strip()
        rule["id"] = rule_id
        if not rule_id or rule_id in seen:
            raise RuleConfigError(f"规则 ID 为空或重复：{rule_id!r}")
        seen.add(rule_id)
        match_type = rule.get("match_type")
        severity = rule.get("severity")
        if not isinstance(match_type, str) or match_type not in VALID_MATCH_TYPES:
            raise RuleConfigError(f"{rule_id}: match_type 必须是 regex 或 keyword")
        if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
            raise RuleConfigError(f"{rule_id}: severity 不合法")
        if match_type == "regex":
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise RuleConfigError(f"{rule_id}: 缺少 pattern")
            try:
                compiled = re.compile(pattern)
                if compiled.search(""):
                    raise RuleConfigError(f"{rule_id}: pattern 不得匹配空文本")
            except re.error as exc:
                raise RuleConfigError(f"{rule_id}: pattern 正则无效") from exc
        for name in ("keywords", "exclude_values", "exclude_context_regex"):
            values = rule.get(name, [])
            if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
                raise RuleConfigError(f"{rule_id}: {name} 必须是非空字符串列表")
        if match_type == "keyword" and not rule.get("keywords"):
            raise RuleConfigError(f"{rule_id}: 缺少 keywords")
        for pattern in rule.get("exclude_context_regex", []):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise RuleConfigError(f"{rule_id}: exclude_context_regex 正则无效") from exc
        if not isinstance(rule.get("enabled", True), bool):
            raise RuleConfigError(f"{rule_id}: enabled 必须是布尔值")
        if not isinstance(rule.get("mask", "token"), str) or rule.get("mask", "token") not in VALID_MASKS:
            raise RuleConfigError(f"{rule_id}: mask 不合法")
        validated.append(rule)
    return validated
