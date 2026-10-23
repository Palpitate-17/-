from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from scanner.common.masking import mask_url, redact_text
from scanner.common.models import RawFinding


# 只在恒脑兼容输出层转换名称；检测器内部分类保持不变。
CATEGORY_MAPPING = {
    "sensitive_info": "sensitive_exposure",
    "page_baseline_change": "integrity_change",
    "external_link_change": "external_link_change",
}


def to_hengnao_finding(finding: RawFinding) -> dict[str, str]:
    """将一个内部发现转换为现有恒脑模拟 API 的五字段结构。

    verification 固定为 pending，表示规则命中仍需人工核实。这里不会把
    检测结果提升为“已确认漏洞”。证据与展示 URL 会再次执行防御性脱敏。
    """

    return {
        "category": CATEGORY_MAPPING.get(finding.category, finding.category),
        "url": mask_url(finding.url),
        "evidence_masked": redact_text(finding.evidence),
        "verification": "pending",
        "severity": finding.severity,
    }


def build_hengnao_response(
    scan_id: str,
    target_url: str,
    findings: Iterable[RawFinding],
    *,
    simulated: bool,
) -> dict[str, Any]:
    """构造与 PR #1 模拟 `/scan` 响应顶层字段兼容的对象。

    离线 fixture、固定数据或未真正抓取网页时必须传 simulated=True；只有
    lcx 的采集层实际获取并检查目标页面后才可传 simulated=False。
    """

    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError("scan_id 不能为空")
    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("target_url 不能为空")
    if not isinstance(simulated, bool):
        raise TypeError("simulated 必须是 bool")

    return {
        "scan_id": scan_id,
        "simulated": simulated,
        "target_url": mask_url(target_url),
        "findings": [to_hengnao_finding(finding) for finding in findings],
    }
