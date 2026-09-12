"""Deterministic assessment statistics from scored, deduplicated findings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vapt_framework.core.enums import Priority, Severity
from vapt_framework.core.models import Finding


@dataclass(frozen=True)
class AssessmentSummary:
    """Serializable roll-up of an assessment (no nested objects)."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    risk_critical: int = 0
    risk_high: int = 0
    risk_medium: int = 0
    risk_low: int = 0
    risk_info: int = 0
    p1: int = 0
    p2: int = 0
    p3: int = 0
    p4: int = 0
    p5: int = 0
    average_risk: float = 0.0
    maximum_risk: float = 0.0
    high_priority_count: int = 0
    scanner_count: int = 0


_EMPTY = AssessmentSummary()


def empty_summary() -> AssessmentSummary:
    return _EMPTY


def build_summary(findings: Sequence[Finding]) -> AssessmentSummary:
    """Count unique scored findings. Call after deduplication and scoring."""
    if not findings:
        return empty_summary()

    severity_counts = {item: 0 for item in Severity}
    band_counts = {item: 0 for item in Severity}
    priority_counts = {item: 0 for item in Priority}
    scores: list[float] = []
    scanners: set[str] = set()

    for finding in findings:
        severity_counts[finding.severity] += 1
        band = finding.risk_band or finding.severity
        band_counts[band] += 1
        if finding.priority is not None:
            priority_counts[finding.priority] += 1
        if finding.risk_score is not None:
            scores.append(finding.risk_score)
        if finding.plugin_name:
            scanners.add(finding.plugin_name)

    average = sum(scores) / len(scores) if scores else 0.0
    maximum = max(scores) if scores else 0.0
    high_priority = (
        priority_counts[Priority.P1] + priority_counts[Priority.P2]
    )
    return AssessmentSummary(
        total_findings=len(findings),
        critical=severity_counts[Severity.CRITICAL],
        high=severity_counts[Severity.HIGH],
        medium=severity_counts[Severity.MEDIUM],
        low=severity_counts[Severity.LOW],
        info=severity_counts[Severity.INFO],
        risk_critical=band_counts[Severity.CRITICAL],
        risk_high=band_counts[Severity.HIGH],
        risk_medium=band_counts[Severity.MEDIUM],
        risk_low=band_counts[Severity.LOW],
        risk_info=band_counts[Severity.INFO],
        p1=priority_counts[Priority.P1],
        p2=priority_counts[Priority.P2],
        p3=priority_counts[Priority.P3],
        p4=priority_counts[Priority.P4],
        p5=priority_counts[Priority.P5],
        average_risk=average,
        maximum_risk=maximum,
        high_priority_count=high_priority,
        scanner_count=len(scanners),
    )
