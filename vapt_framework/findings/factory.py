"""Finding construction helpers."""

from __future__ import annotations

from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.core.target import Target


def build_fingerprint(
    plugin_name: str,
    finding_type: str,
    resource: str,
    parameter: str = "",
) -> str:
    """Deterministic identity for deduplication (not a random UUID)."""
    return "|".join((plugin_name, finding_type, resource, parameter))


def make_finding(
    *,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    plugin_name: str,
    finding_type: str,
    category: str,
    target: Target | None,
    affected_url: str | None,
    evidence: Evidence | None,
    remediation: str | None,
    parameter: str = "",
) -> Finding:
    fingerprint = build_fingerprint(
        plugin_name,
        finding_type,
        affected_url or "",
        parameter,
    )
    return Finding(
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        plugin_name=plugin_name,
        fingerprint=fingerprint,
        category=category,
        finding_type=finding_type,
        target=target,
        affected_url=affected_url,
        parameter=parameter or None,
        evidence=evidence,
        remediation=remediation,
    )
