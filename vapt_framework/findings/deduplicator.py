"""Deterministic finding deduplication by fingerprint."""

from __future__ import annotations

from vapt_framework.core.models import Finding
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.findings.deduplicator")


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Keep the first finding for each fingerprint, preserving order."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            logger.info("Duplicate finding removed: %s", finding.fingerprint)
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique
