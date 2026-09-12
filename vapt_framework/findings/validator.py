"""Reject malformed plugin output without aborting the assessment."""

from __future__ import annotations

from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.findings.validator")


def validate_finding(finding: object) -> Finding | None:
    """Return ``finding`` if it is usable; otherwise log and return ``None``."""
    if not isinstance(finding, Finding):
        logger.warning("Finding rejected: not a Finding instance")
        return None
    if not finding.title.strip():
        logger.warning("Finding rejected: empty title")
        return None
    if not finding.description.strip():
        logger.warning("Finding rejected: empty description")
        return None
    if not isinstance(finding.severity, Severity):
        logger.warning("Finding rejected: invalid severity")
        return None
    if not isinstance(finding.confidence, Confidence):
        logger.warning("Finding rejected: invalid confidence")
        return None
    if not finding.plugin_name.strip():
        logger.warning("Finding rejected: missing plugin name")
        return None
    if finding.target is None:
        logger.warning("Finding rejected: missing target")
        return None
    if not (finding.affected_url or "").strip():
        logger.warning("Finding rejected: missing affected resource")
        return None
    if not finding.fingerprint.strip():
        logger.warning("Finding rejected: missing fingerprint")
        return None
    if finding.evidence is not None and not isinstance(finding.evidence, Evidence):
        logger.warning("Finding rejected: invalid evidence")
        return None
    if finding.evidence is not None and not finding.evidence.description.strip():
        logger.warning("Finding rejected: empty evidence description")
        return None
    return finding
