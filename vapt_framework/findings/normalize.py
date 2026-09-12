"""Normalize finding metadata before risk scoring.

Does not rewrite evidence excerpts or invent severity/confidence.
"""

from __future__ import annotations

from dataclasses import replace

from vapt_framework.core.models import Finding


def normalize_finding(finding: Finding) -> Finding:
    """Trim string metadata. Evidence objects are left unchanged."""
    return replace(
        finding,
        title=finding.title.strip(),
        description=finding.description.strip(),
        plugin_name=finding.plugin_name.strip(),
        category=(finding.category or "").strip(),
        finding_type=(finding.finding_type or "").strip(),
        fingerprint=finding.fingerprint.strip(),
        affected_url=_optional_strip(finding.affected_url),
        parameter=_optional_strip(finding.parameter),
        remediation=_optional_strip(finding.remediation),
    )


def _optional_strip(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
