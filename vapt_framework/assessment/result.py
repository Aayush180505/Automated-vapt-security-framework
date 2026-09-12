"""In-memory assessment outcome."""

from __future__ import annotations

from dataclasses import dataclass, field

from vapt_framework.assessment.summary import AssessmentSummary, empty_summary
from vapt_framework.core.enums import Severity
from vapt_framework.core.models import Finding


@dataclass(frozen=True)
class AssessmentResult:
    """Findings plus plugin execution metadata and risk summary."""

    findings: tuple[Finding, ...]
    executed_plugins: tuple[str, ...]
    skipped_plugins: tuple[str, ...]
    errors: tuple[str, ...]
    active_requests: int = 0
    summary: AssessmentSummary = field(default_factory=empty_summary)

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
