"""Order findings by explainable risk, then deterministic tie-breakers."""

from __future__ import annotations

from collections.abc import Sequence

from vapt_framework.assessment.risk import RiskEngine
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Finding

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


class FindingPrioritizer:
    """Score findings with :class:`RiskEngine` and sort them."""

    def __init__(self, engine: RiskEngine | None = None) -> None:
        self._engine = engine or RiskEngine()

    def prioritize(self, findings: Sequence[Finding]) -> tuple[Finding, ...]:
        scored: list[Finding] = []
        for finding in findings:
            if not isinstance(finding, Finding):
                continue
            if not isinstance(finding.severity, Severity):
                continue
            if not isinstance(finding.confidence, Confidence):
                continue
            scored.append(self._engine.apply(finding))
        scored.sort(key=_sort_key)
        return tuple(scored)


def prioritize_findings(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Convenience wrapper used by the assessment engine and CLI."""
    return FindingPrioritizer().prioritize(findings)


def _sort_key(finding: Finding) -> tuple:
    score = finding.risk_score if finding.risk_score is not None else -1.0
    return (
        -score,
        -_SEVERITY_RANK.get(finding.severity, 0),
        -_CONFIDENCE_RANK.get(finding.confidence, 0),
        (finding.affected_url or "").lower(),
        finding.plugin_name.lower(),
        finding.fingerprint,
    )
