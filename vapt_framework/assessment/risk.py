"""Centralized, explainable finding risk scoring.

Scanners must not compute risk. This module uses only Finding metadata:
severity and confidence. It has no knowledge of specific plugins or HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass

from vapt_framework.core.enums import Confidence, Priority, Severity
from vapt_framework.core.models import Finding
from vapt_framework.findings.normalize import normalize_finding

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 10.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 100.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.LOW: 0.50,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.00,
}

# Inclusive lower bound of each band, highest first.
_BAND_FLOOR: tuple[tuple[float, Severity], ...] = (
    (80.0, Severity.CRITICAL),
    (60.0, Severity.HIGH),
    (40.0, Severity.MEDIUM),
    (20.0, Severity.LOW),
    (0.0, Severity.INFO),
)

# Inclusive lower bound of each priority, highest first.
_PRIORITY_FLOOR: tuple[tuple[float, Priority], ...] = (
    (90.0, Priority.P1),
    (70.0, Priority.P2),
    (50.0, Priority.P3),
    (30.0, Priority.P4),
    (0.0, Priority.P5),
)

HIGH_PRIORITIES = frozenset({Priority.P1, Priority.P2})


@dataclass(frozen=True)
class RiskAssessment:
    """Serializable risk outcome for one finding."""

    score: float
    band: Severity
    priority: Priority
    severity: Severity
    confidence: Confidence
    explanation: str
    calculation: str


def clamp_score(value: float) -> float:
    """Restrict a raw score to ``[0, 100]``."""
    return max(0.0, min(100.0, value))


def band_for_score(score: float) -> Severity:
    """Map a clamped score to a risk band (not original severity)."""
    clamped = clamp_score(score)
    for floor, band in _BAND_FLOOR:
        if clamped >= floor:
            return band
    return Severity.INFO


def priority_for_score(score: float) -> Priority:
    """Map a clamped score to a remediation priority."""
    clamped = clamp_score(score)
    for floor, priority in _PRIORITY_FLOOR:
        if clamped >= floor:
            return priority
    return Priority.P5


def format_score(score: float) -> str:
    """Render a score without unexplained trailing noise."""
    text = f"{clamp_score(score):.2f}".rstrip("0").rstrip(".")
    if "." not in text:
        return f"{text}.0"
    return text


class RiskEngine:
    """Deterministic severity × confidence scoring."""

    def assess(self, finding: Finding) -> RiskAssessment:
        """Return an explainable risk assessment for ``finding``."""
        normalized = normalize_finding(finding)
        if not isinstance(normalized.severity, Severity):
            raise ValueError("Finding severity is not a Severity enum.")
        if not isinstance(normalized.confidence, Confidence):
            raise ValueError("Finding confidence is not a Confidence enum.")
        weight = SEVERITY_WEIGHT[normalized.severity]
        multiplier = CONFIDENCE_MULTIPLIER[normalized.confidence]
        score = clamp_score(weight * multiplier)
        band = band_for_score(score)
        priority = priority_for_score(score)
        explanation = (
            f"{normalized.severity.name.title()} severity finding with "
            f"{normalized.confidence.name.lower()} confidence."
        )
        calculation = f"{format_score(weight)} × {format_score(multiplier)} = {format_score(score)}"
        return RiskAssessment(
            score=score,
            band=band,
            priority=priority,
            severity=normalized.severity,
            confidence=normalized.confidence,
            explanation=explanation,
            calculation=calculation,
        )

    def apply(self, finding: Finding) -> Finding:
        """Return ``finding`` with risk fields populated. Does not change severity."""
        from dataclasses import replace

        normalized = normalize_finding(finding)
        assessment = self.assess(normalized)
        return replace(
            normalized,
            risk_score=assessment.score,
            risk_band=assessment.band,
            priority=assessment.priority,
            risk_explanation=assessment.explanation,
        )
