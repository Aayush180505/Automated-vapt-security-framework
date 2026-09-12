"""Risk engine, bands, priority, and explanation tests (no network)."""

from __future__ import annotations

import pytest

from vapt_framework.assessment.risk import (
    RiskEngine,
    band_for_score,
    clamp_score,
    format_score,
    priority_for_score,
)
from vapt_framework.core.enums import Confidence, Priority, Severity
from vapt_framework.core.models import Finding
from vapt_framework.core.target import parse_target
from vapt_framework.findings.factory import make_finding
from vapt_framework.findings.normalize import normalize_finding


def _finding(
    *,
    severity: Severity,
    confidence: Confidence,
    plugin_name: str = "test-plugin",
    finding_type: str = "example",
    url: str = "http://10.10.10.10/search?q=test",
    parameter: str = "q",
    title: str = "Example Finding",
) -> Finding:
    return make_finding(
        title=title,
        description="A test finding.",
        severity=severity,
        confidence=confidence,
        plugin_name=plugin_name,
        finding_type=finding_type,
        category="test",
        target=parse_target("http://10.10.10.10"),
        affected_url=url,
        evidence=None,
        remediation="n/a",
        parameter=parameter,
    )


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        (Severity.INFO, Confidence.LOW, 5.0),
        (Severity.LOW, Confidence.LOW, 12.5),
        (Severity.LOW, Confidence.HIGH, 25.0),
        (Severity.MEDIUM, Confidence.MEDIUM, 37.5),
        (Severity.HIGH, Confidence.HIGH, 75.0),
        (Severity.HIGH, Confidence.MEDIUM, 56.25),
        (Severity.CRITICAL, Confidence.HIGH, 100.0),
    ],
)
def test_risk_scores(
    severity: Severity, confidence: Confidence, expected: float
) -> None:
    assessment = RiskEngine().assess(_finding(severity=severity, confidence=confidence))
    assert assessment.score == expected
    assert assessment.severity is severity
    assert assessment.confidence is confidence


def test_score_clamping() -> None:
    assert clamp_score(-10) == 0.0
    assert clamp_score(0) == 0.0
    assert clamp_score(100) == 100.0
    assert clamp_score(150) == 100.0


def test_scoring_is_deterministic() -> None:
    finding = _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    engine = RiskEngine()
    first = engine.assess(finding)
    second = engine.assess(finding)
    assert first == second
    assert first.score == 56.25


def test_risk_explanation_and_calculation() -> None:
    assessment = RiskEngine().assess(
        _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    )
    assert assessment.explanation == (
        "High severity finding with medium confidence."
    )
    assert assessment.calculation == "75.0 × 0.75 = 56.25"
    assert "56.25" in format_score(assessment.score)


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0.0, Severity.INFO),
        (19.0, Severity.INFO),
        (20.0, Severity.LOW),
        (39.0, Severity.LOW),
        (40.0, Severity.MEDIUM),
        (59.0, Severity.MEDIUM),
        (60.0, Severity.HIGH),
        (79.0, Severity.HIGH),
        (80.0, Severity.CRITICAL),
        (100.0, Severity.CRITICAL),
    ],
)
def test_risk_bands(score: float, band: Severity) -> None:
    assert band_for_score(score) is band


def test_risk_band_differs_from_severity() -> None:
    assessment = RiskEngine().assess(
        _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    )
    assert assessment.severity is Severity.HIGH
    assert assessment.score == 56.25
    assert assessment.band is Severity.MEDIUM


@pytest.mark.parametrize(
    ("score", "priority"),
    [
        (100.0, Priority.P1),
        (90.0, Priority.P1),
        (89.0, Priority.P2),
        (70.0, Priority.P2),
        (69.0, Priority.P3),
        (50.0, Priority.P3),
        (49.0, Priority.P4),
        (30.0, Priority.P4),
        (29.0, Priority.P5),
        (0.0, Priority.P5),
    ],
)
def test_priority_boundaries(score: float, priority: Priority) -> None:
    assert priority_for_score(score) is priority


def test_priority_for_high_medium_finding() -> None:
    assessment = RiskEngine().assess(
        _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    )
    assert assessment.priority is Priority.P3


def test_apply_does_not_overwrite_severity() -> None:
    original = _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    scored = RiskEngine().apply(original)
    assert scored.severity is Severity.HIGH
    assert scored.risk_band is Severity.MEDIUM
    assert scored.risk_score == 56.25
    assert scored.priority is Priority.P3


def test_normalization_trims_metadata_not_evidence() -> None:
    from vapt_framework.core.models import Evidence

    evidence = Evidence(description="  keep  ")
    finding = make_finding(
        title="  Potential SQL Injection  ",
        description="  body  ",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        plugin_name="  sql-injection  ",
        finding_type=" potential-sqli ",
        category=" injection ",
        target=parse_target("http://10.10.10.10"),
        affected_url="  http://10.10.10.10/search?q=test  ",
        evidence=evidence,
        remediation="  fix  ",
        parameter=" q ",
    )
    normalized = normalize_finding(finding)
    assert normalized.title == "Potential SQL Injection"
    assert normalized.plugin_name == "sql-injection"
    assert normalized.parameter == "q"
    assert normalized.evidence is evidence
    assert normalized.evidence.description == "  keep  "
