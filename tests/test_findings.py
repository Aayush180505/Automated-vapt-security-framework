"""Finding, evidence, validation, and deduplication tests."""

from __future__ import annotations

from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Evidence, Finding, ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.findings.deduplicator import deduplicate_findings
from vapt_framework.findings.factory import build_fingerprint, make_finding
from vapt_framework.findings.validator import validate_finding


def _valid(**overrides: object) -> Finding:
    values = dict(
        title="Missing X-Content-Type-Options Header",
        description="Header was not observed.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        plugin_name="security-headers",
        finding_type="missing-x-content-type-options",
        category="security-headers",
        target=parse_target("http://10.10.10.10"),
        affected_url="http://10.10.10.10/",
        evidence=Evidence(
            description="Header absent",
            url="http://10.10.10.10/",
            method="GET",
            status_code=200,
            headers={"server": "Apache"},
        ),
        remediation="Add the header.",
    )
    values.update(overrides)
    return make_finding(**values)  # type: ignore[arg-type]


def test_finding_creation_and_enums() -> None:
    finding = _valid()
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.HIGH
    assert finding.severity is not finding.confidence
    assert finding.evidence is not None
    assert finding.evidence.url == "http://10.10.10.10/"
    assert finding.plugin_name == "security-headers"


def test_confidence_enum_values() -> None:
    assert [item.value for item in Confidence] == ["low", "medium", "high"]


def test_deterministic_fingerprint() -> None:
    first = _valid()
    second = _valid()
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == build_fingerprint(
        "security-headers",
        "missing-x-content-type-options",
        "http://10.10.10.10/",
        "",
    )


def test_validate_finding_accepts_complete() -> None:
    assert validate_finding(_valid()) is not None


def test_invalid_finding_handling() -> None:
    assert validate_finding("not a finding") is None
    assert validate_finding(_valid(title="")) is None
    assert validate_finding(_valid(description="")) is None
    assert validate_finding(_valid(plugin_name="")) is None
    assert validate_finding(_valid(target=None)) is None
    assert validate_finding(_valid(affected_url="")) is None
    valid = _valid()
    empty_fp = Finding(
        title=valid.title,
        description=valid.description,
        severity=valid.severity,
        confidence=valid.confidence,
        plugin_name=valid.plugin_name,
        fingerprint="",
        category=valid.category,
        finding_type=valid.finding_type,
        target=valid.target,
        affected_url=valid.affected_url,
        evidence=valid.evidence,
        remediation=valid.remediation,
    )
    assert validate_finding(empty_fp) is None


def test_deduplication() -> None:
    unique = deduplicate_findings([_valid(), _valid()])
    assert len(unique) == 1
    other = _valid(finding_type="missing-csp", title="Missing Content-Security-Policy Header")
    unique = deduplicate_findings([_valid(), other])
    assert len(unique) == 2


def test_scan_context_findings() -> None:
    target = parse_target("http://10.10.10.10")
    empty = ScanContext(target=target)
    assert empty.findings == ()
    filled = ScanContext(target=target, findings=(_valid(), _valid(finding_type="missing-csp")))
    assert len(filled.findings) == 2
