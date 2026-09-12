"""Finding prioritization and assessment summary tests (no network)."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.engine import AssessmentEngine
from vapt_framework.assessment.prioritizer import FindingPrioritizer, prioritize_findings
from vapt_framework.assessment.registry import PluginRegistry
from vapt_framework.assessment.summary import build_summary, empty_summary
from vapt_framework.core.enums import Confidence, Priority, Severity
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.findings.deduplicator import deduplicate_findings
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.headers.scanner import SecurityHeadersPlugin
from tests.test_assessment_engine import BoomPlugin, FindingPlugin
from tests.test_risk import _finding


def test_sort_by_risk_score() -> None:
    low = _finding(
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        finding_type="low",
        title="Low",
        url="http://10.10.10.10/a",
    )
    high = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        finding_type="high",
        title="High",
        url="http://10.10.10.10/b",
    )
    medium = _finding(
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        finding_type="med",
        title="Medium",
        url="http://10.10.10.10/c",
    )
    ranked = prioritize_findings((low, high, medium))
    assert [item.risk_score for item in ranked] == [75.0, 50.0, 25.0]


def test_tie_break_is_deterministic() -> None:
    first = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        plugin_name="sql-injection",
        finding_type="a",
        url="http://10.10.10.10/a",
        title="A",
    )
    second = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        plugin_name="reflected-xss",
        finding_type="b",
        url="http://10.10.10.10/b",
        title="B",
    )
    left = FindingPrioritizer().prioritize((second, first))
    right = FindingPrioritizer().prioritize((first, second))
    assert [item.fingerprint for item in left] == [item.fingerprint for item in right]
    assert left[0].affected_url == "http://10.10.10.10/a"


def test_duplicate_findings_not_counted_twice() -> None:
    item = _finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    unique = deduplicate_findings([item, item])
    ranked = prioritize_findings(unique)
    summary = build_summary(ranked)
    assert summary.total_findings == 1


def test_multiple_scanners_in_summary() -> None:
    sqli = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        plugin_name="sql-injection",
        finding_type="sqli",
    )
    xss = _finding(
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        plugin_name="reflected-xss",
        finding_type="xss",
        url="http://10.10.10.10/search?q=x",
    )
    summary = build_summary(prioritize_findings((sqli, xss)))
    assert summary.scanner_count == 2
    assert summary.high == 1
    assert summary.medium == 1
    assert summary.p3 == 1
    assert summary.p4 == 1
    assert summary.average_risk == (56.25 + 37.5) / 2
    assert summary.maximum_risk == 56.25
    assert summary.high_priority_count == 0


def test_empty_summary() -> None:
    summary = build_summary(())
    assert summary == empty_summary()
    assert summary.total_findings == 0
    assert summary.average_risk == 0.0
    assert summary.maximum_risk == 0.0
    assert summary.high_priority_count == 0
    assert summary.scanner_count == 0


def test_high_priority_count_p1_p2() -> None:
    critical = _finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        finding_type="crit",
    )
    high = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        finding_type="high",
        url="http://10.10.10.10/other",
    )
    summary = build_summary(prioritize_findings((critical, high)))
    assert summary.p1 == 1
    assert summary.p2 == 1
    assert summary.high_priority_count == 2
    assert summary.risk_critical == 1
    assert summary.risk_high == 1


def test_invalid_items_skipped_by_prioritizer() -> None:
    valid = _finding(severity=Severity.LOW, confidence=Confidence.HIGH)
    ranked = FindingPrioritizer().prioritize(["nope", valid])  # type: ignore[list-item]
    assert len(ranked) == 1
    assert ranked[0].risk_score == 25.0


def _http_scan() -> ScanContext:
    return ScanContext(
        target=parse_target("http://10.10.10.10"),
        http_services=(
            HTTPService(
                scheme="http",
                host="10.10.10.10",
                port=80,
                base_url="http://10.10.10.10/",
                detected_service="http",
                reachable=True,
                response=HTTPResponseInfo(
                    requested_url="http://10.10.10.10/",
                    final_url="http://10.10.10.10/",
                    status_code=200,
                ),
            ),
        ),
    )


def test_engine_attaches_summary_and_risk() -> None:
    registry = PluginRegistry()
    registry.register(FindingPlugin())
    result = AssessmentEngine(registry).assess(
        AssessmentContext(scan=_http_scan())
    )
    assert result.summary.total_findings == 1
    assert result.findings[0].risk_score == 25.0
    assert result.findings[0].priority is Priority.P5


def test_plugin_failure_does_not_break_risk_engine() -> None:
    registry = PluginRegistry()
    registry.register(BoomPlugin())
    registry.register(FindingPlugin())
    result = AssessmentEngine(registry).assess(
        AssessmentContext(scan=_http_scan())
    )
    assert result.errors
    assert result.summary.total_findings == 1
    assert result.findings[0].risk_score is not None


def test_passive_and_active_findings_use_same_formula() -> None:
    header = make_finding(
        title="Missing X-Content-Type-Options Header",
        description="Header missing.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        plugin_name=SecurityHeadersPlugin.name,
        finding_type="missing-x-content-type-options",
        category="security-headers",
        target=parse_target("http://10.10.10.10"),
        affected_url="http://10.10.10.10/",
        evidence=None,
        remediation="Add the header.",
    )
    sqli = _finding(
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        plugin_name="sql-injection",
        finding_type="potential-sqli",
    )
    ranked = prioritize_findings((header, sqli))
    by_plugin = {item.plugin_name: item for item in ranked}
    assert by_plugin["security-headers"].risk_score == 25.0
    assert by_plugin["sql-injection"].risk_score == 56.25
    assert ranked[0].plugin_name == "sql-injection"


def test_scan_context_holds_summary() -> None:
    summary = build_summary(
        prioritize_findings(
            (_finding(severity=Severity.INFO, confidence=Confidence.HIGH),)
        )
    )
    context = ScanContext(
        target=parse_target("http://10.10.10.10"),
        assessment_summary=summary,
    )
    assert context.assessment_summary is not None
    assert context.assessment_summary.info == 1
    assert context.assessment_summary.risk_info == 1
