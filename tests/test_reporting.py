"""Reporting tests. No network, Nmap, or MySQL."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from vapt_framework.assessment.summary import AssessmentSummary
from vapt_framework.cli.main import main
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import Confidence, Priority, ScanStatus, Severity
from vapt_framework.core.exceptions import ReportError
from vapt_framework.core.models import Evidence, Finding, ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.reporting.builder import report_data_from_context, report_data_from_details
from vapt_framework.reporting.filenames import html_report_filename, safe_scan_token
from vapt_framework.reporting.renderer import render_html
from vapt_framework.reporting.service import ReportService
from vapt_framework.storage.models import ScanDetails, StoredFinding, StoredService


def _stored_finding(**overrides: object) -> StoredFinding:
    values = dict(
        title="Potential SQL Injection",
        scanner="sql-injection",
        severity="high",
        confidence="medium",
        affected_url="http://10.10.10.10/search?q=test",
        parameter="q",
        risk_score=56.25,
        risk_band="medium",
        priority="p3",
        explanation="High severity finding with medium confidence.",
        fingerprint="sql-injection|potential-sqli|http://10.10.10.10/search?q=test|q",
        category="injection",
        description="Error signature after a syntax probe.",
        remediation="Use parameterized queries.",
        evidence_description="mysql error",
        evidence_url="http://10.10.10.10/search?q=test",
        evidence_method="GET",
        evidence_status_code=200,
        evidence_excerpt="You have an error in your SQL syntax",
    )
    values.update(overrides)
    return StoredFinding(**values)  # type: ignore[arg-type]


def _details(**overrides: object) -> ScanDetails:
    values = dict(
        scan_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        target="http://10.10.10.10",
        status="completed",
        started_at=datetime(2026, 9, 13, 21, 10),
        completed_at=datetime(2026, 9, 13, 21, 12),
        total_findings=1,
        average_risk=56.25,
        maximum_risk=56.25,
        highest_risk_band="medium",
        services=(
            StoredService(
                host="10.10.10.10",
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="Apache",
                version="2.4",
            ),
        ),
        findings=(_stored_finding(),),
        scheme="http",
        hostname="10.10.10.10",
        ip_address="10.10.10.10",
        port=80,
    )
    values.update(overrides)
    return ScanDetails(**values)  # type: ignore[arg-type]


def test_report_data_preserves_risk_and_order() -> None:
    first = _stored_finding()
    second = _stored_finding(
        title="Potential Reflected XSS",
        scanner="reflected-xss",
        severity="medium",
        risk_score=37.5,
        risk_band="low",
        priority="p4",
        fingerprint="xss|1",
    )
    data = report_data_from_details(
        _details(findings=(first, second), total_findings=2)
    )
    assert data.scan_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert data.target == "http://10.10.10.10"
    assert [item.title for item in data.findings] == [
        "Potential SQL Injection",
        "Potential Reflected XSS",
    ]
    assert data.findings[0].risk_score == 56.25
    assert data.findings[0].severity == "high"
    assert data.findings[0].confidence == "medium"
    assert data.findings[0].evidence_excerpt == "You have an error in your SQL syntax"
    assert data.attack_surface_persisted is False
    assert data.critical_high_count == 1


def test_empty_and_failed_reports() -> None:
    empty = report_data_from_details(
        _details(findings=(), total_findings=0, services=(), average_risk=0, maximum_risk=0)
    )
    assert empty.findings == ()
    assert empty.highest_severity is None
    failed = report_data_from_details(_details(status="failed"))
    assert failed.status == "failed"


def test_missing_remediation_placeholder() -> None:
    data = report_data_from_details(
        _details(findings=(_stored_finding(remediation=None),))
    )
    html = render_html(data)
    assert "Remediation guidance not available." in html


def test_html_escaping() -> None:
    payload = "<script>alert(1)</script>"
    data = report_data_from_details(
        _details(
            target=payload,
            hostname=payload,
            findings=(
                _stored_finding(
                    title=payload,
                    affected_url=payload,
                    parameter=payload,
                    evidence_excerpt=payload,
                    description=payload,
                ),
            ),
        )
    )
    html = render_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_secrets_not_in_template_output() -> None:
    data = report_data_from_details(_details())
    html = render_html(data)
    assert "Set-Cookie" not in html
    assert "Authorization" not in html
    assert "session=" not in html.lower() or "session=" not in html
    assert "password" not in html.lower() or "password" in "authorized"


def test_safe_filename() -> None:
    assert html_report_filename("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").startswith(
        "vapt_report_"
    )
    assert ".." not in html_report_filename("../etc/passwd")
    assert "/" not in safe_scan_token("a/b")
    assert html_report_filename("http://evil.example") == "vapt_report_httpevilexample.html"


def test_write_html(tmp_path: Path) -> None:
    settings = Settings(report_directory=str(tmp_path))
    path = ReportService(settings).write_from_details(_details())
    assert path.exists()
    assert path.parent == tmp_path
    text = path.read_text(encoding="utf-8")
    assert "Automated VAPT Security Assessment Report" in text
    assert "Potential SQL Injection" in text
    assert "56.25" in text


def test_report_from_context_copies_scores() -> None:
    finding = Finding(
        title="Example",
        description="desc",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        plugin_name="finder",
        fingerprint="finder|x|http://10.10.10.10/|",
        category="test",
        finding_type="x",
        target=parse_target("http://10.10.10.10"),
        affected_url="http://10.10.10.10/",
        risk_score=75.0,
        risk_band=Severity.HIGH,
        priority=Priority.P2,
    )
    context = ScanContext(
        target=parse_target("http://10.10.10.10"),
        scan_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        status=ScanStatus.COMPLETED,
        findings=(finding,),
        assessment_summary=AssessmentSummary(
            total_findings=1, high=1, average_risk=75.0, maximum_risk=75.0
        ),
    )
    data = report_data_from_context(context)
    assert data.findings[0].risk_score == 75.0
    assert data.findings[0].severity == "high"


def test_missing_scan_id(tmp_path: Path) -> None:
    class Store:
        def get_scan(self, scan_id: str):
            return None

    settings = Settings(report_directory=str(tmp_path))
    with pytest.raises(ReportError, match="Scan not found"):
        ReportService(settings).write_from_scan_id("missing", Store())  # type: ignore[arg-type]


def test_cli_report_help(capsys) -> None:
    assert main(["report", "--help"]) == 0
    output = capsys.readouterr().out.lower()
    assert "scan_id" in output or "scan" in output


def test_cli_report_success(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("VAPT_REPORT_DIR", str(tmp_path))

    class Store:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_scan(self, scan_id: str):
            return _details(scan_id=scan_id)

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings",
        lambda settings: Store(),
    )
    code = main(["report", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Report generated successfully" in output
    assert "vapt_report_" in output


def test_cli_report_invalid_id(monkeypatch, capsys) -> None:
    class Store:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_scan(self, scan_id: str):
            return None

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings",
        lambda settings: Store(),
    )
    code = main(["report", "not-found"])
    assert code == 2
    assert "Scan not found" in capsys.readouterr().err


def test_cli_report_database_unavailable(monkeypatch, capsys) -> None:
    from vapt_framework.core.exceptions import DatabaseConnectionError

    def boom(settings):
        raise DatabaseConnectionError(
            "Could not connect to MySQL. "
            "Check VAPT_DB_HOST, VAPT_DB_PORT, VAPT_DB_USER, and VAPT_DB_PASSWORD."
        )

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings", boom
    )
    code = main(["report", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    assert code == 2
    assert "Could not connect to MySQL" in capsys.readouterr().err
