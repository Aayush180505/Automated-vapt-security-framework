"""CLI tests. Commands must not perform network requests or real Nmap scans."""

from __future__ import annotations

import pytest

from vapt_framework import __version__
from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.cli.main import main
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.exceptions import NmapNotFoundError
from vapt_framework.core.models import Evidence, Finding, ScanContext
from vapt_framework.enumeration.web.models import Endpoint, Parameter, WebAttackSurface
from tests.conftest import fixture_text


def _context(
    target,
    discovery,
    http_services=(),
    surfaces=(),
    findings=(),
    errors=(),
    executed=(),
    skipped=(),
    active_requests=0,
):
    return ScanContext(
        target=target,
        discovery_results=discovery,
        http_services=http_services,
        web_attack_surfaces=surfaces,
        findings=findings,
        assessment_errors=errors,
        executed_plugins=executed,
        skipped_plugins=skipped,
        active_requests=active_requests,
    )


@pytest.fixture
def fake_discovery(monkeypatch: pytest.MonkeyPatch):
    result = parse_nmap_xml(fixture_text("nmap_single_host.xml"))

    def fake_run(target, settings):
        return _context(target, result)

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    return result


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "scan" in output
    assert "version" in output


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_scan_validates_http_target(
    fake_discovery, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["scan", "--target", "http://10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "authorized" in output.lower()
    assert "http://10.10.10.10" in output
    assert "Reconnaissance complete." in output
    assert "Database persistence" in output
    assert "disabled" in output


def test_scan_validates_bare_ip(
    fake_discovery, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    assert "10.10.10.10" in capsys.readouterr().out


def test_scan_rejects_invalid_target(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--target", "ftp://example.local"])
    assert code == 2
    err = capsys.readouterr().err
    assert "Error: Invalid target:" in err


def test_scan_requires_target() -> None:
    assert main(["scan"]) == 2


def test_cli_nmap_not_installed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> str:
        raise NmapNotFoundError(
            "Nmap was not found on PATH. "
            "Please install Nmap and ensure the executable is available."
        )

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", missing)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 2
    err = capsys.readouterr().err
    assert "Nmap was not found on PATH" in err


def test_cli_service_discovery_summary(
    fake_discovery, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Discovered Services" in output
    assert "22/tcp" in output
    assert "ssh" in output
    assert "OpenSSH" in output
    assert "80/tcp" in output
    assert "3306/tcp" in output
    assert "ftp" in output


def test_cli_no_open_ports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = parse_nmap_xml(fixture_text("nmap_empty.xml"))

    def fake_run(target, settings):
        return _context(target, empty)

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    assert "No open TCP ports were discovered." in capsys.readouterr().out


def test_cli_http_and_surface_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    http_service = HTTPService(
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
            content_type="text/html",
            server="Apache",
            title="Example Application",
        ),
    )
    surface = WebAttackSurface(
        base_url="http://10.10.10.10/",
        endpoints=(
            Endpoint(
                method="GET",
                url="http://10.10.10.10/",
                path="/",
                parameters=(),
                source="crawl",
            ),
            Endpoint(
                method="GET",
                url="http://10.10.10.10/search?q=test",
                path="/search",
                parameters=(
                    Parameter(name="q", location="query", endpoint_url="http://10.10.10.10/search?q=test"),
                ),
                source="crawl",
            ),
        ),
        forms=(),
        parameters=(Parameter(name="q", location="query"),),
        pages_crawled=2,
        external_references=("https://google.com/external",),
    )

    def fake_run(target, settings):
        return _context(target, discovery, (http_service,), (surface,))

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "HTTP Services" in output
    assert "Example Application" in output
    assert "Apache" in output
    assert "Web Attack Surface" in output
    assert "Pages discovered: 2" in output
    assert "GET  /search?q=test" in output or "GET  /search?q=test" in output.replace(
        "http://10.10.10.10", ""
    )


def test_cli_graceful_http_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    failed = HTTPService(
        scheme="https",
        host="10.10.10.10",
        port=443,
        base_url="https://10.10.10.10/",
        detected_service="https",
        reachable=False,
        error="HTTP connection failed.",
    )

    def fake_run(target, settings):
        return _context(target, discovery, (failed,), ())

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "unreachable" in output
    assert "22/tcp" in output


def test_cli_findings_and_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    finding = Finding(
        title="Missing X-Content-Type-Options Header",
        description="Header missing.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        plugin_name="security-headers",
        fingerprint="security-headers|missing-x-content-type-options|http://10.10.10.10/|",
        category="security-headers",
        finding_type="missing-x-content-type-options",
        target=None,
        affected_url="http://10.10.10.10/",
        evidence=Evidence(description="absent", url="http://10.10.10.10/"),
        remediation="Add the header.",
    )
    info = Finding(
        title="Web Server Version Disclosure",
        description="Server header.",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        plugin_name="information-disclosure",
        fingerprint="information-disclosure|server-version|http://10.10.10.10/|",
        category="information-disclosure",
        finding_type="server-version",
        affected_url="http://10.10.10.10/",
        evidence=Evidence(description="Server: Apache/2.4.57"),
        remediation="Reduce disclosure.",
    )

    def fake_run(target, settings):
        return _context(target, discovery, findings=(finding, info))

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Security Assessment" in output
    assert "Findings: 2" in output
    assert "[LOW] Missing X-Content-Type-Options Header" in output
    assert "[INFO] Web Server Version Disclosure" in output
    assert "Low:      1" in output
    assert "Info:     1" in output
    assert "Scanner errors: 0" in output
    assert "Risk Assessment" in output
    assert "Priority:" in output
    assert "Average risk score:" in output
    assert "Reason:" in output
    assert "Low severity finding with high confidence." in output


def test_cli_active_findings_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    sqli = Finding(
        title="Potential SQL Injection",
        description="Error signature.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        plugin_name="sql-injection",
        fingerprint="sql-injection|potential-sqli|http://10.10.10.10/search?q=test|q",
        category="injection",
        finding_type="potential-sqli",
        affected_url="http://10.10.10.10/search?q=test",
        parameter="q",
        evidence=Evidence(description="mysql error"),
        remediation="Use parameterized queries.",
    )

    def fake_run(target, settings):
        return _context(
            target,
            discovery,
            findings=(sqli,),
            executed=(
                "security-headers",
                "information-disclosure",
                "sql-injection",
                "reflected-xss",
                "path-traversal",
            ),
            skipped=(),
            active_requests=12,
        )

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Passive checks:" in output
    assert "security-headers" in output
    assert "Active checks:" in output
    assert "sql-injection" in output
    assert "[HIGH] Potential SQL Injection" in output
    assert "Parameter: q" in output
    assert "Scanner: sql-injection" in output
    assert "Plugins executed: 5" in output
    assert "Active requests: 12" in output
    assert "Findings: 1" in output
    assert "authorized" in output.lower()
    assert "Risk: 56.25" in output
    assert "Priority: P3" in output
    assert "High severity finding with medium confidence." in output
    assert "75.0 × 0.75 = 56.25" in output


def test_cli_no_findings_message(fake_discovery, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "No security findings were identified" in output
    assert "does NOT mean the target is secure" in output
    assert "No findings available for risk scoring." in output


def test_cli_plugin_failure_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))

    def fake_run(target, settings):
        return _context(
            target,
            discovery,
            errors=("information-disclosure: plugin exploded",),
        )

    monkeypatch.setattr("vapt_framework.cli.main.require_nmap", lambda: "nmap")
    monkeypatch.setattr("vapt_framework.cli.main.run_scan", fake_run)
    code = main(["scan", "--target", "10.10.10.10"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Plugin errors:" in output
    assert "information-disclosure: plugin exploded" in output
