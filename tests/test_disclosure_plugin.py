"""Information-disclosure plugin tests (no network)."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.scanners.information_disclosure.scanner import (
    InformationDisclosurePlugin,
)


def _context(headers: dict[str, str]) -> AssessmentContext:
    service = HTTPService(
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
            headers=headers,
            server=headers.get("server"),
        ),
    )
    return AssessmentContext(
        scan=ScanContext(
            target=parse_target("http://10.10.10.10"),
            http_services=(service,),
        )
    )


def test_server_version_disclosure() -> None:
    findings = InformationDisclosurePlugin().check(
        _context({"server": "Apache/2.4.57"})
    )
    assert len(findings) == 1
    assert findings[0].title == "Web Server Version Disclosure"
    assert findings[0].severity is Severity.INFO
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].evidence is not None
    assert "Apache/2.4.57" in findings[0].evidence.description
    assert findings[0].affected_url == "http://10.10.10.10/"


def test_x_powered_by_disclosure() -> None:
    findings = InformationDisclosurePlugin().check(
        _context({"x-powered-by": "PHP/8.2"})
    )
    assert any(item.finding_type == "x-powered-by" for item in findings)
    assert all(item.severity is Severity.INFO for item in findings)


def test_no_disclosure() -> None:
    findings = InformationDisclosurePlugin().check(_context({"server": "Apache"}))
    assert findings == []


def test_multiple_disclosure_headers() -> None:
    findings = InformationDisclosurePlugin().check(
        _context({"server": "Apache/2.4.57", "x-powered-by": "PHP/8.2"})
    )
    types = {item.finding_type for item in findings}
    assert types == {"server-version", "x-powered-by"}
    assert all(item.evidence is not None for item in findings)
