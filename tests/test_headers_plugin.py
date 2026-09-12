"""Security-headers plugin tests (no network)."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.scanners.headers.scanner import SecurityHeadersPlugin

_COMPLETE = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "x-frame-options": "DENY",
}


def _context(*services: HTTPService) -> AssessmentContext:
    return AssessmentContext(
        scan=ScanContext(
            target=parse_target("http://10.10.10.10"),
            http_services=services,
        )
    )


def _service(
    url: str,
    scheme: str,
    headers: dict[str, str],
    port: int | None = None,
) -> HTTPService:
    host = "10.10.10.10"
    return HTTPService(
        scheme=scheme,
        host=host,
        port=port or (443 if scheme == "https" else 80),
        base_url=url,
        detected_service=scheme,
        reachable=True,
        response=HTTPResponseInfo(
            requested_url=url,
            final_url=url,
            status_code=200,
            headers=headers,
        ),
    )


def test_all_required_headers_present() -> None:
    plugin = SecurityHeadersPlugin()
    http = _service("http://10.10.10.10/", "http", _COMPLETE)
    findings = plugin.check(_context(http))
    assert findings == []


def test_one_missing_header() -> None:
    headers = dict(_COMPLETE)
    del headers["x-content-type-options"]
    findings = SecurityHeadersPlugin().check(
        _context(_service("http://10.10.10.10/", "http", headers))
    )
    assert len(findings) == 1
    assert findings[0].title == "Missing X-Content-Type-Options Header"
    assert findings[0].severity is Severity.LOW
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].affected_url == "http://10.10.10.10/"
    assert findings[0].evidence is not None
    assert "x-content-type-options" in findings[0].evidence.description.lower()


def test_multiple_missing_headers() -> None:
    findings = SecurityHeadersPlugin().check(
        _context(_service("http://10.10.10.10/", "http", {"server": "Apache"}))
    )
    types = {item.finding_type for item in findings}
    assert "missing-x-content-type-options" in types
    assert "missing-csp" in types
    assert "missing-referrer-policy" in types
    assert "missing-hsts" not in types


def test_header_present_is_not_reported() -> None:
    headers = dict(_COMPLETE)
    findings = SecurityHeadersPlugin().check(
        _context(_service("http://10.10.10.10/", "http", headers))
    )
    assert all("x-frame-options" not in item.finding_type for item in findings)


def test_hsts_only_for_https() -> None:
    https = _service("https://10.10.10.10/", "https", {"x-content-type-options": "nosniff"})
    types = {item.finding_type for item in SecurityHeadersPlugin().check(_context(https))}
    assert "missing-hsts" in types


def test_multiple_http_services_keep_separate_urls() -> None:
    http = _service("http://10.10.10.10/", "http", {})
    https = _service("https://10.10.10.10/", "https", {})
    findings = SecurityHeadersPlugin().check(_context(http, https))
    urls = {item.affected_url for item in findings}
    assert "http://10.10.10.10/" in urls
    assert "https://10.10.10.10/" in urls
