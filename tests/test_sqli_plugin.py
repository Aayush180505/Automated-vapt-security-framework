"""SQL injection detection plugin tests (mocked HTTP)."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.engine import AssessmentEngine
from vapt_framework.assessment.registry import PluginRegistry
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.enumeration.web.models import Endpoint, Parameter, WebAttackSurface
from vapt_framework.scanners.active.client import ScannerHttpClient
from vapt_framework.scanners.base import ActivePlugin
from vapt_framework.scanners.sql_injection.scanner import SQLInjectionPlugin
from vapt_framework.utils.urls import replace_query_param
from tests.conftest import query_value


def _endpoint(url: str, *names: str) -> Endpoint:
    return Endpoint(
        method="GET",
        url=url,
        path=urlparse(url).path or "/",
        parameters=tuple(
            Parameter(name=name, location="query", endpoint_url=url) for name in names
        ),
        source="crawl",
    )


def _surface(*endpoints: Endpoint) -> WebAttackSurface:
    return WebAttackSurface(
        base_url="http://10.10.10.10/",
        endpoints=endpoints,
        pages_crawled=1,
    )


def _http(handler) -> HttpClient:
    return HttpClient(
        timeout=2,
        user_agent="test",
        verify_tls=True,
        max_redirects=2,
        transport=httpx.MockTransport(handler),
    )


def _context(http: HttpClient, *endpoints: Endpoint, max_requests: int = 25) -> AssessmentContext:
    scan = ScanContext(
        target=parse_target("http://10.10.10.10"),
        web_attack_surfaces=(_surface(*endpoints),),
        http_services=(),
    )
    # reachable HTTP: applies_to needs has_reachable_http unless we fake a service
    from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService

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
        ),
    )
    scan = ScanContext(
        target=scan.target,
        web_attack_surfaces=scan.web_attack_surfaces,
        http_services=(service,),
    )
    client = ScannerHttpClient(http, ("http://10.10.10.10/",), max_requests)
    return AssessmentContext(
        scan=scan,
        settings=Settings(),
        http_client=http,
        scanner_client=client,
    )


def test_no_eligible_parameters() -> None:
    http = _http(lambda r: httpx.Response(200, text="ok"))
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/login"))
        plugin = SQLInjectionPlugin()
        assert plugin.applies_to(ctx) is False
        assert plugin.check(ctx) == []
    finally:
        http.close()


def test_mysql_error_detection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        if q == "'":
            return httpx.Response(
                200,
                text="You have an error in your SQL syntax near '''",
            )
        return httpx.Response(200, text="results for test")

    http = _http(handler)
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        findings = SQLInjectionPlugin().check(ctx)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Potential SQL Injection"
        assert finding.parameter == "q"
        assert finding.affected_url.endswith("/search?q=test") or "search" in (
            finding.affected_url or ""
        )
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.MEDIUM
        assert finding.evidence is not None
        assert "sql syntax" in (finding.evidence.excerpt or "").lower()
    finally:
        http.close()


@pytest.mark.parametrize(
    "error",
    [
        "unterminated quoted string at or near",
        "Unclosed quotation mark after the character string",
        "ORA-01756: quoted string not properly terminated",
        "sqlite3.OperationalError: unrecognized token",
    ],
)
def test_other_database_errors(error: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        if "'" in q:
            return httpx.Response(200, text=error)
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        assert SQLInjectionPlugin().check(ctx)
    finally:
        http.close()


def test_no_sql_error_and_false_positive_status_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        if q == "'":
            return httpx.Response(500, text="internal error")
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        assert SQLInjectionPlugin().check(ctx) == []
    finally:
        http.close()


def test_error_already_in_baseline_ignored() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="You have an error in your SQL syntax always"
        )

    http = _http(handler)
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        assert SQLInjectionPlugin().check(ctx) == []
    finally:
        http.close()


def test_multiple_parameters_and_dedup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if query_value(request, "q") == "'":
            return httpx.Response(
                200, text="You have an error in your SQL syntax"
            )
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _context(
            http,
            _endpoint("http://10.10.10.10/search?q=test&page=2", "q", "page"),
        )
        findings = SQLInjectionPlugin().check(ctx)
        names = [item.parameter for item in findings]
        assert names.count("q") == 1
        assert "page" not in names
    finally:
        http.close()


def test_request_limit_stops_sqli() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _context(
            http,
            _endpoint("http://10.10.10.10/a?q=1", "q"),
            _endpoint("http://10.10.10.10/b?q=1", "q"),
            _endpoint("http://10.10.10.10/c?q=1", "q"),
            max_requests=2,
        )
        SQLInjectionPlugin().check(ctx)
        assert len(calls) <= 2
    finally:
        http.close()


def test_timeout_does_not_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    http = _http(handler)
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        assert SQLInjectionPlugin().check(ctx) == []
    finally:
        http.close()


def test_plugin_failure_isolation() -> None:
    class Boom(ActivePlugin):
        name = "boom-active"
        description = "boom"
        is_active = True

        def check(self, context):
            raise RuntimeError("boom")

    registry = PluginRegistry()
    registry.register(SQLInjectionPlugin())
    registry.register(Boom())
    http = _http(lambda r: httpx.Response(200, text="ok"))
    try:
        ctx = _context(http, _endpoint("http://10.10.10.10/search?q=test", "q"))
        result = AssessmentEngine(registry).assess(ctx)
        assert any("boom" in err for err in result.errors)
        assert "sql-injection" in result.executed_plugins
    finally:
        http.close()


def test_replace_keeps_other_params() -> None:
    url = replace_query_param("http://10.10.10.10/search?q=test&page=2", "q", "'")
    assert url is not None
    assert "page=2" in url
    assert "q=" in url
