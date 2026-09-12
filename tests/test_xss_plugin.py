"""Reflected XSS detection plugin tests (no JavaScript execution)."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.enumeration.web.models import Endpoint, Parameter, WebAttackSurface
from vapt_framework.scanners.active.client import ScannerHttpClient
from vapt_framework.scanners.xss.scanner import MARKER, ReflectedXSSPlugin
from tests.conftest import query_value


def _ctx(http: HttpClient, url: str, *names: str, max_requests: int = 25) -> AssessmentContext:
    endpoint = Endpoint(
        method="GET",
        url=url,
        path=urlparse(url).path or "/",
        parameters=tuple(
            Parameter(name=n, location="query", endpoint_url=url) for n in names
        ),
        source="crawl",
    )
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
        target=parse_target("http://10.10.10.10"),
        http_services=(service,),
        web_attack_surfaces=(
            WebAttackSurface(
                base_url="http://10.10.10.10/",
                endpoints=(endpoint,),
            ),
        ),
    )
    return AssessmentContext(
        scan=scan,
        settings=Settings(),
        http_client=http,
        scanner_client=ScannerHttpClient(
            http, ("http://10.10.10.10/",), max_requests
        ),
    )


def _http(handler) -> HttpClient:
    return HttpClient(
        timeout=2,
        user_agent="test",
        verify_tls=True,
        max_redirects=2,
        transport=httpx.MockTransport(handler),
    )


def test_xss_no_eligible_parameters() -> None:
    http = _http(lambda r: httpx.Response(200, text="ok"))
    try:
        ctx = _ctx(http, "http://10.10.10.10/about")
        plugin = ReflectedXSSPlugin()
        assert plugin.applies_to(ctx) is False
    finally:
        http.close()


def test_marker_not_reflected() -> None:
    http = _http(lambda r: httpx.Response(200, text="<html>hello</html>", headers={"content-type": "text/html"}))
    try:
        ctx = _ctx(http, "http://10.10.10.10/search?q=test", "q")
        assert ReflectedXSSPlugin().check(ctx) == []
    finally:
        http.close()


def test_html_text_reflection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        body = f"<html><body>Results {q}</body></html>"
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    http = _http(handler)
    try:
        findings = ReflectedXSSPlugin().check(
            _ctx(http, "http://10.10.10.10/search?q=test", "q")
        )
        assert len(findings) == 1
        assert findings[0].title == "Potential Reflected XSS"
        assert findings[0].parameter == "q"
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].confidence is Confidence.MEDIUM
        assert findings[0].evidence is not None
        assert MARKER in (findings[0].evidence.excerpt or "")
        assert "html-text" in findings[0].evidence.description
    finally:
        http.close()


def test_html_attribute_reflection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        body = f'<html><input value="{q}"></html>'
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    http = _http(handler)
    try:
        findings = ReflectedXSSPlugin().check(
            _ctx(http, "http://10.10.10.10/search?q=test", "q")
        )
        assert findings
        assert "html-attribute" in (findings[0].evidence.description if findings[0].evidence else "")
    finally:
        http.close()


def test_xss_timeout_does_not_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    http = _http(handler)
    try:
        assert (
            ReflectedXSSPlugin().check(
                _ctx(http, "http://10.10.10.10/search?q=test", "q")
            )
            == []
        )
    finally:
        http.close()


def test_xss_duplicate_findings_deduped() -> None:
    from vapt_framework.assessment.engine import AssessmentEngine
    from vapt_framework.assessment.registry import PluginRegistry
    from vapt_framework.findings.deduplicator import deduplicate_findings

    def handler(request: httpx.Request) -> httpx.Response:
        q = query_value(request, "q")
        body = f"<html><body>{q}</body></html>"
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    http = _http(handler)
    try:
        ctx = _ctx(http, "http://10.10.10.10/search?q=test", "q")
        plugin = ReflectedXSSPlugin()
        first = plugin.check(ctx)
        second = plugin.check(ctx)
        unique = deduplicate_findings(first + second)
        assert len(first) == 1
        assert len(unique) == 1
        registry = PluginRegistry()
        registry.register(plugin)
        result = AssessmentEngine(registry).assess(ctx)
        assert len(result.findings) <= 1
    finally:
        http.close()


def test_external_link_not_tested() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url.host))
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        endpoint = Endpoint(
            method="GET",
            url="http://evil.example/search?q=test",
            path="/search",
            parameters=(Parameter(name="q", location="query"),),
            source="crawl",
        )
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
            target=parse_target("http://10.10.10.10"),
            http_services=(service,),
            web_attack_surfaces=(
                WebAttackSurface(base_url="http://10.10.10.10/", endpoints=(endpoint,)),
            ),
        )
        ctx = AssessmentContext(
            scan=scan,
            settings=Settings(),
            http_client=http,
            scanner_client=ScannerHttpClient(
                http, ("http://10.10.10.10/",), 10
            ),
        )
        assert ReflectedXSSPlugin().check(ctx) == []
        assert "evil.example" not in "".join(calls)
    finally:
        http.close()


def test_xss_request_limit() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append("x")
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _ctx(
            http,
            "http://10.10.10.10/search?q=test&page=2",
            "q",
            "page",
            max_requests=1,
        )
        ReflectedXSSPlugin().check(ctx)
        assert len(calls) == 1
    finally:
        http.close()
