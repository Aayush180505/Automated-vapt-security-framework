"""Path traversal detection plugin tests (mocked HTTP)."""

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
from vapt_framework.scanners.path_traversal.scanner import PathTraversalPlugin
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
    return AssessmentContext(
        scan=ScanContext(
            target=parse_target("http://10.10.10.10"),
            http_services=(service,),
            web_attack_surfaces=(
                WebAttackSurface(
                    base_url="http://10.10.10.10/",
                    endpoints=(endpoint,),
                ),
            ),
        ),
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


def test_no_eligible_path_parameters() -> None:
    http = _http(lambda r: httpx.Response(200, text="ok"))
    try:
        ctx = _ctx(http, "http://10.10.10.10/search?q=test", "q")
        plugin = PathTraversalPlugin()
        assert plugin.applies_to(ctx) is False
    finally:
        http.close()


def test_path_parameter_with_indicator() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        value = query_value(request, "file")
        if ".." in value:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
        return httpx.Response(200, text="file contents")

    http = _http(handler)
    try:
        findings = PathTraversalPlugin().check(
            _ctx(http, "http://10.10.10.10/download?file=test.txt", "file")
        )
        assert len(findings) == 1
        assert findings[0].title == "Potential Path Traversal"
        assert findings[0].parameter == "file"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].confidence is Confidence.MEDIUM
        assert findings[0].evidence is not None
        assert "root:x:0:0" in (findings[0].evidence.excerpt or "")
    finally:
        http.close()


def test_filename_parameter_is_eligible() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        value = query_value(request, "filename")
        if ".." in value:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        ctx = _ctx(http, "http://10.10.10.10/view?filename=about.html", "filename")
        assert PathTraversalPlugin().applies_to(ctx) is True
        assert PathTraversalPlugin().check(ctx)
    finally:
        http.close()


def test_path_timeout_does_not_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    http = _http(handler)
    try:
        assert (
            PathTraversalPlugin().check(
                _ctx(http, "http://10.10.10.10/download?file=test.txt", "file")
            )
            == []
        )
    finally:
        http.close()


def test_no_indicator_or_baseline_match() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not found")

    http = _http(handler)
    try:
        assert (
            PathTraversalPlugin().check(
                _ctx(http, "http://10.10.10.10/download?file=test.txt", "file")
            )
            == []
        )
    finally:
        http.close()

    def always_root(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="root:x:0:0 always")

    http = _http(always_root)
    try:
        assert (
            PathTraversalPlugin().check(
                _ctx(http, "http://10.10.10.10/download?file=test.txt", "file")
            )
            == []
        )
    finally:
        http.close()


def test_path_request_limit() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append("x")
        return httpx.Response(200, text="ok")

    http = _http(handler)
    try:
        PathTraversalPlugin().check(
            _ctx(
                http,
                "http://10.10.10.10/download?file=a.txt",
                "file",
                max_requests=1,
            )
        )
        assert len(calls) == 1
    finally:
        http.close()
