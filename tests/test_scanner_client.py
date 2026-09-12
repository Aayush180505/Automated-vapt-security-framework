"""ScannerHttpClient tests (mocked HTTP, no network)."""

from __future__ import annotations

import httpx
import pytest

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.scanners.active.client import ScannerHttpClient
from vapt_framework.scanners.headers.scanner import SecurityHeadersPlugin
from vapt_framework.scanners.sql_injection.scanner import SQLInjectionPlugin


def _client(handler) -> HttpClient:
    return HttpClient(
        timeout=2,
        user_agent="test",
        verify_tls=True,
        max_redirects=3,
        transport=httpx.MockTransport(handler),
    )


def test_request_limit() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="ok")

    http = _client(handler)
    try:
        scanner = ScannerHttpClient(
            http, ("http://10.10.10.10/",), max_requests=5
        )
        for _ in range(8):
            scanner.get(
                "http://10.10.10.10/search?q=test",
                plugin="sql-injection",
                parameter="q",
            )
        assert len(calls) == 5
        assert scanner.request_count == 5
        assert scanner.limit_reached
    finally:
        http.close()


def test_scope_rejects_external_and_other_port() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="ok")

    http = _client(handler)
    try:
        scanner = ScannerHttpClient(
            http, ("http://10.10.10.10/",), max_requests=10
        )
        assert (
            scanner.get(
                "http://external.example/search?q=test",
                plugin="sql-injection",
                parameter="q",
            )
            is None
        )
        assert (
            scanner.get(
                "http://10.10.10.10:8080/search?q=test",
                plugin="sql-injection",
                parameter="q",
            )
            is None
        )
        assert calls == []
        in_scope = scanner.get(
            "http://10.10.10.10/search?q=test",
            plugin="sql-injection",
            parameter="q",
        )
        assert in_scope is not None
        assert len(calls) == 1
    finally:
        http.close()


def test_out_of_scope_redirect_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/leave":
            return httpx.Response(
                302, headers={"Location": "http://external.example/out"}
            )
        return httpx.Response(200, text="ok")

    http = _client(handler)
    try:
        scanner = ScannerHttpClient(
            http, ("http://10.10.10.10/",), max_requests=10
        )
        response = scanner.get(
            "http://10.10.10.10/leave",
            plugin="sql-injection",
            parameter="q",
        )
        assert response is not None
        assert response.status_code == 302
        assert all("external.example" not in url for url in calls)
        assert scanner.request_count == 1
    finally:
        http.close()


def test_timeout_surfaces_as_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    http = _client(handler)
    try:
        scanner = ScannerHttpClient(
            http, ("http://10.10.10.10/",), max_requests=5
        )
        with pytest.raises(HTTPProbeError):
            scanner.get(
                "http://10.10.10.10/",
                plugin="sql-injection",
                parameter="q",
            )
    finally:
        http.close()


def test_active_vs_passive_flags() -> None:
    assert SecurityHeadersPlugin().is_active is False
    assert SQLInjectionPlugin().is_active is True
