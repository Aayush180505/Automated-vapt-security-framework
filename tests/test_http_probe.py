"""HTTP client and probe tests using MockTransport (no network)."""

from __future__ import annotations

import pytest

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.adapters.http.probe import probe_http_service
from vapt_framework.core.exceptions import HTTPProbeError
from tests.conftest import lab_client


def test_http_probe_success() -> None:
    client = lab_client()
    try:
        service = HTTPService(
            scheme="http",
            host="10.10.10.10",
            port=80,
            base_url="http://10.10.10.10/",
            detected_service="http",
            reachable=False,
        )
        probed = probe_http_service(client, service)
        assert probed.reachable
        assert probed.response is not None
        assert probed.response.status_code == 200
        assert probed.response.server == "Apache"
        assert probed.response.content_type is not None
        assert "html" in probed.response.content_type
        assert probed.response.title == "Example Application"
        assert probed.response.body is None
        assert "sessionid" in probed.response.cookie_names
        assert probed.response.headers.get("set-cookie") is None
    finally:
        client.close()


def test_https_service_uses_https_url() -> None:
    service = HTTPService(
        scheme="https",
        host="10.10.10.10",
        port=443,
        base_url="https://10.10.10.10/",
        detected_service="https",
        reachable=True,
    )
    assert service.base_url.startswith("https://")


def test_http_probe_connect_failure() -> None:
    client = lab_client()
    try:
        service = HTTPService(
            scheme="http",
            host="10.10.10.10",
            port=80,
            base_url="http://10.10.10.10/down",
            detected_service="http",
            reachable=False,
        )
        probed = probe_http_service(client, service)
        assert not probed.reachable
        assert probed.error is not None
    finally:
        client.close()


def test_http_timeout() -> None:
    client = lab_client()
    try:
        with pytest.raises(HTTPProbeError, match="timed out"):
            client.request("GET", "http://10.10.10.10/timeout")
    finally:
        client.close()


def test_redirect_handling() -> None:
    client = lab_client()
    try:
        info = client.request(
            "GET",
            "http://10.10.10.10/redirect",
            follow_redirects=True,
            include_body=True,
        )
        assert info.status_code == 200
        assert info.redirect_chain[-1].endswith("/login")
        assert info.final_url.endswith("/login")
    finally:
        client.close()


def test_head_fallback_to_get() -> None:
    client = lab_client()
    try:
        service = HTTPService(
            scheme="http",
            host="10.10.10.10",
            port=80,
            base_url="http://10.10.10.10/head-only",
            detected_service="http",
            reachable=False,
        )
        probed = probe_http_service(client, service)
        assert probed.reachable
        assert probed.response is not None
        assert probed.response.title == "Head Fallback"
    finally:
        client.close()


def test_response_metadata_and_title() -> None:
    client = lab_client()
    try:
        info = client.request(
            "GET",
            "http://10.10.10.10/",
            include_body=True,
        )
        assert info.status_code == 200
        assert info.title == "Example Application"
        assert info.content_type is not None
        assert info.server == "Apache"
        assert info.elapsed_ms is not None
    finally:
        client.close()


def test_http_client_uses_configured_user_agent() -> None:
    captured: list[str] = []

    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, text="ok")

    client = HttpClient(
        timeout=2,
        user_agent="VAPT-Framework/0.1 (+authorized-assessment)",
        verify_tls=True,
        max_redirects=2,
        transport=httpx.MockTransport(handler),
    )
    try:
        client.request("GET", "http://10.10.10.10/")
    finally:
        client.close()
    assert captured == ["VAPT-Framework/0.1 (+authorized-assessment)"]
