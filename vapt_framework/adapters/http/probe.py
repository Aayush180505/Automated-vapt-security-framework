"""Identify HTTP/HTTPS services from Nmap results and probe them."""

from __future__ import annotations

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.adapters.nmap.models import NmapScanResult, PortResult
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.core.target import Target
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import normalize_url

logger = get_logger("vapt_framework.adapters.http.probe")

_HEAD_FALLBACK = frozenset({405, 501})


def detect_http_candidates(
    discovery: NmapScanResult,
    target: Target,
) -> tuple[HTTPService, ...]:
    """Return unique HTTP(S) candidates from Nmap, plus an explicit HTTP target URL."""
    found: dict[str, HTTPService] = {}
    for host in discovery.hosts:
        for port in host.ports:
            if port.state != "open" or port.protocol.lower() != "tcp":
                continue
            if not _nmap_indicates_http(port):
                continue
            scheme = _scheme_for_port(port)
            service = _candidate(
                scheme=scheme,
                host=host.address or target.hostname,
                port=port.number,
                detected=port.service_name,
            )
            found[service.base_url] = service

    if target.scheme in {"http", "https"}:
        port = target.port or (443 if target.scheme == "https" else 80)
        service = _candidate(
            scheme=target.scheme,
            host=target.hostname,
            port=port,
            detected=target.scheme,
        )
        found.setdefault(service.base_url, service)

    return tuple(sorted(found.values(), key=lambda item: item.base_url))


def probe_http_service(client: HttpClient, service: HTTPService) -> HTTPService:
    """HEAD (then GET if needed). Records failures without raising to the caller."""
    logger.info("HTTP probe started: %s", service.base_url)
    try:
        response = client.request(
            "HEAD",
            service.base_url,
            follow_redirects=True,
            include_body=False,
        )
        needs_get = response.status_code in _HEAD_FALLBACK or _should_get_body(
            response.content_type
        )
        if needs_get:
            response = client.request(
                "GET",
                service.base_url,
                follow_redirects=True,
                include_body=True,
            )
        logger.info(
            "HTTP probe completed: %s status=%s",
            service.base_url,
            response.status_code,
        )
        return HTTPService(
            scheme=service.scheme,
            host=service.host,
            port=service.port,
            base_url=service.base_url,
            detected_service=service.detected_service,
            reachable=True,
            response=response.without_body(),
            error=None,
        )
    except HTTPProbeError as exc:
        logger.warning("HTTP probe failed: %s (%s)", service.base_url, exc)
        return HTTPService(
            scheme=service.scheme,
            host=service.host,
            port=service.port,
            base_url=service.base_url,
            detected_service=service.detected_service,
            reachable=False,
            response=None,
            error=str(exc),
        )


def nmap_indicates_http(port: PortResult) -> bool:
    """Public helper for tests: whether Nmap labeled this port as HTTP(S)."""
    return _nmap_indicates_http(port)


def _nmap_indicates_http(port: PortResult) -> bool:
    blob = _service_blob(port)
    return "http" in blob


def _scheme_for_port(port: PortResult) -> str:
    blob = _service_blob(port)
    if "https" in blob or "ssl/http" in blob or "tls/http" in blob:
        return "https"
    if blob.startswith("ssl/") and "http" in blob:
        return "https"
    return "http"


def _service_blob(port: PortResult) -> str:
    if port.service is None:
        return ""
    parts = [
        port.service.name or "",
        port.service.product or "",
        port.service.extra_info or "",
    ]
    return " ".join(parts).lower()


def _candidate(*, scheme: str, host: str, port: int, detected: str) -> HTTPService:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base = f"{scheme}://{host}"
    else:
        base = f"{scheme}://{host}:{port}"
    normalized = normalize_url(base) or base
    return HTTPService(
        scheme=scheme,
        host=host,
        port=port,
        base_url=normalized,
        detected_service=detected,
        reachable=False,
    )


def _should_get_body(content_type: str | None) -> bool:
    if content_type is None:
        return True
    return "html" in content_type.lower()
