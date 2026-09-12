"""HTTP service detection tests (Nmap models only; no network)."""

from __future__ import annotations

from vapt_framework.adapters.http.probe import detect_http_candidates, nmap_indicates_http
from vapt_framework.adapters.nmap.models import HostResult, NmapScanResult, PortResult, ServiceInfo
from vapt_framework.core.target import parse_target


def _port(number: int, name: str | None, *, extra: str | None = None) -> PortResult:
    service = None if name is None else ServiceInfo(name=name, extra_info=extra)
    return PortResult(number=number, protocol="tcp", state="open", service=service)


def test_detects_http_and_https_from_nmap() -> None:
    discovery = NmapScanResult(
        hosts=(
            HostResult(
                address="10.10.10.10",
                status="up",
                ports=(
                    _port(22, "ssh"),
                    _port(80, "http"),
                    _port(443, "https"),
                    _port(3306, "mysql"),
                    _port(8080, "http-alt"),
                    _port(8443, "ssl/http"),
                ),
            ),
        )
    )
    target = parse_target("10.10.10.10")
    services = detect_http_candidates(discovery, target)
    urls = {item.base_url for item in services}
    assert "http://10.10.10.10/" in urls
    assert "https://10.10.10.10/" in urls
    assert "http://10.10.10.10:8080/" in urls
    assert "https://10.10.10.10:8443/" in urls
    assert all("3306" not in item.base_url for item in services)
    assert all(":22" not in item.base_url for item in services)


def test_does_not_assume_port_80_without_http_name() -> None:
    discovery = NmapScanResult(
        hosts=(
            HostResult(
                address="10.10.10.10",
                status="up",
                ports=(_port(80, "ssh"),),
            ),
        )
    )
    services = detect_http_candidates(discovery, parse_target("10.10.10.10"))
    assert services == ()


def test_explicit_http_target_is_a_candidate() -> None:
    discovery = NmapScanResult(
        hosts=(
            HostResult(
                address="10.10.10.10",
                status="up",
                ports=(_port(22, "ssh"),),
            ),
        )
    )
    services = detect_http_candidates(discovery, parse_target("http://10.10.10.10"))
    assert len(services) == 1
    assert services[0].scheme == "http"
    assert services[0].base_url == "http://10.10.10.10/"


def test_nmap_indicates_http_helpers() -> None:
    assert nmap_indicates_http(_port(80, "http"))
    assert nmap_indicates_http(_port(443, "https"))
    assert nmap_indicates_http(_port(8080, "http-alt"))
    assert nmap_indicates_http(_port(8443, "ssl/http"))
    assert not nmap_indicates_http(_port(22, "ssh"))
    assert not nmap_indicates_http(_port(80, None))
