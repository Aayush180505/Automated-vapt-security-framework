"""Attack-surface construction and ScanContext integration."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.enumeration.web.crawler import CrawlLimits, crawl_web
from tests.conftest import fixture_text, lab_client


def test_attack_surface_construction() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3),
        )
        assert surface.base_url.startswith("http://10.10.10.10")
        assert surface.endpoints
        assert surface.forms
        assert surface.parameters
        assert surface.pages_crawled > 0
        methods_urls = [(e.method, e.url) for e in surface.endpoints]
        assert methods_urls == sorted(methods_urls)
    finally:
        client.close()


def test_scan_context_stores_web_surface() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=10, max_depth=2),
        )
        http_service = HTTPService(
            scheme="http",
            host="10.10.10.10",
            port=80,
            base_url="http://10.10.10.10/",
            detected_service="http",
            reachable=True,
        )
        context = ScanContext(
            target=parse_target("http://10.10.10.10"),
            discovery_results=parse_nmap_xml(fixture_text("nmap_single_host.xml")),
            http_services=(http_service,),
            web_attack_surfaces=(surface,),
        )
        assert context.http_services[0].base_url == "http://10.10.10.10/"
        assert context.web_attack_surfaces[0].forms
        assert context.discovery_results is not None
    finally:
        client.close()
