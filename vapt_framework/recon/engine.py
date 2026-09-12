"""Reconnaissance orchestration: Nmap, HTTP detection, and web enumeration."""

from __future__ import annotations

from datetime import datetime, timezone

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.adapters.http.probe import detect_http_candidates, probe_http_service
from vapt_framework.adapters.nmap.adapter import NmapAdapter
from vapt_framework.adapters.nmap.models import NmapScanResult
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.engine import AssessmentEngine
from vapt_framework.assessment.registry import PluginRegistry
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import ScanStatus
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import Target
from vapt_framework.enumeration.web.crawler import CrawlLimits, crawl_web
from vapt_framework.enumeration.web.models import WebAttackSurface
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.recon")


def require_nmap() -> str:
    """Ensure Nmap is on PATH."""
    return NmapAdapter().require_executable()


def discover_services(target: Target, timeout: float) -> NmapScanResult:
    """Run service discovery for a validated target."""
    return NmapAdapter().discover(target, timeout=timeout)


def run_scan(
    target: Target,
    settings: Settings,
    *,
    http_client: HttpClient | None = None,
    plugin_registry: PluginRegistry | None = None,
) -> ScanContext:
    """Run Nmap, HTTP enumeration, then the assessment engine."""
    discovery = discover_services(target, timeout=settings.nmap_timeout)
    owns_client = http_client is None
    client = http_client or HttpClient.from_settings(settings)
    context: ScanContext | None = None
    result = None
    try:
        http_services, surfaces = enumerate_web(discovery, target, client, settings)
        context = ScanContext(
            target=target,
            discovery_results=discovery,
            http_services=http_services,
            web_attack_surfaces=surfaces,
        )
        result = AssessmentEngine(plugin_registry).assess(
            AssessmentContext(
                scan=context,
                settings=settings,
                http_client=client,
            )
        )
    finally:
        if owns_client:
            client.close()
    if context is None or result is None:
        raise RuntimeError("Scan did not complete.")
    return ScanContext(
        target=context.target,
        created_at=context.created_at,
        profile=context.profile,
        scan_id=context.scan_id,
        status=ScanStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
        discovery_results=context.discovery_results,
        http_services=context.http_services,
        web_attack_surfaces=context.web_attack_surfaces,
        findings=result.findings,
        assessment_errors=result.errors,
        executed_plugins=result.executed_plugins,
        skipped_plugins=result.skipped_plugins,
        active_requests=result.active_requests,
        assessment_summary=result.summary,
    )


def enumerate_web(
    discovery: NmapScanResult,
    target: Target,
    client: HttpClient,
    settings: Settings,
) -> tuple[tuple[HTTPService, ...], tuple[WebAttackSurface, ...]]:
    """Probe HTTP services and crawl reachable origins. Failures are isolated."""
    candidates = detect_http_candidates(discovery, target)
    probed: list[HTTPService] = []
    for candidate in candidates:
        logger.info("HTTP service detected: %s", candidate.base_url)
        probed.append(probe_http_service(client, candidate))

    limits = CrawlLimits(
        max_pages=settings.max_pages,
        max_depth=settings.max_depth,
        respect_robots=True,
    )
    surfaces: list[WebAttackSurface] = []
    for service in probed:
        if not service.reachable:
            continue
        try:
            surfaces.append(crawl_web(service.base_url, client, limits))
        except Exception as exc:  # noqa: BLE001 - isolate one origin
            logger.warning("Crawler failed for %s: %s", service.base_url, exc)
            surfaces.append(
                WebAttackSurface(base_url=service.base_url, error=str(exc))
            )
    return tuple(probed), tuple(surfaces)
