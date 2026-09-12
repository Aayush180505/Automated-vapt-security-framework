"""Read-only view of scan data for plugins (no CLI coupling)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.config.settings import Settings
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import Target
from vapt_framework.enumeration.web.models import WebAttackSurface

if TYPE_CHECKING:
    from vapt_framework.adapters.http.client import HttpClient
    from vapt_framework.scanners.active.client import ScannerHttpClient


@dataclass(frozen=True)
class AssessmentContext:
    """Plugin-facing subset of a completed recon pass."""

    scan: ScanContext
    settings: Settings | None = None
    http_client: HttpClient | None = None
    scanner_client: ScannerHttpClient | None = None

    @property
    def target(self) -> Target:
        return self.scan.target

    @property
    def http_services(self) -> tuple[HTTPService, ...]:
        return self.scan.http_services

    @property
    def web_attack_surfaces(self) -> tuple[WebAttackSurface, ...]:
        return self.scan.web_attack_surfaces

    def reachable_http_services(self) -> tuple[HTTPService, ...]:
        return tuple(
            service
            for service in self.scan.http_services
            if service.reachable and service.response is not None
        )

    def has_reachable_http(self) -> bool:
        return bool(self.reachable_http_services())
