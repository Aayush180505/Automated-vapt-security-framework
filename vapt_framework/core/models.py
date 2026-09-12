"""Lightweight domain objects used across later pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from vapt_framework.core.enums import Confidence, Priority, ScanStatus, Severity
from vapt_framework.core.target import Target

if TYPE_CHECKING:
    from vapt_framework.adapters.http.models import HTTPService
    from vapt_framework.adapters.nmap.models import NmapScanResult
    from vapt_framework.assessment.summary import AssessmentSummary
    from vapt_framework.enumeration.web.models import WebAttackSurface


@dataclass(frozen=True)
class Evidence:
    """Concise observation supporting a finding. No secrets or full bodies."""

    description: str
    url: str | None = None
    method: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    excerpt: str | None = None


@dataclass(frozen=True)
class Finding:
    """Structured security finding produced by an assessment plugin."""

    title: str
    description: str
    severity: Severity
    confidence: Confidence
    plugin_name: str
    fingerprint: str
    category: str
    finding_type: str
    target: Target | None = None
    affected_url: str | None = None
    parameter: str | None = None
    evidence: Evidence | None = None
    remediation: str | None = None
    risk_score: float | None = None
    risk_band: Severity | None = None
    priority: Priority | None = None
    risk_explanation: str | None = None


@dataclass(frozen=True)
class ScanContext:
    """Holds state for a single assessment run."""

    target: Target
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    profile: str = "standard"
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    status: ScanStatus = ScanStatus.RUNNING
    completed_at: datetime | None = None
    discovery_results: NmapScanResult | None = None
    http_services: tuple[HTTPService, ...] = ()
    web_attack_surfaces: tuple[WebAttackSurface, ...] = ()
    findings: tuple[Finding, ...] = ()
    assessment_errors: tuple[str, ...] = ()
    executed_plugins: tuple[str, ...] = ()
    skipped_plugins: tuple[str, ...] = ()
    active_requests: int = 0
    assessment_summary: AssessmentSummary | None = None
