"""Database-facing DTOs. Independent of mysql.connector types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ScanHistoryItem:
    scan_id: str
    target: str
    started_at: datetime | None
    total_findings: int
    status: str


@dataclass(frozen=True)
class StoredService:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str


@dataclass(frozen=True)
class StoredFinding:
    title: str
    scanner: str
    severity: str
    confidence: str
    affected_url: str | None
    parameter: str | None
    risk_score: float | None
    risk_band: str | None
    priority: str | None
    explanation: str | None
    fingerprint: str = ""
    category: str = ""
    description: str = ""
    remediation: str | None = None
    evidence_description: str | None = None
    evidence_url: str | None = None
    evidence_method: str | None = None
    evidence_status_code: int | None = None
    evidence_excerpt: str | None = None


@dataclass(frozen=True)
class ScanDetails:
    scan_id: str
    target: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    total_findings: int
    average_risk: float
    maximum_risk: float
    highest_risk_band: str | None
    services: tuple[StoredService, ...]
    findings: tuple[StoredFinding, ...]
    scheme: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    port: int | None = None
