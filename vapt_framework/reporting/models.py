"""Read-only report view of a completed assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vapt_framework.storage.models import StoredService

METHODOLOGY: tuple[str, ...] = (
    "Target validation and normalization (no network during parse).",
    "Nmap service discovery for open TCP ports and service versions.",
    "HTTP/HTTPS detection and probing of candidate ports.",
    "Same-origin web enumeration (pages, endpoints, forms, parameters, robots.txt).",
    "Passive checks on already-collected HTTP metadata (headers, disclosure).",
    "Controlled in-scope GET detection (SQL error signatures, reflected XSS markers, path probes).",
    "Finding validation and fingerprint-based deduplication.",
    "Explainable risk scoring from severity × confidence (not CVSS).",
    "Optional MySQL persistence of the completed assessment.",
    "Read-only HTML reporting from stored or in-memory results.",
)

LIMITATIONS: tuple[str, ...] = (
    "This framework is for authorized testing of labs, CTFs, and systems you own or have permission to assess.",
    "Synthetic or lab results may not represent production environments.",
    "Active checks are conservative and detection-oriented; they are not exploitation.",
    "SQL injection detection is currently error-based only (no blind or time-based techniques).",
    "Reflected XSS detection identifies marker reflection and does not prove JavaScript execution.",
    "Path traversal detection uses a small set of controlled probes on path-like parameters.",
    "No authenticated scanning, browser/DOM execution, or CVE/threat-intelligence feeds.",
    "Risk scores are framework-defined and explainable; they are not a guarantee of real-world impact.",
    "Zero findings does not mean the target is secure.",
)


@dataclass(frozen=True)
class ReportFinding:
    fingerprint: str
    title: str
    scanner: str
    category: str
    severity: str
    confidence: str
    risk_score: float | None
    risk_band: str | None
    priority: str | None
    affected_url: str | None
    parameter: str | None
    description: str
    remediation: str | None
    evidence_description: str | None
    evidence_url: str | None
    evidence_method: str | None
    evidence_status_code: int | None
    evidence_excerpt: str | None
    risk_explanation: str | None


@dataclass(frozen=True)
class ReportEndpoint:
    method: str
    url: str


@dataclass(frozen=True)
class ReportData:
    """Structured input for the Jinja renderer. No database objects."""

    title: str
    scan_id: str
    target: str
    scheme: str | None
    hostname: str | None
    ip_address: str | None
    port: int | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    total_findings: int
    average_risk: float
    maximum_risk: float
    highest_risk_band: str | None
    highest_severity: str | None
    critical_high_count: int
    services: tuple[StoredService, ...]
    findings: tuple[ReportFinding, ...]
    endpoints: tuple[ReportEndpoint, ...]
    attack_surface_persisted: bool
    severity_counts: dict[str, int]
    confidence_counts: dict[str, int]
    risk_band_counts: dict[str, int]
    priority_counts: dict[str, int]
    methodology: tuple[str, ...] = METHODOLOGY
    limitations: tuple[str, ...] = LIMITATIONS
    authorized_use: str = (
        "This assessment is intended only for systems the operator is "
        "explicitly authorized to test."
    )
    generated_note: str = field(
        default="Report generated from existing assessment data. No additional scan was performed."
    )
