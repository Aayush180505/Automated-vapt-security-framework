"""Build ReportData from stored or in-memory results. Does not scan or score."""

from __future__ import annotations

from vapt_framework.core.models import Finding, ScanContext
from vapt_framework.reporting.models import ReportData, ReportEndpoint, ReportFinding
from vapt_framework.storage.models import ScanDetails, StoredFinding

_SEVERITY_RANK = ("critical", "high", "medium", "low", "info")


def report_data_from_details(details: ScanDetails) -> ReportData:
    findings = tuple(_from_stored(item) for item in details.findings)
    return _assemble(
        scan_id=details.scan_id,
        target=details.target,
        scheme=details.scheme,
        hostname=details.hostname,
        ip_address=details.ip_address,
        port=details.port,
        status=details.status,
        started_at=details.started_at,
        completed_at=details.completed_at,
        total_findings=details.total_findings,
        average_risk=details.average_risk,
        maximum_risk=details.maximum_risk,
        highest_risk_band=details.highest_risk_band,
        services=details.services,
        findings=findings,
        endpoints=(),
        attack_surface_persisted=False,
    )


def report_data_from_context(context: ScanContext) -> ReportData:
    findings = tuple(_from_memory(item) for item in context.findings)
    endpoints: list[ReportEndpoint] = []
    for surface in context.web_attack_surfaces:
        for endpoint in surface.endpoints:
            endpoints.append(ReportEndpoint(method=endpoint.method, url=endpoint.url))
    summary = context.assessment_summary
    target = context.target
    return _assemble(
        scan_id=context.scan_id,
        target=target.normalized,
        scheme=target.scheme,
        hostname=target.hostname,
        ip_address=target.ip_address,
        port=target.port,
        status=context.status.value,
        started_at=context.created_at,
        completed_at=context.completed_at,
        total_findings=summary.total_findings if summary else len(findings),
        average_risk=summary.average_risk if summary else 0.0,
        maximum_risk=summary.maximum_risk if summary else 0.0,
        highest_risk_band=_highest_band_from_findings(findings),
        services=_services_from_context(context),
        findings=findings,
        endpoints=tuple(endpoints),
        attack_surface_persisted=bool(endpoints),
    )


def _services_from_context(context: ScanContext):
    from vapt_framework.storage.models import StoredService

    discovery = context.discovery_results
    if discovery is None:
        return ()
    rows: list[StoredService] = []
    for host in discovery.hosts:
        for port in host.ports:
            rows.append(
                StoredService(
                    host=host.address,
                    port=port.number,
                    protocol=port.protocol,
                    state=port.state,
                    service=port.service_name,
                    product=(port.service.product if port.service else None) or "-",
                    version=(port.service.version if port.service else None) or "-",
                )
            )
    return tuple(rows)


def _assemble(
    *,
    scan_id: str,
    target: str,
    scheme: str | None,
    hostname: str | None,
    ip_address: str | None,
    port: int | None,
    status: str,
    started_at,
    completed_at,
    total_findings: int,
    average_risk: float,
    maximum_risk: float,
    highest_risk_band: str | None,
    services,
    findings: tuple[ReportFinding, ...],
    endpoints: tuple[ReportEndpoint, ...],
    attack_surface_persisted: bool,
) -> ReportData:
    return ReportData(
        title="Automated VAPT Security Assessment Report",
        scan_id=scan_id,
        target=target,
        scheme=scheme,
        hostname=hostname,
        ip_address=ip_address,
        port=port,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        total_findings=total_findings,
        average_risk=average_risk,
        maximum_risk=maximum_risk,
        highest_risk_band=highest_risk_band,
        highest_severity=_highest_severity(findings),
        critical_high_count=sum(
            1 for item in findings if item.severity.lower() in {"critical", "high"}
        ),
        services=services,
        findings=findings,
        endpoints=endpoints,
        attack_surface_persisted=attack_surface_persisted,
        severity_counts=_count(findings, lambda item: item.severity.lower()),
        confidence_counts=_count(findings, lambda item: item.confidence.lower()),
        risk_band_counts=_count(findings, lambda item: (item.risk_band or "").lower()),
        priority_counts=_count(findings, lambda item: (item.priority or "").lower()),
    )


def _highest_band_from_findings(findings: tuple[ReportFinding, ...]) -> str | None:
    best: str | None = None
    best_score = -1.0
    for item in findings:
        if item.risk_score is not None and item.risk_score > best_score:
            best_score = item.risk_score
            best = item.risk_band
    return best


def _highest_severity(findings: tuple[ReportFinding, ...]) -> str | None:
    if not findings:
        return None
    best = None
    best_rank = len(_SEVERITY_RANK)
    for item in findings:
        key = item.severity.lower()
        if key in _SEVERITY_RANK:
            rank = _SEVERITY_RANK.index(key)
            if rank < best_rank:
                best_rank = rank
                best = key
    return best


def _count(findings: tuple[ReportFinding, ...], key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in findings:
        label = key(item) or "unknown"
        counts[label] = counts.get(label, 0) + 1
    return counts


def _from_stored(item: StoredFinding) -> ReportFinding:
    return ReportFinding(
        fingerprint=item.fingerprint,
        title=item.title,
        scanner=item.scanner,
        category=item.category,
        severity=item.severity,
        confidence=item.confidence,
        risk_score=item.risk_score,
        risk_band=item.risk_band,
        priority=item.priority,
        affected_url=item.affected_url,
        parameter=item.parameter,
        description=item.description,
        remediation=item.remediation,
        evidence_description=item.evidence_description,
        evidence_url=item.evidence_url,
        evidence_method=item.evidence_method,
        evidence_status_code=item.evidence_status_code,
        evidence_excerpt=item.evidence_excerpt,
        risk_explanation=item.explanation,
    )


def _from_memory(item: Finding) -> ReportFinding:
    evidence = item.evidence
    return ReportFinding(
        fingerprint=item.fingerprint,
        title=item.title,
        scanner=item.plugin_name,
        category=item.category,
        severity=item.severity.value,
        confidence=item.confidence.value,
        risk_score=item.risk_score,
        risk_band=item.risk_band.value if item.risk_band else None,
        priority=item.priority.value if item.priority else None,
        affected_url=item.affected_url,
        parameter=item.parameter,
        description=item.description,
        remediation=item.remediation,
        evidence_description=evidence.description if evidence else None,
        evidence_url=evidence.url if evidence else None,
        evidence_method=evidence.method if evidence else None,
        evidence_status_code=evidence.status_code if evidence else None,
        evidence_excerpt=evidence.excerpt if evidence else None,
        risk_explanation=item.risk_explanation,
    )
