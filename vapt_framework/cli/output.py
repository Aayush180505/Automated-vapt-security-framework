"""Human-readable CLI presentation helpers."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.adapters.nmap.models import NmapScanResult
from vapt_framework.assessment.prioritizer import prioritize_findings
from vapt_framework.assessment.risk import RiskEngine, format_score
from vapt_framework.assessment.summary import AssessmentSummary, build_summary
from vapt_framework.core.models import Finding
from vapt_framework.enumeration.web.models import WebAttackSurface


def format_discovery_summary(result: NmapScanResult, target_label: str) -> str:
    """Render a concise service-discovery table."""
    lines = [
        f"Target: {target_label}",
        "",
        "Discovered Services",
        "-" * 50,
        f"{'PORT':<10} {'STATE':<10} {'SERVICE':<13} VERSION",
    ]

    open_tcp = result.open_tcp_ports()
    if not open_tcp:
        lines.append("No open TCP ports were discovered.")
        lines.append("-" * 50)
        return "\n".join(lines)

    rows = [
        port
        for host in result.hosts
        for port in host.ports
        if port.state == "open"
    ]
    for port in rows:
        lines.append(
            f"{port.label:<10} {port.state:<10} {port.service_name:<13} "
            f"{port.version_label}"
        )
    lines.append("-" * 50)
    return "\n".join(lines)


def format_http_services(services: tuple[HTTPService, ...]) -> str:
    """Render probed HTTP/HTTPS services."""
    lines = ["HTTP Services", "-" * 50]
    if not services:
        lines.append("No HTTP/HTTPS services were identified.")
        lines.append("-" * 50)
        return "\n".join(lines)

    for service in services:
        lines.append(service.base_url)
        if not service.reachable:
            lines.append(f"Status: unreachable ({service.error or 'probe failed'})")
            lines.append("-" * 50)
            continue
        info = service.response
        status = info.status_code if info else "-"
        title = (info.title if info and info.title else "-")
        server = (info.server if info and info.server else "-")
        content_type = (info.content_type if info and info.content_type else "-")
        lines.append(f"Status: {status}")
        lines.append(f"Title: {title}")
        lines.append(f"Server: {server}")
        lines.append(f"Content-Type: {content_type}")
        lines.append("-" * 50)
    return "\n".join(lines)


def format_attack_surfaces(surfaces: tuple[WebAttackSurface, ...]) -> str:
    """Render crawl totals and a short endpoint list."""
    lines = ["Web Attack Surface", "-" * 50]
    if not surfaces:
        lines.append("No web attack surface was enumerated.")
        lines.append("-" * 50)
        return "\n".join(lines)

    for surface in surfaces:
        lines.append(f"Base URL: {surface.base_url}")
        if surface.error:
            lines.append(f"Crawl error: {surface.error}")
        lines.append(f"Pages discovered: {surface.pages_crawled}")
        lines.append(f"Endpoints discovered: {len(surface.endpoints)}")
        lines.append(f"Forms discovered: {len(surface.forms)}")
        lines.append(f"Parameters discovered: {len(surface.parameters)}")
        lines.append(f"External references: {len(surface.external_references)}")
        if surface.endpoints:
            lines.append("")
            for endpoint in surface.endpoints:
                lines.append(_endpoint_line(endpoint.method, endpoint.url, surface.base_url))
        lines.append("-" * 50)
    return "\n".join(lines)


def _endpoint_line(method: str, url: str, base_url: str) -> str:
    display = url
    prefix = base_url.rstrip("/")
    if display.startswith(prefix):
        display = display[len(prefix) :] or "/"
    return f"{method:<4} {display}"


def format_findings(
    findings: tuple[Finding, ...],
    *,
    executed: tuple[str, ...] = (),
    skipped: tuple[str, ...] = (),
    active_requests: int = 0,
    errors: tuple[str, ...] = (),
    active_enabled: bool = True,
    summary: AssessmentSummary | None = None,
) -> str:
    """Render plugin roster, prioritized findings, and risk statistics."""
    ranked = prioritize_findings(findings)
    stats = summary or build_summary(ranked)
    passive = [
        name
        for name in executed
        if name in {"security-headers", "information-disclosure"}
    ]
    active = [name for name in executed if name not in set(passive)]
    lines = [
        "Security Assessment",
        "=" * 50,
        "",
        "Passive checks:",
    ]
    if passive:
        for name in passive:
            lines.append(f"  {name}")
    else:
        lines.append("  (none executed)")
    lines.append("")
    lines.append("Active checks:")
    if not active_enabled:
        lines.append("  (disabled by VAPT_ENABLE_ACTIVE_SCANNERS)")
    elif active:
        for name in active:
            lines.append(f"  {name}")
    else:
        lines.append("  (none executed)")
    lines.append("")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Findings: {len(ranked)}")
    lines.append("")
    if not ranked:
        lines.append(
            "No security findings were identified by the enabled assessment plugins."
        )
        lines.append("This does NOT mean the target is secure.")
        lines.append("")
        lines.append("Risk Assessment:")
        lines.append("No findings available for risk scoring.")
    else:
        for finding in ranked:
            lines.extend(_finding_card(finding))
            lines.append("")
        lines.extend(_risk_summary_lines(stats))
        lines.append("")
        lines.append("Prioritized Findings:")
        lines.append("")
        for finding in ranked:
            lines.extend(_prioritized_line(finding))
            lines.append("")
            lines.extend(_finding_details(finding))
            lines.append("")
    lines.append("=" * 50)
    lines.append("")
    lines.append("Summary:")
    lines.append(f"Critical: {stats.critical}")
    lines.append(f"High:     {stats.high}")
    lines.append(f"Medium:   {stats.medium}")
    lines.append(f"Low:      {stats.low}")
    lines.append(f"Info:     {stats.info}")
    lines.append("")
    lines.append("Assessment completed.")
    lines.append(f"Plugins executed: {len(executed)}")
    lines.append(f"Plugins skipped: {len(skipped)}")
    lines.append(f"Active requests: {active_requests}")
    lines.append(f"Findings: {len(ranked)}")
    lines.append(f"Scanner errors: {len(errors)}")
    return "\n".join(lines)


def _finding_card(finding: Finding) -> list[str]:
    label = finding.severity.value.upper()
    lines = [
        f"[{label}] {finding.title}",
        f"Target: {finding.affected_url or '-'}",
    ]
    if finding.parameter:
        lines.append(f"Parameter: {finding.parameter}")
    lines.append(f"Scanner: {finding.plugin_name}")
    if finding.risk_score is not None and finding.priority is not None:
        lines.append(
            f"Risk: {format_score(finding.risk_score)}  "
            f"Priority: {finding.priority.value.upper()}"
        )
    return lines


def _prioritized_line(finding: Finding) -> list[str]:
    label = finding.severity.value.upper()
    score = format_score(finding.risk_score or 0.0)
    priority = finding.priority.value.upper() if finding.priority else "-"
    return [
        f"[{label}]  Risk: {score}  Priority: {priority}",
        finding.title,
        finding.affected_url or "-",
    ]


def _finding_details(finding: Finding) -> list[str]:
    engine = RiskEngine()
    assessment = engine.assess(finding)
    label = finding.severity.value.upper()
    lines = [
        f"[{label}]",
        finding.title,
        "",
        "URL:",
        finding.affected_url or "-",
    ]
    if finding.parameter:
        lines.extend(["", "Parameter:", finding.parameter])
    lines.extend(
        [
            "",
            "Severity:",
            finding.severity.value.upper(),
            "",
            "Confidence:",
            finding.confidence.value.upper(),
            "",
            "Risk:",
            f"{format_score(assessment.score)} / 100",
            "",
            "Risk Band:",
            assessment.band.value.upper(),
            "",
            "Priority:",
            assessment.priority.value.upper(),
            "",
            "Reason:",
            assessment.explanation,
            "",
            "Calculation:",
            assessment.calculation,
        ]
    )
    return lines


def _risk_summary_lines(summary: AssessmentSummary) -> list[str]:
    return [
        "=" * 50,
        "",
        "Risk Assessment",
        "=" * 50,
        "",
        f"Total findings: {summary.total_findings}",
        "",
        "Risk Distribution:",
        f"  Critical: {summary.risk_critical}",
        f"  High:     {summary.risk_high}",
        f"  Medium:   {summary.risk_medium}",
        f"  Low:      {summary.risk_low}",
        f"  Info:     {summary.risk_info}",
        "",
        "Priority:",
        f"  P1: {summary.p1}",
        f"  P2: {summary.p2}",
        f"  P3: {summary.p3}",
        f"  P4: {summary.p4}",
        f"  P5: {summary.p5}",
        "",
        f"Average risk score: {summary.average_risk:.1f}",
        f"Maximum risk score: {summary.maximum_risk:.1f}",
    ]


def format_assessment_errors(errors: tuple[str, ...]) -> str:
    if not errors:
        return ""
    lines = ["Plugin errors:", "-" * 50]
    for error in errors:
        lines.append(f"- {error}")
    return "\n".join(lines)


def format_persistence(outcome) -> str:
    """Render whether the current scan was saved. ``outcome`` is PersistenceOutcome."""
    if not outcome.enabled:
        return "Database persistence:\ndisabled"
    if outcome.saved:
        return f"Scan saved:\n{outcome.scan_id or '-'}"
    return (
        "Warning:\n"
        + (outcome.error or "Database persistence failed. Results were not saved.")
    )


def format_history(items) -> str:
    lines = [
        "Scan History",
        "=" * 50,
        "",
        f"{'SCAN ID':<38} {'TARGET':<22} {'DATE':<18} FINDINGS",
        "-" * 90,
    ]
    if not items:
        lines.append("No saved scans.")
        return "\n".join(lines)
    for item in items:
        date = _fmt_dt(item.started_at)
        lines.append(
            f"{item.scan_id:<38} {item.target:<22} {date:<18} {item.total_findings}"
        )
    return "\n".join(lines)


def format_scan_details(details) -> str:
    lines = [
        "Scan Details",
        "=" * 50,
        "",
        "Scan ID:",
        details.scan_id,
        "",
        "Target:",
        details.target,
        "",
        "Status:",
        details.status.upper(),
        "",
        "Started:",
        _fmt_dt(details.started_at),
        "",
        "Completed:",
        _fmt_dt(details.completed_at),
        "",
        f"Findings: {details.total_findings}",
        "",
        "Risk:",
        f"Highest: {(details.highest_risk_band or '-').upper()}",
        f"Average: {details.average_risk:.1f}",
        "",
        "Services:",
    ]
    if not details.services:
        lines.append("None recorded.")
    else:
        for service in details.services:
            lines.append(
                f"{service.port}/{service.protocol} {service.state} "
                f"{service.service} {service.product} {service.version}"
            )
    lines.extend(["", "Findings:"])
    if not details.findings:
        lines.append("No findings stored for this scan.")
    else:
        for finding in details.findings:
            lines.append(f"[{finding.severity.upper()}] {finding.title}")
    return "\n".join(lines)


def _fmt_dt(value) -> str:
    if value is None:
        return "-"
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M")
    return str(value)

