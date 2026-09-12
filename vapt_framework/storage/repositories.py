"""Parameterized persistence and retrieval. No SQL in CLI or scanners."""

from __future__ import annotations

from datetime import datetime, timezone

from vapt_framework.core.enums import ScanStatus
from vapt_framework.core.exceptions import DatabasePersistenceError
from vapt_framework.core.models import Evidence, Finding, ScanContext
from vapt_framework.core.target import Target
from vapt_framework.storage.database import Database
from vapt_framework.storage.models import (
    ScanDetails,
    ScanHistoryItem,
    StoredFinding,
    StoredService,
)

_EXCERPT_MAX = 500


class ScanRepository:
    """Scan-owned writes and reads through :class:`Database`."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def save_scan_context(self, context: ScanContext) -> str:
        """Persist a completed assessment in one transaction."""
        try:
            with self._db.transaction():
                target_pk = self.create_target(context.target)
                scan_pk = self.create_scan(context, target_pk)
                self.create_services(scan_pk, context)
                self.create_findings(scan_pk, context)
                self.update_scan_summary(scan_pk, context)
        except DatabasePersistenceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DatabasePersistenceError("Could not save the scan.") from exc
        return context.scan_id

    def create_target(self, target: Target) -> int:
        return self._db.execute(
            "INSERT INTO targets (scheme, hostname, ip_address, port, normalized_target) "
            "VALUES (%s, %s, %s, %s, %s)",
            (
                target.scheme,
                target.hostname,
                target.ip_address,
                target.port,
                target.normalized,
            ),
        )

    def create_scan(self, context: ScanContext, target_pk: int) -> int:
        summary = context.assessment_summary
        started = _naive_utc(context.created_at)
        completed = _naive_utc(context.completed_at) if context.completed_at else None
        status = context.status.value if context.status else ScanStatus.COMPLETED.value
        return self._db.execute(
            "INSERT INTO scans (scan_id, started_at, completed_at, status, target_id, "
            "total_findings, active_requests, plugins_executed, plugins_skipped, "
            "average_risk, maximum_risk, highest_risk_band) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                context.scan_id,
                started,
                completed,
                status,
                target_pk,
                summary.total_findings if summary else len(context.findings),
                context.active_requests,
                ",".join(context.executed_plugins),
                ",".join(context.skipped_plugins),
                summary.average_risk if summary else 0.0,
                summary.maximum_risk if summary else 0.0,
                _highest_band(context),
            ),
        )

    def create_services(self, scan_pk: int, context: ScanContext) -> None:
        discovery = context.discovery_results
        if discovery is None:
            return
        for host in discovery.hosts:
            for port in host.ports:
                product = port.service.product if port.service else None
                version = port.service.version if port.service else None
                name = port.service.name if port.service else None
                self._db.execute(
                    "INSERT INTO services (scan_id, host, port, protocol, state, "
                    "service, product, version) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        scan_pk,
                        host.address,
                        port.number,
                        port.protocol,
                        port.state,
                        name,
                        product,
                        version,
                    ),
                )

    def create_findings(self, scan_pk: int, context: ScanContext) -> None:
        created = _naive_utc(context.completed_at or context.created_at)
        for finding in context.findings:
            finding_pk = self.create_finding(scan_pk, finding, created)
            if finding.evidence is not None:
                self.create_evidence(finding_pk, finding)
            if finding.risk_score is not None:
                self.create_risk_assessment(finding_pk, finding)

    def create_finding(
        self, scan_pk: int, finding: Finding, created_at: datetime
    ) -> int:
        return self._db.execute(
            "INSERT INTO findings (scan_id, fingerprint, scanner, category, title, "
            "description, severity, confidence, affected_url, parameter, "
            "remediation, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                scan_pk,
                finding.fingerprint,
                finding.plugin_name,
                finding.category,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.confidence.value,
                finding.affected_url,
                finding.parameter,
                finding.remediation,
                created_at,
            ),
        )

    def create_evidence(self, finding_pk: int, finding: Finding) -> int:
        evidence = finding.evidence
        assert evidence is not None
        return self._db.execute(
            "INSERT INTO evidence (finding_id, evidence_type, url, method, "
            "status_code, description, excerpt) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                finding_pk,
                finding.finding_type or "observation",
                evidence.url,
                evidence.method,
                evidence.status_code,
                evidence.description,
                _safe_excerpt(evidence),
            ),
        )

    def create_risk_assessment(self, finding_pk: int, finding: Finding) -> int:
        band = finding.risk_band.value if finding.risk_band else finding.severity.value
        priority = finding.priority.value if finding.priority else "p5"
        explanation = finding.risk_explanation or ""
        return self._db.execute(
            "INSERT INTO risk_assessments (finding_id, risk_score, risk_band, "
            "priority, explanation) VALUES (%s, %s, %s, %s, %s)",
            (
                finding_pk,
                finding.risk_score,
                band,
                priority,
                explanation,
            ),
        )

    def update_scan_summary(self, scan_pk: int, context: ScanContext) -> None:
        summary = context.assessment_summary
        total = summary.total_findings if summary else len(context.findings)
        average = summary.average_risk if summary else 0.0
        maximum = summary.maximum_risk if summary else 0.0
        self._db.execute(
            "UPDATE scans SET total_findings = %s, average_risk = %s, "
            "maximum_risk = %s, highest_risk_band = %s, status = %s, "
            "completed_at = %s WHERE id = %s",
            (
                total,
                average,
                maximum,
                _highest_band(context),
                ScanStatus.COMPLETED.value,
                _naive_utc(context.completed_at or context.created_at),
                scan_pk,
            ),
        )

    def list_scans(self, limit: int = 20) -> tuple[ScanHistoryItem, ...]:
        rows = self._db.fetchall(
            "SELECT s.scan_id AS scan_id, t.normalized_target AS target, "
            "s.started_at AS started_at, s.total_findings AS total_findings, "
            "s.status AS status "
            "FROM scans s INNER JOIN targets t ON t.id = s.target_id "
            "ORDER BY s.started_at DESC LIMIT %s",
            (limit,),
        )
        return tuple(
            ScanHistoryItem(
                scan_id=str(row["scan_id"]),
                target=str(row["target"]),
                started_at=row.get("started_at"),
                total_findings=int(row["total_findings"]),
                status=str(row["status"]),
            )
            for row in rows
        )

    def get_scan(self, scan_id: str) -> ScanDetails | None:
        row = self._db.fetchone(
            "SELECT s.scan_id AS scan_id, t.normalized_target AS target, "
            "s.status AS status, s.started_at AS started_at, "
            "s.completed_at AS completed_at, s.total_findings AS total_findings, "
            "s.average_risk AS average_risk, s.maximum_risk AS maximum_risk, "
            "s.highest_risk_band AS highest_risk_band, s.id AS id, "
            "t.scheme AS scheme, t.hostname AS hostname, "
            "t.ip_address AS ip_address, t.port AS port "
            "FROM scans s INNER JOIN targets t ON t.id = s.target_id "
            "WHERE s.scan_id = %s",
            (scan_id,),
        )
        if row is None:
            return None
        scan_pk = int(row["id"])
        return ScanDetails(
            scan_id=str(row["scan_id"]),
            target=str(row["target"]),
            status=str(row["status"]),
            started_at=row.get("started_at"),
            completed_at=row.get("completed_at"),
            total_findings=int(row["total_findings"]),
            average_risk=float(row["average_risk"] or 0),
            maximum_risk=float(row["maximum_risk"] or 0),
            highest_risk_band=row.get("highest_risk_band"),
            services=self.get_services(scan_pk),
            findings=self.get_findings_for_scan(scan_pk),
            scheme=row.get("scheme"),
            hostname=row.get("hostname"),
            ip_address=row.get("ip_address"),
            port=int(row["port"]) if row.get("port") is not None else None,
        )

    def get_services(self, scan_pk: int) -> tuple[StoredService, ...]:
        rows = self._db.fetchall(
            "SELECT host, port, protocol, state, service, product, version "
            "FROM services WHERE scan_id = %s ORDER BY port ASC",
            (scan_pk,),
        )
        return tuple(
            StoredService(
                host=str(row["host"]),
                port=int(row["port"]),
                protocol=str(row["protocol"]),
                state=str(row["state"]),
                service=str(row["service"] or "-"),
                product=str(row["product"] or "-"),
                version=str(row["version"] or "-"),
            )
            for row in rows
        )

    def get_findings_for_scan(self, scan_pk: int) -> tuple[StoredFinding, ...]:
        rows = self._db.fetchall(
            "SELECT f.fingerprint AS fingerprint, f.title AS title, "
            "f.scanner AS scanner, f.category AS category, "
            "f.description AS description, f.severity AS severity, "
            "f.confidence AS confidence, f.affected_url AS affected_url, "
            "f.parameter AS parameter, f.remediation AS remediation, "
            "e.description AS evidence_description, e.url AS evidence_url, "
            "e.method AS evidence_method, e.status_code AS evidence_status_code, "
            "e.excerpt AS evidence_excerpt, r.risk_score AS risk_score, "
            "r.risk_band AS risk_band, r.priority AS priority, "
            "r.explanation AS explanation "
            "FROM findings f LEFT JOIN risk_assessments r ON r.finding_id = f.id "
            "LEFT JOIN evidence e ON e.finding_id = f.id "
            "WHERE f.scan_id = %s "
            "ORDER BY r.risk_score DESC, f.severity ASC, f.id ASC",
            (scan_pk,),
        )
        return tuple(
            StoredFinding(
                title=str(row["title"]),
                scanner=str(row["scanner"]),
                severity=str(row["severity"]),
                confidence=str(row["confidence"]),
                affected_url=row.get("affected_url"),
                parameter=row.get("parameter"),
                risk_score=float(row["risk_score"]) if row.get("risk_score") is not None else None,
                risk_band=row.get("risk_band"),
                priority=row.get("priority"),
                explanation=row.get("explanation"),
                fingerprint=str(row.get("fingerprint") or ""),
                category=str(row.get("category") or ""),
                description=str(row.get("description") or ""),
                remediation=row.get("remediation"),
                evidence_description=row.get("evidence_description"),
                evidence_url=row.get("evidence_url"),
                evidence_method=row.get("evidence_method"),
                evidence_status_code=row.get("evidence_status_code"),
                evidence_excerpt=row.get("evidence_excerpt"),
            )
            for row in rows
        )


def _highest_band(context: ScanContext) -> str | None:
    summary = context.assessment_summary
    if summary is not None:
        from vapt_framework.assessment.risk import band_for_score

        return band_for_score(summary.maximum_risk).value
    return None


def _safe_excerpt(evidence: Evidence) -> str | None:
    if not evidence.excerpt:
        return None
    text = evidence.excerpt.replace("\x00", "")
    return text[:_EXCERPT_MAX]


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)
