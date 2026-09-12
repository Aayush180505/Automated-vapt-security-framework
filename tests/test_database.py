"""Database settings, schema, fake connection, and persistence tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vapt_framework.assessment.summary import AssessmentSummary
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import Confidence, ScanStatus, Severity
from vapt_framework.core.exceptions import (
    DatabaseConnectionError,
    DatabasePersistenceError,
)
from vapt_framework.core.models import Evidence, Finding, ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.storage.database import Database
from vapt_framework.storage.repositories import ScanRepository
from vapt_framework.storage.schema import SCHEMA_STATEMENTS, SCHEMA_VERSION, init_schema
from vapt_framework.storage.service import persist_scan
from tests.conftest import fixture_text
from tests.fake_database import FakeDatabase
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.findings.factory import make_finding


def _finding() -> Finding:
    return make_finding(
        title="Potential SQL Injection",
        description="Error signature.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        plugin_name="sql-injection",
        finding_type="potential-sqli",
        category="injection",
        target=parse_target("http://10.10.10.10"),
        affected_url="http://10.10.10.10/search?q=test",
        evidence=Evidence(
            description="mysql error",
            url="http://10.10.10.10/search?q=test",
            method="GET",
            status_code=200,
            excerpt="You have an error in your SQL syntax",
        ),
        remediation="Use parameterized queries.",
        parameter="q",
    )


def _context(**overrides: object) -> ScanContext:
    from vapt_framework.core.enums import Priority

    finding = _finding()
    finding = Finding(
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        confidence=finding.confidence,
        plugin_name=finding.plugin_name,
        fingerprint=finding.fingerprint,
        category=finding.category,
        finding_type=finding.finding_type,
        target=finding.target,
        affected_url=finding.affected_url,
        parameter=finding.parameter,
        evidence=finding.evidence,
        remediation=finding.remediation,
        risk_score=56.25,
        risk_band=Severity.MEDIUM,
        priority=Priority.P3,
        risk_explanation="High severity finding with medium confidence.",
    )
    values = dict(
        target=parse_target("http://10.10.10.10"),
        scan_id="11111111-1111-1111-1111-111111111111",
        status=ScanStatus.COMPLETED,
        created_at=datetime(2026, 9, 13, 21, 10, tzinfo=timezone.utc),
        completed_at=datetime(2026, 9, 13, 21, 12, tzinfo=timezone.utc),
        discovery_results=parse_nmap_xml(fixture_text("nmap_single_host.xml")),
        findings=(finding,),
        executed_plugins=("sql-injection",),
        skipped_plugins=(),
        active_requests=4,
        assessment_summary=AssessmentSummary(
            total_findings=1,
            high=1,
            risk_medium=1,
            p3=1,
            average_risk=56.25,
            maximum_risk=56.25,
            scanner_count=1,
        ),
    )
    values.update(overrides)
    return ScanContext(**values)  # type: ignore[arg-type]


def test_settings_database_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "VAPT_DATABASE_ENABLED",
        "VAPT_DB_HOST",
        "VAPT_DB_PORT",
        "VAPT_DB_NAME",
        "VAPT_DB_USER",
        "VAPT_DB_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = Settings.from_env()
    assert settings.database_enabled is False
    assert settings.db_host == "localhost"
    assert settings.db_port == 3306
    assert settings.db_name == "vapt_framework"
    assert settings.db_user == "vapt_user"
    assert settings.db_password == ""


def test_settings_database_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAPT_DATABASE_ENABLED", "true")
    monkeypatch.setenv("VAPT_DB_HOST", "127.0.0.1")
    monkeypatch.setenv("VAPT_DB_PORT", "3307")
    monkeypatch.setenv("VAPT_DB_NAME", "lab")
    monkeypatch.setenv("VAPT_DB_USER", "tester")
    monkeypatch.setenv("VAPT_DB_PASSWORD", "change_me")
    settings = Settings.from_env()
    assert settings.database_enabled is True
    assert settings.db_host == "127.0.0.1"
    assert settings.db_port == 3307
    assert settings.db_name == "lab"
    assert settings.db_user == "tester"
    assert settings.db_password == "change_me"


def test_execute_requires_open_connection() -> None:
    db = Database(
        host="localhost", port=3306, database="vapt_framework", user="u", password="x"
    )
    with pytest.raises(DatabaseConnectionError):
        db.execute("SELECT 1")


def test_schema_has_keys_and_indexes() -> None:
    joined = "\n".join(SCHEMA_STATEMENTS)
    assert "FOREIGN KEY" in joined
    assert "ON DELETE CASCADE" in joined
    assert "uq_scans_scan_id" in joined
    assert "uq_findings_scan_fingerprint" in joined
    assert "idx_scans_started_at" in joined
    assert "idx_findings_scan_id" in joined
    assert "idx_findings_severity" in joined
    assert "idx_risk_score" in joined
    assert SCHEMA_VERSION == 1


def test_schema_initialization_uses_transaction() -> None:
    fake = FakeDatabase()
    fake.fetchone_result = None
    init_schema(fake)
    assert fake.committed is True
    assert fake.rolled_back is False
    texts = " ".join(fake.sql_texts())
    assert "CREATE TABLE IF NOT EXISTS scans" in texts
    assert "schema_version" in texts


def test_parameterized_queries_do_not_embed_target() -> None:
    fake = FakeDatabase()
    repo = ScanRepository(fake)
    context = _context()
    repo.save_scan_context(context)
    saw_bound_target = False
    for _op, sql, params in fake.calls:
        assert "10.10.10.10" not in sql
        assert "Potential SQL Injection" not in sql
        if params is not None and _op == "execute" and "INSERT" in sql.upper():
            assert "%s" in sql
            if "10.10.10.10" in str(params):
                saw_bound_target = True
    assert saw_bound_target


def test_save_scan_is_transactional() -> None:
    fake = FakeDatabase()
    repo = ScanRepository(fake)
    scan_id = repo.save_scan_context(_context())
    assert scan_id == "11111111-1111-1111-1111-111111111111"
    assert fake.committed is True
    kinds = [sql.split()[0] for _op, sql, _p in fake.calls if _op == "execute"]
    assert "INSERT" in kinds
    assert "UPDATE" in kinds


def test_rollback_on_failure() -> None:
    fake = FakeDatabase()
    fake.fail_sql = "INSERT INTO findings"
    repo = ScanRepository(fake)
    with pytest.raises(DatabasePersistenceError):
        repo.save_scan_context(_context())
    assert fake.rolled_back is True
    assert fake.committed is False


def test_list_scans_limit_and_order_query() -> None:
    fake = FakeDatabase()
    fake.fetchall_result = [
        {
            "scan_id": "aaa",
            "target": "10.10.10.10",
            "started_at": datetime(2026, 9, 13, 21, 10),
            "total_findings": 5,
            "status": "completed",
        }
    ]
    items = ScanRepository(fake).list_scans(limit=10)
    assert items[0].total_findings == 5
    sql = fake.calls[-1][1]
    assert "ORDER BY s.started_at DESC" in sql
    assert fake.calls[-1][2] == (10,)


def test_get_scan_missing() -> None:
    fake = FakeDatabase()
    fake.fetchone_result = None
    assert ScanRepository(fake).get_scan("missing") is None


def test_get_scan_details() -> None:
    fake = FakeDatabase()
    fake.fetchone_result = {
        "scan_id": "aaa",
        "target": "http://10.10.10.10",
        "status": "completed",
        "started_at": datetime(2026, 9, 13, 21, 10),
        "completed_at": datetime(2026, 9, 13, 21, 12),
        "total_findings": 1,
        "average_risk": 56.25,
        "maximum_risk": 56.25,
        "highest_risk_band": "medium",
        "id": 9,
    }
    fake.fetchall_result = []
    details = ScanRepository(fake).get_scan("aaa")
    assert details is not None
    assert details.scan_id == "aaa"
    assert details.total_findings == 1
    assert fake.calls[0][2] == ("aaa",)


def test_persist_scan_disabled() -> None:
    settings = Settings(database_enabled=False)
    outcome = persist_scan(_context(), settings)
    assert outcome.enabled is False
    assert outcome.saved is False


def test_persist_failure_does_not_drop_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    from vapt_framework.core.exceptions import DatabaseConnectionError

    def boom(settings: Settings):
        raise DatabaseConnectionError("Could not connect to MySQL.")

    monkeypatch.setattr(
        "vapt_framework.storage.service.ScanStorageService.from_settings",
        boom,
    )
    context = _context()
    outcome = persist_scan(context, Settings(database_enabled=True))
    assert outcome.enabled is True
    assert outcome.saved is False
    assert outcome.error
    assert context.findings
    assert "password" not in (outcome.error or "").lower()


def test_evidence_excerpt_truncated_not_headers() -> None:
    fake = FakeDatabase()
    repo = ScanRepository(fake)
    finding = _finding()
    long = "A" * 800
    finding = Finding(
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        confidence=finding.confidence,
        plugin_name=finding.plugin_name,
        fingerprint=finding.fingerprint,
        category=finding.category,
        finding_type=finding.finding_type,
        target=finding.target,
        affected_url=finding.affected_url,
        parameter=finding.parameter,
        evidence=Evidence(
            description="ok",
            excerpt=long,
            headers={"set-cookie": "session=SECRET"},
        ),
        remediation=finding.remediation,
        risk_score=56.25,
        risk_band=Severity.MEDIUM,
        risk_explanation="x",
    )
    repo.create_evidence(3, finding)
    params = fake.calls[-1][2]
    assert params is not None
    excerpt = params[-1]
    assert excerpt is not None
    assert len(excerpt) <= 500
    assert "SECRET" not in str(params[:-1])
    sql = fake.calls[-1][1]
    assert "set-cookie" not in sql.lower()
