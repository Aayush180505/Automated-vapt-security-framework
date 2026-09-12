"""CLI database command tests (no real MySQL)."""

from __future__ import annotations

from datetime import datetime

from vapt_framework.cli.main import main
from vapt_framework.cli.output import format_history, format_persistence, format_scan_details
from vapt_framework.storage.models import (
    ScanDetails,
    ScanHistoryItem,
    StoredFinding,
    StoredService,
)
from vapt_framework.storage.service import PersistenceOutcome


def test_cli_help_lists_db_commands(capsys) -> None:
    assert main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "db" in output
    assert "history" in output
    assert "show" in output
    assert "report" in output


def test_db_help(capsys) -> None:
    assert main(["db", "--help"]) == 0
    output = capsys.readouterr().out.lower()
    assert "init" in output


def test_history_help(capsys) -> None:
    assert main(["history", "--help"]) == 0
    assert "--limit" in capsys.readouterr().out


def test_show_help(capsys) -> None:
    assert main(["show", "--help"]) == 0
    output = capsys.readouterr().out.lower()
    assert "scan_id" in output or "scan" in output


def test_db_init_unavailable(monkeypatch, capsys) -> None:
    from vapt_framework.core.exceptions import DatabaseConnectionError

    def boom(settings):
        raise DatabaseConnectionError(
            "Could not connect to MySQL. "
            "Check VAPT_DB_HOST, VAPT_DB_PORT, VAPT_DB_USER, and VAPT_DB_PASSWORD."
        )

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings", boom
    )
    code = main(["db", "init"])
    assert code == 2
    err = capsys.readouterr().err
    assert "Could not connect to MySQL" in err
    assert "password" not in err.lower() or "VAPT_DB_PASSWORD" in err


def test_history_command(monkeypatch, capsys) -> None:
    class Store:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def list_scans(self, limit=20):
            assert limit == 5
            return (
                ScanHistoryItem(
                    scan_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    target="10.10.10.10",
                    started_at=datetime(2026, 9, 13, 21, 10),
                    total_findings=5,
                    status="completed",
                ),
            )

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings",
        lambda settings: Store(),
    )
    code = main(["history", "--limit", "5"])
    assert code == 0
    output = capsys.readouterr().out
    assert "Scan History" in output
    assert "10.10.10.10" in output
    assert "5" in output


def test_show_invalid_scan(monkeypatch, capsys) -> None:
    class Store:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_scan(self, scan_id):
            return None

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings",
        lambda settings: Store(),
    )
    code = main(["show", "not-a-real-id"])
    assert code == 2
    assert "Scan not found" in capsys.readouterr().err


def test_show_scan_details(monkeypatch, capsys) -> None:
    details = ScanDetails(
        scan_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        target="http://10.10.10.10",
        status="completed",
        started_at=datetime(2026, 9, 13, 21, 10),
        completed_at=datetime(2026, 9, 13, 21, 12),
        total_findings=1,
        average_risk=48.2,
        maximum_risk=56.25,
        highest_risk_band="medium",
        services=(
            StoredService(
                host="10.10.10.10",
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="Apache",
                version="2.4",
            ),
        ),
        findings=(
            StoredFinding(
                title="Potential SQL Injection",
                scanner="sql-injection",
                severity="high",
                confidence="medium",
                affected_url="http://10.10.10.10/search?q=test",
                parameter="q",
                risk_score=56.25,
                risk_band="medium",
                priority="p3",
                explanation="High severity finding with medium confidence.",
            ),
        ),
    )

    class Store:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_scan(self, scan_id):
            assert scan_id == details.scan_id
            return details

    monkeypatch.setattr(
        "vapt_framework.cli.main.ScanStorageService.from_settings",
        lambda settings: Store(),
    )
    code = main(["show", details.scan_id])
    assert code == 0
    output = capsys.readouterr().out
    assert "Scan Details" in output
    assert "Potential SQL Injection" in output
    assert "http://10.10.10.10" in output


def test_persistence_formatters() -> None:
    disabled = format_persistence(
        PersistenceOutcome(enabled=False, saved=False, scan_id="x")
    )
    assert "disabled" in disabled
    saved = format_persistence(
        PersistenceOutcome(enabled=True, saved=True, scan_id="abc")
    )
    assert "Scan saved" in saved
    assert "abc" in saved
    failed = format_persistence(
        PersistenceOutcome(
            enabled=True,
            saved=False,
            error="Database persistence failed. Results were not saved.",
        )
    )
    assert "Warning" in failed
    history = format_history(())
    assert "No saved scans" in history
    text = format_scan_details(
        ScanDetails(
            scan_id="abc",
            target="lab.local",
            status="completed",
            started_at=None,
            completed_at=None,
            total_findings=0,
            average_risk=0.0,
            maximum_risk=0.0,
            highest_risk_band=None,
            services=(),
            findings=(),
        )
    )
    assert "Scan Details" in text
