"""Static MySQL DDL. Identifiers are never taken from user input."""

from __future__ import annotations

from vapt_framework.core.exceptions import DatabaseMigrationError
from vapt_framework.storage.database import Database
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.storage.schema")

SCHEMA_VERSION = 1

SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INT NOT NULL PRIMARY KEY,
        applied_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS targets (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        scheme VARCHAR(16) NULL,
        hostname VARCHAR(255) NOT NULL,
        ip_address VARCHAR(64) NULL,
        port INT NULL,
        normalized_target VARCHAR(512) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        scan_id CHAR(36) NOT NULL,
        started_at DATETIME NOT NULL,
        completed_at DATETIME NULL,
        status VARCHAR(32) NOT NULL,
        target_id BIGINT NOT NULL,
        total_findings INT NOT NULL DEFAULT 0,
        active_requests INT NOT NULL DEFAULT 0,
        plugins_executed TEXT NOT NULL,
        plugins_skipped TEXT NOT NULL,
        average_risk DECIMAL(6, 2) NOT NULL DEFAULT 0,
        maximum_risk DECIMAL(6, 2) NOT NULL DEFAULT 0,
        highest_risk_band VARCHAR(16) NULL,
        UNIQUE KEY uq_scans_scan_id (scan_id),
        KEY idx_scans_started_at (started_at),
        KEY idx_scans_target_id (target_id),
        CONSTRAINT fk_scans_target
            FOREIGN KEY (target_id) REFERENCES targets(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS services (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        scan_id BIGINT NOT NULL,
        host VARCHAR(255) NOT NULL,
        port INT NOT NULL,
        protocol VARCHAR(16) NOT NULL,
        state VARCHAR(32) NOT NULL,
        service VARCHAR(128) NULL,
        product VARCHAR(255) NULL,
        version VARCHAR(255) NULL,
        KEY idx_services_scan_id (scan_id),
        CONSTRAINT fk_services_scan
            FOREIGN KEY (scan_id) REFERENCES scans(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        scan_id BIGINT NOT NULL,
        fingerprint VARCHAR(768) NOT NULL,
        scanner VARCHAR(128) NOT NULL,
        category VARCHAR(128) NOT NULL,
        title VARCHAR(512) NOT NULL,
        description TEXT NOT NULL,
        severity VARCHAR(16) NOT NULL,
        confidence VARCHAR(16) NOT NULL,
        affected_url VARCHAR(2048) NULL,
        parameter VARCHAR(255) NULL,
        remediation TEXT NULL,
        created_at DATETIME NOT NULL,
        UNIQUE KEY uq_findings_scan_fingerprint (scan_id, fingerprint),
        KEY idx_findings_scan_id (scan_id),
        KEY idx_findings_severity (severity),
        KEY idx_findings_fingerprint (fingerprint),
        CONSTRAINT fk_findings_scan
            FOREIGN KEY (scan_id) REFERENCES scans(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        finding_id BIGINT NOT NULL,
        evidence_type VARCHAR(64) NOT NULL,
        url VARCHAR(2048) NULL,
        method VARCHAR(16) NULL,
        status_code INT NULL,
        description TEXT NOT NULL,
        excerpt VARCHAR(512) NULL,
        KEY idx_evidence_finding_id (finding_id),
        CONSTRAINT fk_evidence_finding
            FOREIGN KEY (finding_id) REFERENCES findings(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_assessments (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        finding_id BIGINT NOT NULL,
        risk_score DECIMAL(6, 2) NOT NULL,
        risk_band VARCHAR(16) NOT NULL,
        priority VARCHAR(8) NOT NULL,
        explanation TEXT NOT NULL,
        UNIQUE KEY uq_risk_finding (finding_id),
        KEY idx_risk_score (risk_score),
        CONSTRAINT fk_risk_finding
            FOREIGN KEY (finding_id) REFERENCES findings(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
)


def init_schema(database: Database) -> None:
    """Create tables if missing and record schema version 1."""
    try:
        with database.transaction():
            for statement in SCHEMA_STATEMENTS:
                database.execute(statement)
            existing = database.fetchone(
                "SELECT version FROM schema_version WHERE version = %s",
                (SCHEMA_VERSION,),
            )
            if existing is None:
                database.execute(
                    "INSERT INTO schema_version (version, applied_at) "
                    "VALUES (%s, UTC_TIMESTAMP())",
                    (SCHEMA_VERSION,),
                )
    except DatabaseMigrationError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Schema initialization failed")
        raise DatabaseMigrationError("Could not initialize the database schema.") from exc
    logger.info("Database schema ready (version %s)", SCHEMA_VERSION)
