"""High-level persistence: ScanContext in, MySQL out."""

from __future__ import annotations

from dataclasses import dataclass

from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import DatabaseError
from vapt_framework.core.models import ScanContext
from vapt_framework.storage.database import Database
from vapt_framework.storage.models import ScanDetails, ScanHistoryItem
from vapt_framework.storage.repositories import ScanRepository
from vapt_framework.storage.schema import init_schema


@dataclass(frozen=True)
class PersistenceOutcome:
    enabled: bool
    saved: bool
    scan_id: str | None = None
    error: str | None = None


class ScanStorageService:
    """CLI-facing storage API. Scanners never call this."""

    def __init__(self, database: Database) -> None:
        self._database = database
        self._repo = ScanRepository(database)

    @classmethod
    def from_settings(cls, settings: Settings) -> ScanStorageService:
        database = Database.from_settings(settings)
        database.connect()
        return cls(database)

    def close(self) -> None:
        self._database.close()

    def __enter__(self) -> ScanStorageService:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def initialize(self) -> None:
        init_schema(self._database)

    def save(self, context: ScanContext) -> str:
        return self._repo.save_scan_context(context)

    def list_scans(self, limit: int = 20) -> tuple[ScanHistoryItem, ...]:
        return self._repo.list_scans(limit=limit)

    def get_scan(self, scan_id: str) -> ScanDetails | None:
        return self._repo.get_scan(scan_id)


def persist_scan(context: ScanContext, settings: Settings) -> PersistenceOutcome:
    """Save ``context`` when persistence is enabled. Never raises to callers."""
    if not settings.database_enabled:
        return PersistenceOutcome(enabled=False, saved=False, scan_id=context.scan_id)
    try:
        with ScanStorageService.from_settings(settings) as store:
            store.save(context)
        return PersistenceOutcome(
            enabled=True, saved=True, scan_id=context.scan_id
        )
    except DatabaseError:
        return PersistenceOutcome(
            enabled=True,
            saved=False,
            scan_id=context.scan_id,
            error="Database persistence failed. Results were not saved.",
        )
