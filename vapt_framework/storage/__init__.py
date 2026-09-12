"""MySQL persistence for completed assessments."""

from vapt_framework.storage.database import Database
from vapt_framework.storage.service import ScanStorageService, persist_scan

__all__ = ["Database", "ScanStorageService", "persist_scan"]
