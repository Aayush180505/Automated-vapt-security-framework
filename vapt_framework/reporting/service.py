"""Read-only HTML report generation from completed scan data."""

from __future__ import annotations

from pathlib import Path

from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import ReportError
from vapt_framework.core.models import ScanContext
from vapt_framework.reporting.builder import report_data_from_context, report_data_from_details
from vapt_framework.reporting.filenames import html_report_filename
from vapt_framework.reporting.renderer import render_html
from vapt_framework.storage.models import ScanDetails
from vapt_framework.storage.service import ScanStorageService


class ReportService:
    """Load completed results, render HTML, write a file. Never scans."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def write_from_details(self, details: ScanDetails, output_dir: Path | None = None) -> Path:
        data = report_data_from_details(details)
        return self._write(data, output_dir)

    def write_from_context(self, context: ScanContext, output_dir: Path | None = None) -> Path:
        data = report_data_from_context(context)
        return self._write(data, output_dir)

    def write_from_scan_id(self, scan_id: str, storage: ScanStorageService) -> Path:
        details = storage.get_scan(scan_id)
        if details is None:
            raise ReportError("Scan not found.")
        return self.write_from_details(details)

    def _write(self, data, output_dir: Path | None) -> Path:
        directory = Path(output_dir or self._settings.report_directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / html_report_filename(data.scan_id)
        html = render_html(data)
        path.write_text(html, encoding="utf-8")
        return path
