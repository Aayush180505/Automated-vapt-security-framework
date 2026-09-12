"""Safe report filenames. Targets never become paths."""

from __future__ import annotations

import re

_SAFE = re.compile(r"[^A-Za-z0-9-]")


def safe_scan_token(scan_id: str) -> str:
    cleaned = _SAFE.sub("", scan_id.strip())
    return cleaned[:64] or "unknown"


def html_report_filename(scan_id: str) -> str:
    return f"vapt_report_{safe_scan_token(scan_id)}.html"
