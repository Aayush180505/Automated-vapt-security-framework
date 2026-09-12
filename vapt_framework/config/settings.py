"""Application settings loaded from environment variables.

Secrets must never be hardcoded. MySQL persistence is opt-in via VAPT_DATABASE_ENABLED.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from vapt_framework import __app_name__, __version__
from vapt_framework.core.exceptions import ConfigurationError

_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class Settings:
    """Runtime configuration for the framework."""

    app_name: str = __app_name__
    version: str = __version__
    log_level: str = "INFO"
    database_url: str = ""
    request_timeout: float = 10.0
    http_timeout: float = 10.0
    user_agent: str = "VAPT-Framework/0.1 (+authorized-assessment)"
    report_directory: str = "reports"
    scan_output_directory: str = "data/scans"
    nmap_timeout: float = 120.0
    max_pages: int = 50
    max_depth: int = 3
    max_redirects: int = 5
    max_response_bytes: int = 1_000_000
    tls_verify: bool = True
    max_scanner_requests: int = 25
    enable_active_scanners: bool = True
    database_enabled: bool = False
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "vapt_framework"
    db_user: str = "vapt_user"
    db_password: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from process environment variables."""
        log_level = os.getenv("VAPT_LOG_LEVEL", "INFO").strip().upper()
        if log_level not in _VALID_LOG_LEVELS:
            raise ConfigurationError(
                f"Invalid VAPT_LOG_LEVEL '{log_level}'. "
                f"Expected one of: {', '.join(sorted(_VALID_LOG_LEVELS))}."
            )

        request_timeout = _positive_float("VAPT_REQUEST_TIMEOUT", "10")
        if os.getenv("VAPT_HTTP_TIMEOUT"):
            http_timeout = _positive_float("VAPT_HTTP_TIMEOUT", "10")
        else:
            http_timeout = request_timeout
        nmap_timeout = _positive_float("VAPT_NMAP_TIMEOUT", "120")

        return cls(
            app_name=os.getenv("VAPT_APP_NAME", __app_name__).strip() or __app_name__,
            version=__version__,
            log_level=log_level,
            database_url=os.getenv("VAPT_DATABASE_URL", "").strip(),
            request_timeout=request_timeout,
            http_timeout=http_timeout,
            user_agent=os.getenv(
                "VAPT_USER_AGENT",
                "VAPT-Framework/0.1 (+authorized-assessment)",
            ).strip(),
            report_directory=os.getenv("VAPT_REPORT_DIR", "reports").strip() or "reports",
            scan_output_directory=os.getenv(
                "VAPT_SCAN_OUTPUT_DIR", "data/scans"
            ).strip()
            or "data/scans",
            nmap_timeout=nmap_timeout,
            max_pages=_positive_int("VAPT_MAX_PAGES", "50"),
            max_depth=_positive_int("VAPT_MAX_DEPTH", "3"),
            max_redirects=_positive_int("VAPT_MAX_REDIRECTS", "5"),
            max_response_bytes=_positive_int("VAPT_MAX_RESPONSE_BYTES", "1000000"),
            tls_verify=_env_bool("VAPT_TLS_VERIFY", True),
            max_scanner_requests=_positive_int("VAPT_MAX_SCANNER_REQUESTS", "25"),
            enable_active_scanners=_env_bool("VAPT_ENABLE_ACTIVE_SCANNERS", True),
            database_enabled=_env_bool("VAPT_DATABASE_ENABLED", False),
            db_host=os.getenv("VAPT_DB_HOST", "localhost").strip() or "localhost",
            db_port=_positive_int("VAPT_DB_PORT", "3306"),
            db_name=os.getenv("VAPT_DB_NAME", "vapt_framework").strip()
            or "vapt_framework",
            db_user=os.getenv("VAPT_DB_USER", "vapt_user").strip() or "vapt_user",
            db_password=os.getenv("VAPT_DB_PASSWORD", "").strip(),
        )


def _positive_float(name: str, default: str) -> float:
    raw = os.getenv(name, default)
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number of seconds.") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be greater than zero.")
    return value


def _positive_int(name: str, default: str) -> int:
    raw = os.getenv(name, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive integer.") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be greater than zero.")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigurationError(f"{name} must be true or false.")
