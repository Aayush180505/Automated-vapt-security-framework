"""Settings tests. These tests do not open network or database connections."""

from __future__ import annotations

import pytest

from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import ConfigurationError


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "VAPT_LOG_LEVEL",
        "VAPT_DATABASE_URL",
        "VAPT_REQUEST_TIMEOUT",
        "VAPT_USER_AGENT",
        "VAPT_REPORT_DIR",
        "VAPT_SCAN_OUTPUT_DIR",
        "VAPT_APP_NAME",
        "VAPT_NMAP_TIMEOUT",
        "VAPT_HTTP_TIMEOUT",
        "VAPT_MAX_PAGES",
        "VAPT_MAX_DEPTH",
        "VAPT_TLS_VERIFY",
        "VAPT_MAX_SCANNER_REQUESTS",
        "VAPT_ENABLE_ACTIVE_SCANNERS",
        "VAPT_DATABASE_ENABLED",
        "VAPT_DB_HOST",
        "VAPT_DB_PORT",
        "VAPT_DB_NAME",
        "VAPT_DB_USER",
        "VAPT_DB_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    settings = Settings.from_env()
    assert settings.log_level == "INFO"
    assert settings.database_url == ""
    assert settings.request_timeout == 10.0
    assert "VAPT-Framework" in settings.user_agent
    assert settings.report_directory == "reports"
    assert settings.scan_output_directory == "data/scans"
    assert settings.version == "0.1.0"
    assert settings.nmap_timeout == 120.0
    assert settings.http_timeout == 10.0
    assert settings.max_pages == 50
    assert settings.max_depth == 3
    assert settings.tls_verify is True
    assert settings.max_scanner_requests == 25
    assert settings.enable_active_scanners is True
    assert settings.database_enabled is False


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAPT_LOG_LEVEL", "debug")
    monkeypatch.setenv("VAPT_DATABASE_URL", "mysql://user:password@localhost:3306/vapt")
    monkeypatch.setenv("VAPT_REQUEST_TIMEOUT", "15")
    monkeypatch.setenv("VAPT_REPORT_DIR", "out/reports")
    monkeypatch.setenv("VAPT_NMAP_TIMEOUT", "90")
    monkeypatch.setenv("VAPT_HTTP_TIMEOUT", "8")
    monkeypatch.setenv("VAPT_MAX_PAGES", "20")
    monkeypatch.setenv("VAPT_TLS_VERIFY", "false")
    monkeypatch.setenv("VAPT_MAX_SCANNER_REQUESTS", "5")
    monkeypatch.setenv("VAPT_ENABLE_ACTIVE_SCANNERS", "false")

    settings = Settings.from_env()
    assert settings.log_level == "DEBUG"
    assert settings.database_url.startswith("mysql://")
    assert settings.request_timeout == 15.0
    assert settings.report_directory == "out/reports"
    assert settings.nmap_timeout == 90.0
    assert settings.http_timeout == 8.0
    assert settings.max_pages == 20
    assert settings.tls_verify is False
    assert settings.max_scanner_requests == 5
    assert settings.enable_active_scanners is False


def test_invalid_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAPT_LOG_LEVEL", "VERBOSE")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_invalid_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAPT_REQUEST_TIMEOUT", "fast")
    with pytest.raises(ConfigurationError):
        Settings.from_env()
