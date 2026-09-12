"""Unit tests for target parsing and severity labels.

These tests perform no network I/O.
"""

from __future__ import annotations

import pytest

from vapt_framework.core.enums import Severity
from vapt_framework.core.exceptions import TargetValidationError
from vapt_framework.core.target import parse_target


def test_valid_http_target() -> None:
    target = parse_target("http://example.local")
    assert target.is_valid
    assert target.scheme == "http"
    assert target.hostname == "example.local"
    assert target.port is None
    assert target.ip_address is None
    assert target.normalized == "http://example.local"


def test_valid_https_target() -> None:
    target = parse_target("https://example.local")
    assert target.scheme == "https"
    assert target.normalized == "https://example.local"


def test_valid_ip_target() -> None:
    target = parse_target("10.10.10.10")
    assert target.scheme is None
    assert target.hostname == "10.10.10.10"
    assert target.ip_address == "10.10.10.10"
    assert target.normalized == "10.10.10.10"


def test_http_ip_target() -> None:
    target = parse_target("http://10.10.10.10")
    assert target.scheme == "http"
    assert target.ip_address == "10.10.10.10"
    assert target.normalized == "http://10.10.10.10"


def test_https_custom_port() -> None:
    target = parse_target("https://10.10.10.10:8443")
    assert target.scheme == "https"
    assert target.port == 8443
    assert target.normalized == "https://10.10.10.10:8443"


def test_bare_ip_with_port() -> None:
    target = parse_target("10.10.10.10:8080")
    assert target.scheme is None
    assert target.port == 8080
    assert target.normalized == "10.10.10.10:8080"


def test_normalization_lowercases_host_and_scheme() -> None:
    target = parse_target("HTTP://Example.LOCAL/Path")
    assert target.scheme == "http"
    assert target.hostname == "example.local"
    assert target.normalized == "http://example.local/Path"


def test_default_http_port_omitted_from_normalized_url() -> None:
    target = parse_target("http://example.local:80")
    assert target.port == 80
    assert target.normalized == "http://example.local"


def test_invalid_empty_target() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("")
    with pytest.raises(TargetValidationError):
        parse_target("   ")


def test_invalid_scheme() -> None:
    with pytest.raises(TargetValidationError, match="Unsupported URL scheme"):
        parse_target("ftp://example.local")


def test_invalid_hostname() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("http://")
    with pytest.raises(TargetValidationError):
        parse_target("not a host")
    with pytest.raises(TargetValidationError):
        parse_target("http://bad_host")


def test_invalid_port() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("http://example.local:99999")
    with pytest.raises(TargetValidationError):
        parse_target("10.10.10.10:abc")


def test_credentials_rejected() -> None:
    with pytest.raises(TargetValidationError, match="credentials"):
        parse_target("http://user:pass@example.local")


def test_severity_enum_values() -> None:
    assert [item.value for item in Severity] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert Severity.INFO.name == "INFO"
    assert Severity.CRITICAL == "critical"
