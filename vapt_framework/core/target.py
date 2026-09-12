"""Target parsing, validation, and normalization.

This module does not perform DNS lookups, HTTP requests, or host discovery.
It only inspects the string the operator supplied.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from vapt_framework.core.exceptions import TargetValidationError

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """Authorized assessment target after local validation and normalization."""

    raw_input: str
    normalized: str
    scheme: str | None
    hostname: str
    port: int | None
    ip_address: str | None
    path: str
    is_valid: bool


def parse_target(raw: str) -> Target:
    """Validate and normalize ``raw`` into a :class:`Target`.

    Accepted forms include HTTP(S) URLs, ``host:port``, hostnames, and IP
    addresses (for example ``10.10.10.10``).
    """
    if raw is None:
        raise TargetValidationError("Target must not be empty.")

    stripped = raw.strip()
    if not stripped:
        raise TargetValidationError("Target must not be empty.")
    if any(ch.isspace() for ch in stripped):
        raise TargetValidationError("Target must not contain whitespace.")

    if "://" in stripped:
        return _from_url(raw, stripped)
    return _from_host(raw, stripped)


def _from_url(raw: str, value: str) -> Target:
    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetValidationError(
            f"Unsupported URL scheme '{parsed.scheme or '(none)'}'. "
            "Use http, https, or a bare host/IP."
        )
    if parsed.username or parsed.password:
        raise TargetValidationError("Targets must not include credentials.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetValidationError("URL is missing a hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Port must be between 1 and 65535.") from exc
    _assert_port(port)
    ip_address = _ip_literal(hostname)
    _assert_hostname(hostname, ip_address)

    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"

    normalized = _build_http_url(scheme, hostname, port, path)
    return Target(
        raw_input=raw,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        ip_address=ip_address,
        path=path or "/",
        is_valid=True,
    )


def _from_host(raw: str, value: str) -> Target:
    host_part, port = _split_host_port(value)
    hostname = host_part.lower()
    ip_address = _ip_literal(hostname)
    _assert_hostname(hostname, ip_address)
    _assert_port(port)

    if port is not None:
        normalized = f"{hostname}:{port}"
    else:
        normalized = hostname

    return Target(
        raw_input=raw,
        normalized=normalized,
        scheme=None,
        hostname=hostname,
        port=port,
        ip_address=ip_address,
        path="",
        is_valid=True,
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.count(":") == 0:
        return value, None
    if value.count(":") == 1:
        host, _, port_text = value.partition(":")
        if not host:
            raise TargetValidationError("Target is missing a hostname.")
        return host, _parse_port(port_text)
    # Multiple colons: treat as IPv6 (no port) if the whole string is an IP.
    if _ip_literal(value) is not None:
        return value, None
    raise TargetValidationError(
        "Ambiguous host:port value. Use an HTTP(S) URL or IPv4 host:port."
    )


def _parse_port(port_text: str) -> int:
    if not port_text.isdigit():
        raise TargetValidationError(f"Invalid port '{port_text}'.")
    port = int(port_text)
    _assert_port(port)
    return port


def _assert_port(port: int | None) -> None:
    if port is None:
        return
    if port < 1 or port > 65535:
        raise TargetValidationError("Port must be between 1 and 65535.")


def _ip_literal(hostname: str) -> str | None:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return None


def _assert_hostname(hostname: str, ip_address: str | None) -> None:
    if ip_address is not None:
        return
    if not _HOSTNAME_RE.match(hostname):
        raise TargetValidationError(f"Invalid hostname '{hostname}'.")


def _build_http_url(scheme: str, hostname: str, port: int | None, path: str) -> str:
    host = hostname
    if ":" in hostname and not hostname.startswith("["):
        host = f"[{hostname}]"
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    if not path:
        return f"{scheme}://{netloc}"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{scheme}://{netloc}{path}"
