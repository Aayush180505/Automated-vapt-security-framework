"""URL normalization and same-origin helpers.

Used by the HTTP adapter and crawler. Does not fetch the network.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

_UNSUPPORTED_SCHEMES = frozenset(
    {"javascript", "mailto", "tel", "data", "about", "blob", "file"}
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def is_supported_http_scheme(scheme: str | None) -> bool:
    return (scheme or "").lower() in {"http", "https"}


def is_unsupported_href_scheme(href: str) -> bool:
    stripped = href.strip()
    if ":" not in stripped:
        return False
    scheme = stripped.split(":", 1)[0].lower()
    return scheme in _UNSUPPORTED_SCHEMES


def origin_key(url: str) -> tuple[str, str, int] | None:
    """Return ``(scheme, hostname, port)`` or ``None`` if not an HTTP URL."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if not is_supported_http_scheme(scheme):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    port = parsed.port or _DEFAULT_PORTS[scheme]
    return scheme, host, port


def is_same_origin(left: str, right: str) -> bool:
    origin_left = origin_key(left)
    origin_right = origin_key(right)
    if origin_left is None or origin_right is None:
        return False
    return origin_left == origin_right


def normalize_url(url: str, base: str | None = None) -> str | None:
    """Resolve, strip fragments, and canonicalize an HTTP(S) URL.

    Returns ``None`` for empty values, unsupported schemes, or invalid HTTP URLs.
    """
    raw = (url or "").strip()
    if not raw or raw.startswith("#"):
        return None
    if is_unsupported_href_scheme(raw):
        return None
    joined = urljoin(base or "", raw) if base else raw
    parsed = urlparse(joined)
    scheme = (parsed.scheme or "").lower()
    if not is_supported_http_scheme(scheme):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    if parsed.username or parsed.password:
        return None

    port = parsed.port
    default_port = _DEFAULT_PORTS[scheme]
    if port in (None, default_port):
        netloc = host
    else:
        netloc = f"{host}:{port}"

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = f"/{path}"

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs.sort(key=lambda item: item[0])
    query = urlencode(query_pairs, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def replace_query_param(url: str, name: str, value: str) -> str | None:
    """Return ``url`` with query parameter ``name`` set to ``value``.

    Other parameters are preserved. Fragments are not included.
    """
    parsed = urlparse(url)
    if not is_supported_http_scheme(parsed.scheme):
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    updated: list[tuple[str, str]] = []
    for key, current in pairs:
        if key == name:
            updated.append((key, value))
            found = True
        else:
            updated.append((key, current))
    if not found:
        updated.append((name, value))
    query = urlencode(updated, doseq=True)
    rebuilt = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", query, "")
    )
    return normalize_url(rebuilt)


def extract_query_params(url: str) -> tuple[str, ...]:
    """Return unique query parameter names in first-seen order."""
    parsed = urlparse(url)
    names: list[str] = []
    seen: set[str] = set()
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if name not in seen:
            seen.add(name)
            names.append(name)
    return tuple(names)
