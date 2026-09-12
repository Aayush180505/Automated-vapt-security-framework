"""HTTP transport wrapper around httpx."""

from __future__ import annotations

import time
from collections.abc import Mapping

import httpx

from vapt_framework.adapters.http.models import HTTPResponseInfo
from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import normalize_url

logger = get_logger("vapt_framework.adapters.http.client")

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_SAFE_HEADER_NAMES = frozenset(
    {
        "server",
        "content-type",
        "content-length",
        "location",
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "www-authenticate",
        "x-powered-by",
        "cache-control",
    }
)
_MAX_BODY = 1_000_000


class HttpClient:
    """Configurable HTTP client. Does not send payloads or credentials."""

    def __init__(
        self,
        *,
        timeout: float,
        user_agent: str,
        verify_tls: bool,
        max_redirects: int,
        max_response_bytes: int = _MAX_BODY,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes
        self._client = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": user_agent},
            verify=verify_tls,
            follow_redirects=False,
            transport=transport,
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> HttpClient:
        return cls(
            timeout=settings.http_timeout,
            user_agent=settings.user_agent,
            verify_tls=settings.tls_verify,
            max_redirects=settings.max_redirects,
            max_response_bytes=settings.max_response_bytes,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = False,
        include_body: bool = False,
    ) -> HTTPResponseInfo:
        """Send a single method. Optionally follow redirects (probe only)."""
        current = url
        chain: list[str] = []
        last: HTTPResponseInfo | None = None
        hops = self._max_redirects if follow_redirects else 0
        for _ in range(hops + 1):
            last = self._send(method, current, include_body=include_body)
            if not follow_redirects:
                return last
            if last.status_code in _REDIRECT_STATUS and last.location:
                nxt = normalize_url(last.location, current)
                if nxt is None:
                    raise HTTPProbeError("HTTP redirect target is invalid.")
                chain.append(nxt)
                current = nxt
                continue
            return HTTPResponseInfo(
                requested_url=url,
                final_url=last.final_url,
                status_code=last.status_code,
                headers=last.headers,
                content_type=last.content_type,
                content_length=last.content_length,
                server=last.server,
                title=last.title,
                location=last.location,
                redirect_chain=tuple(chain),
                elapsed_ms=last.elapsed_ms,
                cookie_names=last.cookie_names,
                body=last.body,
            )
        raise HTTPProbeError("HTTP redirect limit exceeded.")

    def _send(self, method: str, url: str, *, include_body: bool) -> HTTPResponseInfo:
        started = time.perf_counter()
        try:
            response = self._client.request(method.upper(), url)
        except httpx.TimeoutException as exc:
            raise HTTPProbeError("HTTP request timed out.") from exc
        except httpx.ConnectError as exc:
            raise HTTPProbeError("HTTP connection failed.") from exc
        except httpx.TooManyRedirects as exc:
            raise HTTPProbeError("HTTP redirect limit exceeded.") from exc
        except httpx.HTTPError as exc:
            raise HTTPProbeError("HTTP request failed.") from exc

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        headers = _safe_headers(response.headers)
        body = None
        title = None
        if include_body:
            body = response.text[: self._max_response_bytes]
            title = _extract_title(body)
        content_type = headers.get("content-type")
        length = _content_length(headers, body)
        return HTTPResponseInfo(
            requested_url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers=headers,
            content_type=content_type,
            content_length=length,
            server=headers.get("server"),
            title=title,
            location=response.headers.get("location"),
            elapsed_ms=elapsed_ms,
            cookie_names=_cookie_names(response.headers),
            body=body,
        )


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    stored: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in _SAFE_HEADER_NAMES:
            stored[lower] = value
    return stored


def _content_length(headers: Mapping[str, str], body: str | None) -> int | None:
    raw = headers.get("content-length")
    if raw and raw.isdigit():
        return int(raw)
    if body is not None:
        return len(body.encode("utf-8", errors="replace"))
    return None


def _cookie_names(headers: Mapping[str, str]) -> tuple[str, ...]:
    raw: list[str] = []
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        raw = list(getter("set-cookie"))
    else:
        value = headers.get("set-cookie")
        if value:
            raw = [value]
    names: list[str] = []
    for item in raw:
        name = item.split(";", 1)[0].split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _extract_title(body: str) -> str | None:
    lower = body.lower()
    start = lower.find("<title")
    if start < 0:
        return None
    gt = body.find(">", start)
    end = lower.find("</title>", gt)
    if gt < 0 or end < 0:
        return None
    title = body[gt + 1 : end].strip()
    return title or None
