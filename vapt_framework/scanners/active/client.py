"""GET-only HTTP helper for active scanners.

Enforces request budgets, same-origin scope, and does not follow
out-of-scope redirects. Scanners must not call httpx directly.
"""

from __future__ import annotations

from urllib.parse import urlparse

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.adapters.http.models import HTTPResponseInfo
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import is_same_origin, normalize_url

logger = get_logger("vapt_framework.scanners.active.client")

_REDIRECTS = frozenset({301, 302, 303, 307, 308})


class ScannerHttpClient:
    """Budgeted, in-scope GET client wrapping :class:`HttpClient`."""

    def __init__(
        self,
        http: HttpClient,
        origins: tuple[str, ...],
        max_requests: int,
    ) -> None:
        self._http = http
        self._origins = origins
        self.max_requests = max_requests
        self.request_count = 0
        self.limit_reached = False

    def get(
        self,
        url: str,
        *,
        plugin: str,
        parameter: str,
    ) -> HTTPResponseInfo | None:
        """GET ``url`` if in scope and under budget. Never POST."""
        if self.request_count >= self.max_requests:
            self.limit_reached = True
            logger.info(
                "Request limit reached plugin=%s requests=%s",
                plugin,
                self.request_count,
            )
            return None
        normalized = normalize_url(url)
        if normalized is None or not self._in_scope(normalized):
            logger.info("Out-of-scope scanner GET skipped plugin=%s", plugin)
            return None
        self.request_count += 1
        logger.info(
            "scanner=%s method=GET param=%s request=%s path=%s",
            plugin,
            parameter,
            self.request_count,
            _path_only(normalized),
        )
        try:
            response = self._http.request(
                "GET",
                normalized,
                follow_redirects=False,
                include_body=True,
            )
        except HTTPProbeError:
            raise
        if response.status_code in _REDIRECTS and response.location:
            nxt = normalize_url(response.location, normalized)
            if nxt is None or not self._in_scope(nxt):
                logger.info("Redirect left scope; not followed plugin=%s", plugin)
                return response
        return response

    def _in_scope(self, url: str) -> bool:
        if not self._origins:
            return False
        return any(is_same_origin(origin, url) for origin in self._origins)


def allowed_origins(context_surfaces_and_services: tuple[str, ...]) -> tuple[str, ...]:
    origins: list[str] = []
    for item in context_surfaces_and_services:
        normalized = normalize_url(item)
        if normalized and normalized not in origins:
            origins.append(normalized)
    return tuple(origins)


def _path_only(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = parsed.path or "/"
    return f"{parsed.scheme}://{netloc}{path}"
