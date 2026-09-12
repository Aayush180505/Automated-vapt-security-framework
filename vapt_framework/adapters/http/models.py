"""HTTP domain models independent of httpx."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HTTPResponseInfo:
    """Normalized HTTP response metadata (no raw httpx objects)."""

    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    title: str | None = None
    location: str | None = None
    redirect_chain: tuple[str, ...] = ()
    elapsed_ms: int | None = None
    cookie_names: tuple[str, ...] = ()
    body: str | None = None

    def without_body(self) -> HTTPResponseInfo:
        """Return a copy safe to persist without HTML."""
        if self.body is None:
            return self
        return HTTPResponseInfo(
            requested_url=self.requested_url,
            final_url=self.final_url,
            status_code=self.status_code,
            headers=self.headers,
            content_type=self.content_type,
            content_length=self.content_length,
            server=self.server,
            title=self.title,
            location=self.location,
            redirect_chain=self.redirect_chain,
            elapsed_ms=self.elapsed_ms,
            cookie_names=self.cookie_names,
            body=None,
        )


@dataclass(frozen=True)
class HTTPService:
    """A discovered HTTP or HTTPS service after optional probing."""

    scheme: str
    host: str
    port: int
    base_url: str
    detected_service: str
    reachable: bool
    response: HTTPResponseInfo | None = None
    error: str | None = None
