"""Eligible GET query parameters for active detection plugins."""

from __future__ import annotations

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.enumeration.web.models import Endpoint, Parameter
from vapt_framework.utils.urls import extract_query_params, is_same_origin, normalize_url

_SKIP_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "token",
        "csrf",
        "secret",
        "session",
        "cookie",
        "auth",
        "authorization",
    }
)

PATH_PARAM_NAMES = frozenset(
    {
        "file",
        "filename",
        "filepath",
        "path",
        "page",
        "document",
        "template",
    }
)


def query_targets(
    context: AssessmentContext,
    *,
    path_like_only: bool = False,
) -> tuple[tuple[Endpoint, str], ...]:
    """Return in-scope GET endpoints with query parameter names to test."""
    origins = [
        surface.base_url for surface in context.web_attack_surfaces
    ] + [service.base_url for service in context.reachable_http_services()]
    pairs: list[tuple[Endpoint, str]] = []
    seen: set[tuple[str, str]] = set()
    for surface in context.web_attack_surfaces:
        for endpoint in surface.endpoints:
            if endpoint.method.upper() != "GET":
                continue
            url = normalize_url(endpoint.url)
            if url is None:
                continue
            if origins and not any(is_same_origin(origin, url) for origin in origins):
                continue
            names = [p.name for p in endpoint.parameters if p.location == "query"]
            if not names:
                names = list(extract_query_params(url))
            for name in names:
                key = name.lower()
                if key in _SKIP_NAMES:
                    continue
                if path_like_only and key not in PATH_PARAM_NAMES:
                    continue
                identity = (url, name)
                if identity in seen:
                    continue
                seen.add(identity)
                pairs.append((endpoint, name))
    return tuple(pairs)
