"""Same-origin static HTML crawler. Discovery only: no form posts, no payloads."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

from vapt_framework.adapters.http.client import HttpClient
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.enumeration.web.models import (
    Endpoint,
    Form,
    Parameter,
    RobotsEntry,
    WebAttackSurface,
)
from vapt_framework.enumeration.web.parser import extract_forms, extract_hrefs, parse_robots
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import (
    extract_query_params,
    is_same_origin,
    normalize_url,
)

logger = get_logger("vapt_framework.enumeration.web.crawler")

_REDIRECTS = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class CrawlLimits:
    max_pages: int
    max_depth: int
    respect_robots: bool = True


def crawl_web(
    base_url: str,
    client: HttpClient,
    limits: CrawlLimits,
) -> WebAttackSurface:
    """Crawl in-scope HTML starting at ``base_url``."""
    origin = normalize_url(base_url)
    if origin is None:
        return WebAttackSurface(base_url=base_url, error="Invalid crawl base URL.")

    logger.info("Crawl started: %s", origin)
    robots_entries, disallowed = _load_robots(origin, client, limits.respect_robots)

    queue: deque[tuple[str, int]] = deque([(origin, 0)])
    visited: set[str] = set()
    endpoints: dict[tuple[str, str], Endpoint] = {}
    forms: dict[tuple[str, str], Form] = {}
    external: set[str] = set()
    pages = 0
    limit_reached = False

    while queue:
        url, depth = queue.popleft()
        if url in visited:
            continue
        if pages >= limits.max_pages:
            limit_reached = True
            logger.info("Crawl page limit reached (%s)", limits.max_pages)
            break
        if depth > limits.max_depth:
            continue
        if limits.respect_robots and _is_disallowed(url, origin, disallowed):
            logger.info("Skipping robots.txt Disallow path: %s", urlparse(url).path)
            continue

        visited.add(url)
        try:
            response = client.request("GET", url, follow_redirects=False, include_body=True)
        except HTTPProbeError as exc:
            logger.warning("Crawl request failed: %s (%s)", url, exc)
            continue

        if response.status_code in _REDIRECTS and response.location:
            nxt = normalize_url(response.location, url)
            if nxt is None:
                continue
            if is_same_origin(origin, nxt):
                if nxt not in visited:
                    queue.append((nxt, depth))
            else:
                external.add(nxt)
            continue

        if response.status_code >= 400:
            continue

        pages += 1
        _add_get_endpoint(endpoints, url, response.content_type, source="crawl")
        logger.info("URL discovered: %s", url)

        html = response.body or ""
        content_type = (response.content_type or "").lower()
        if html and ("html" in content_type or "<html" in html.lower() or "<form" in html.lower()):
            for href in extract_hrefs(html):
                resolved = normalize_url(href, url)
                if resolved is None:
                    continue
                if not is_same_origin(origin, resolved):
                    external.add(resolved)
                    continue
                if resolved not in visited and depth < limits.max_depth:
                    queue.append((resolved, depth + 1))
                    logger.debug("URL queued: %s", resolved)
            for form in extract_forms(html, url):
                if not is_same_origin(origin, form.action_url):
                    external.add(form.action_url)
                    continue
                forms[(form.method, form.action_url)] = form
                logger.info("Form discovered: %s %s", form.method, form.action_url)
                _add_form_endpoint(endpoints, form)

    if limit_reached:
        logger.info("Crawl completed with page limit: %s", origin)
    else:
        logger.info("Crawl completed: %s pages=%s", origin, pages)

    return _build_surface(origin, endpoints, forms, robots_entries, external, pages)


def _load_robots(
    origin: str,
    client: HttpClient,
    respect: bool,
) -> tuple[tuple[RobotsEntry, ...], tuple[str, ...]]:
    robots_url = normalize_url("/robots.txt", origin)
    if robots_url is None:
        return (), ()
    try:
        response = client.request("GET", robots_url, include_body=True)
    except HTTPProbeError:
        return (), ()
    if response.status_code != 200 or not response.body:
        return (), ()
    parsed = parse_robots(response.body)
    entries = tuple(
        RobotsEntry(user_agent=ua, directive=directive, value=value)
        for ua, directive, value in parsed
    )
    disallowed: list[str] = []
    if respect:
        for entry in entries:
            if entry.directive == "disallow" and entry.value:
                disallowed.append(entry.value)
    logger.info("robots.txt discovery: %s entries", len(entries))
    return entries, tuple(disallowed)


def _is_disallowed(url: str, origin: str, prefixes: tuple[str, ...]) -> bool:
    path = urlparse(url).path or "/"
    for prefix in prefixes:
        if not prefix:
            continue
        if prefix == "/":
            return True
        if prefix.endswith("/"):
            if path.startswith(prefix) or path + "/" == prefix:
                return True
        elif path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _add_get_endpoint(
    endpoints: dict[tuple[str, str], Endpoint],
    url: str,
    content_type: str | None,
    source: str,
) -> None:
    names = extract_query_params(url)
    params = tuple(
        Parameter(name=name, location="query", endpoint_url=url) for name in names
    )
    path = urlparse(url).path or "/"
    endpoints.setdefault(
        ("GET", url),
        Endpoint(
            method="GET",
            url=url,
            path=path,
            parameters=params,
            source=source,
            content_type=content_type,
        ),
    )


def _add_form_endpoint(
    endpoints: dict[tuple[str, str], Endpoint],
    form: Form,
) -> None:
    params = tuple(
        Parameter(name=field.name, location="form", endpoint_url=form.action_url)
        for field in form.fields
    )
    path = urlparse(form.action_url).path or "/"
    key = (form.method, form.action_url)
    existing = endpoints.get(key)
    if existing is None:
        endpoints[key] = Endpoint(
            method=form.method,
            url=form.action_url,
            path=path,
            parameters=params,
            source="form",
            content_type=None,
        )
        return
    merged = _merge_params(existing.parameters, params)
    endpoints[key] = Endpoint(
        method=existing.method,
        url=existing.url,
        path=existing.path,
        parameters=merged,
        source=existing.source,
        content_type=existing.content_type,
    )


def _merge_params(
    left: tuple[Parameter, ...],
    right: tuple[Parameter, ...],
) -> tuple[Parameter, ...]:
    seen = {item.name: item for item in left}
    ordered = list(left)
    for item in right:
        if item.name not in seen:
            seen[item.name] = item
            ordered.append(item)
    return tuple(ordered)


def _build_surface(
    origin: str,
    endpoints: dict[tuple[str, str], Endpoint],
    forms: dict[tuple[str, str], Form],
    robots_entries: tuple[RobotsEntry, ...],
    external: set[str],
    pages: int,
) -> WebAttackSurface:
    endpoint_list = tuple(
        sorted(endpoints.values(), key=lambda item: (item.method, item.url))
    )
    form_list = tuple(
        sorted(forms.values(), key=lambda item: (item.method, item.action_url))
    )
    param_map: dict[tuple[str, str], Parameter] = {}
    for endpoint in endpoint_list:
        for param in endpoint.parameters:
            param_map.setdefault((param.name, param.location), param)
    for form in form_list:
        for field in form.fields:
            param = Parameter(
                name=field.name, location="form", endpoint_url=form.action_url
            )
            param_map.setdefault((param.name, param.location), param)
    parameters = tuple(sorted(param_map.values(), key=lambda item: (item.location, item.name)))
    return WebAttackSurface(
        base_url=origin,
        endpoints=endpoint_list,
        forms=form_list,
        parameters=parameters,
        robots_entries=robots_entries,
        external_references=tuple(sorted(external)),
        pages_crawled=pages,
    )
