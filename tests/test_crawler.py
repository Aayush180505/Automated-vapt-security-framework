"""Crawler tests using MockTransport (no live HTTP)."""

from __future__ import annotations

from vapt_framework.enumeration.web.crawler import CrawlLimits, crawl_web
from tests.conftest import lab_client


def test_basic_crawl_discovers_links_forms_and_params() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3),
        )
        urls = {endpoint.url for endpoint in surface.endpoints}
        assert "http://10.10.10.10/" in urls
        assert "http://10.10.10.10/login" in urls
        assert "http://10.10.10.10/products" in urls
        assert any("/search?" in url or url.endswith("/search") for url in urls)
        assert "http://10.10.10.10/page" in urls
        assert surface.pages_crawled >= 4
        assert any(form.method == "POST" for form in surface.forms)
        assert any(form.method == "GET" for form in surface.forms)
        param_names = {param.name for param in surface.parameters}
        assert {"q", "username", "password", "notes", "role"}.issubset(param_names)
        assert any("google.com" in ref for ref in surface.external_references)
        assert all("google.com" not in endpoint.url for endpoint in surface.endpoints)
        methods = {endpoint.method for endpoint in surface.endpoints}
        assert "POST" in methods
    finally:
        client.close()


def test_duplicate_url_prevention() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3),
        )
        keys = [(item.method, item.url) for item in surface.endpoints]
        assert len(keys) == len(set(keys))
        form_keys = [(item.method, item.action_url) for item in surface.forms]
        assert len(form_keys) == len(set(form_keys))
    finally:
        client.close()


def test_max_pages_limit() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/many",
            client,
            CrawlLimits(max_pages=3, max_depth=3),
        )
        assert surface.pages_crawled <= 3
    finally:
        client.close()


def test_max_depth_limit() -> None:
    client = lab_client()
    try:
        shallow = crawl_web(
            "http://10.10.10.10/chain1",
            client,
            CrawlLimits(max_pages=20, max_depth=0),
        )
        urls = {endpoint.url for endpoint in shallow.endpoints}
        assert "http://10.10.10.10/chain1" in urls
        assert "http://10.10.10.10/chain3" not in urls
    finally:
        client.close()


def test_same_origin_and_external_not_crawled() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3),
        )
        assert any("google.com" in ref for ref in surface.external_references)
        assert all(endpoint.url.startswith("http://10.10.10.10") for endpoint in surface.endpoints)
        assert all(":8080" not in endpoint.url for endpoint in surface.endpoints)
    finally:
        client.close()


def test_robots_discovered_and_disallow_not_crawled() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3, respect_robots=True),
        )
        assert any(entry.directive == "disallow" for entry in surface.robots_entries)
        assert all("/secret" not in endpoint.url for endpoint in surface.endpoints)
    finally:
        client.close()


def test_unsupported_schemes_not_queued() -> None:
    client = lab_client()
    try:
        surface = crawl_web(
            "http://10.10.10.10/",
            client,
            CrawlLimits(max_pages=50, max_depth=3),
        )
        joined = " ".join(endpoint.url for endpoint in surface.endpoints)
        assert "javascript:" not in joined
        assert "mailto:" not in joined
    finally:
        client.close()
