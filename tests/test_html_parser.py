"""HTML parser, form, parameter, and robots tests (no network)."""

from __future__ import annotations

from vapt_framework.enumeration.web.parser import extract_forms, extract_hrefs, parse_robots
from vapt_framework.utils.urls import extract_query_params, normalize_url
from tests.conftest import fixture_text


def test_link_and_form_extraction() -> None:
    html = fixture_text("index.html")
    hrefs = extract_hrefs(html)
    assert "/login" in hrefs
    assert "products" in hrefs
    assert any("search?q=test" in item for item in hrefs)
    assert any("google.com" in item for item in hrefs)
    assert any("#section" in item for item in hrefs)
    assert not any(item.startswith("javascript:") for item in hrefs)
    assert not any(item.startswith("mailto:") for item in hrefs)

    forms = extract_forms(html, "http://10.10.10.10/")
    methods = {form.method for form in forms}
    assert methods == {"GET", "POST"}
    post = next(form for form in forms if form.method == "POST")
    assert post.action_url == "http://10.10.10.10/login"
    names = {field.name for field in post.fields}
    assert names == {"username", "password", "notes", "role"}
    types = {field.name: field.field_type for field in post.fields}
    assert types["notes"] == "textarea"
    assert types["role"] == "select"
    get = next(form for form in forms if form.method == "GET")
    assert get.action_url.endswith("/search")
    assert {field.name for field in get.fields} == {"q", "ref"}


def test_malformed_and_empty_html() -> None:
    assert extract_hrefs(fixture_text("empty.html")) == ()
    assert extract_forms(fixture_text("empty.html"), "http://10.10.10.10/") == ()
    extract_hrefs(fixture_text("malformed.html"))
    extract_forms(fixture_text("malformed.html"), "http://10.10.10.10/")


def test_query_parameters_from_url() -> None:
    assert extract_query_params("http://10.10.10.10/search?q=test&page=2") == (
        "q",
        "page",
    )
    assert normalize_url("http://10.10.10.10/search?q=test&page=2") == (
        "http://10.10.10.10/search?page=2&q=test"
    )


def test_robots_parsing() -> None:
    entries = parse_robots(fixture_text("robots.txt"))
    directives = {(item[1], item[2]) for item in entries}
    assert ("disallow", "/secret") in directives
    assert ("allow", "/") in directives
    assert any(item[1] == "sitemap" for item in entries)
