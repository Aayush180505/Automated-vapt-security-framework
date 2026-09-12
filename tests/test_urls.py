"""URL normalization and same-origin tests (no network)."""

from __future__ import annotations

from vapt_framework.utils.urls import (
    extract_query_params,
    is_same_origin,
    is_unsupported_href_scheme,
    normalize_url,
    replace_query_param,
)


def test_relative_url_normalization() -> None:
    assert (
        normalize_url("products", "http://10.10.10.10/app/")
        == "http://10.10.10.10/app/products"
    )


def test_absolute_url_normalization() -> None:
    assert (
        normalize_url("HTTP://10.10.10.10/Login")
        == "http://10.10.10.10/Login"
    )


def test_fragment_removal() -> None:
    assert (
        normalize_url("http://10.10.10.10/page#section")
        == "http://10.10.10.10/page"
    )
    assert normalize_url("#section", "http://10.10.10.10/page") is None


def test_query_parameter_preservation() -> None:
    assert (
        normalize_url("http://10.10.10.10/search?q=test&page=2")
        == "http://10.10.10.10/search?page=2&q=test"
    )
    assert extract_query_params("http://10.10.10.10/search?q=test&page=2") == (
        "q",
        "page",
    )


def test_duplicate_query_names() -> None:
    names = extract_query_params("http://10.10.10.10/x?q=1&q=2&z=3")
    assert names == ("q", "z")


def test_external_url_detection() -> None:
    assert not is_same_origin("http://10.10.10.10/", "https://google.com/")
    assert not is_same_origin("http://10.10.10.10/", "http://external.example/")


def test_different_port_is_not_same_origin() -> None:
    assert not is_same_origin("http://10.10.10.10/", "http://10.10.10.10:8080/")
    assert is_same_origin("http://10.10.10.10/", "http://10.10.10.10:80/")


def test_replace_query_param_preserves_others() -> None:
    updated = replace_query_param(
        "http://10.10.10.10/search?q=test&page=2", "q", "VAPTREFLECT123"
    )
    assert updated is not None
    assert "page=2" in updated
    assert "VAPTREFLECT123" in updated
    assert "q=test" not in updated


def test_unsupported_schemes() -> None:
    assert is_unsupported_href_scheme("javascript:alert(1)")
    assert is_unsupported_href_scheme("mailto:a@b.c")
    assert is_unsupported_href_scheme("tel:123")
    assert normalize_url("javascript:void(0)", "http://10.10.10.10/") is None
