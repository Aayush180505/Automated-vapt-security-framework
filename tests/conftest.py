from __future__ import annotations

from pathlib import Path

import httpx


def fixture_text(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8")


def lab_http_handler(request: httpx.Request) -> httpx.Response:
    """Deterministic in-memory lab app for HTTP tests (no network)."""
    path = request.url.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/") or "/"

    if path == "/timeout":
        raise httpx.TimeoutException("timed out")
    if path == "/down":
        raise httpx.ConnectError("connection failed")
    if path == "/redirect":
        return httpx.Response(302, headers={"Location": "/login"})
    if path == "/external-redirect":
        return httpx.Response(302, headers={"Location": "https://example.invalid/out"})
    if path == "/head-only":
        if request.method == "HEAD":
            return httpx.Response(
                405,
                headers={"Content-Type": "text/html", "Server": "Apache"},
            )
        return httpx.Response(
            200,
            text="<html><head><title>Head Fallback</title></head><body>ok</body></html>",
            headers={"Content-Type": "text/html", "Server": "Apache"},
        )
    if path == "/robots.txt":
        return httpx.Response(
            200,
            text=fixture_text("robots.txt"),
            headers={"Content-Type": "text/plain"},
        )
    if path == "/secret":
        return httpx.Response(200, text="<html><body>secret</body></html>")
    if path == "/chain1":
        return httpx.Response(
            200,
            text='<html><a href="/chain2">next</a></html>',
            headers={"Content-Type": "text/html"},
        )
    if path == "/chain2":
        return httpx.Response(
            200,
            text='<html><a href="/chain3">next</a></html>',
            headers={"Content-Type": "text/html"},
        )
    if path == "/chain3":
        return httpx.Response(200, text="<html><body>deep</body></html>")
    if path == "/many":
        links = "".join(f'<a href="/p{i}">n</a>' for i in range(8))
        return httpx.Response(
            200,
            text=f"<html><body>{links}</body></html>",
            headers={"Content-Type": "text/html"},
        )
    for i in range(8):
        if path == f"/p{i}":
            return httpx.Response(
                200,
                text=f"<html><body>p{i}</body></html>",
                headers={"Content-Type": "text/html"},
            )

    files = {
        "/": "index.html",
        "/login": "login.html",
        "/products": "products.html",
        "/search": "search.html",
        "/page": "page.html",
        "/empty": "empty.html",
        "/malformed": "malformed.html",
    }
    name = files.get(path)
    if name is None:
        return httpx.Response(404, text="not found")
    headers = {
        "Content-Type": "text/html",
        "Server": "Apache",
        "Set-Cookie": "sessionid=not-a-secret-for-storage; HttpOnly",
    }
    if request.method == "HEAD":
        return httpx.Response(200, headers=headers)
    return httpx.Response(200, text=fixture_text(name), headers=headers)


def lab_client():
    from vapt_framework.adapters.http.client import HttpClient

    return HttpClient(
        timeout=5.0,
        user_agent="VAPT-Framework-Test/0.1",
        verify_tls=True,
        max_redirects=5,
        transport=httpx.MockTransport(lab_http_handler),
    )


def query_value(request: httpx.Request, name: str) -> str:
    """Read a query parameter from a mocked httpx request."""
    return request.url.params.get(name, "")
