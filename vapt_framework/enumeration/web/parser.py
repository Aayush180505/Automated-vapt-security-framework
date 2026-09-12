"""Static HTML parsing: links, forms, and field names. No JavaScript."""

from __future__ import annotations

from bs4 import BeautifulSoup

from vapt_framework.enumeration.web.models import Form, FormField
from vapt_framework.utils.urls import is_unsupported_href_scheme, normalize_url


def extract_title(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    if soup.title and soup.title.string:
        text = soup.title.string.strip()
        return text or None
    return None


def extract_hrefs(html: str) -> tuple[str, ...]:
    soup = BeautifulSoup(html, "html.parser")
    hrefs: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = str(tag.get("href", "")).strip()
        if href and not is_unsupported_href_scheme(href):
            hrefs.append(href)
    return tuple(hrefs)


def extract_forms(html: str, page_url: str) -> tuple[Form, ...]:
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []
    for tag in soup.find_all("form"):
        method = str(tag.get("method") or "get").strip().upper() or "GET"
        if method not in {"GET", "POST"}:
            method = "GET"
        action = str(tag.get("action") or "").strip() or page_url
        action_url = normalize_url(action, page_url)
        if action_url is None:
            continue
        fields = _form_fields(tag)
        forms.append(
            Form(
                action_url=action_url,
                method=method,
                fields=fields,
                source_url=page_url,
            )
        )
    return tuple(forms)


def _form_fields(form_tag: object) -> tuple[FormField, ...]:
    fields: list[FormField] = []
    seen: set[str] = set()
    for tag in form_tag.find_all(["input", "textarea", "select"]):  # type: ignore[attr-defined]
        name = str(tag.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        if tag.name == "textarea":
            field_type = "textarea"
        elif tag.name == "select":
            field_type = "select"
        else:
            field_type = str(tag.get("type") or "text").strip().lower() or "text"
        fields.append(FormField(name=name, field_type=field_type))
    return tuple(fields)


def parse_robots(text: str) -> tuple[tuple[str, str, str], ...]:
    """Return ``(user_agent, directive, value)`` triples."""
    entries: list[tuple[str, str, str]] = []
    current_ua = "*"
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        directive = key.strip().lower()
        argument = value.strip()
        if directive == "user-agent":
            current_ua = argument or "*"
            continue
        if directive in {"disallow", "allow", "sitemap"}:
            entries.append((current_ua, directive, argument))
    return tuple(entries)
