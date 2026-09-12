"""Web attack-surface domain models for future assessment plugins."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Parameter:
    """A named input on an endpoint or form (name only; no values)."""

    name: str
    location: str
    endpoint_url: str | None = None


@dataclass(frozen=True)
class FormField:
    """A discovered form control (name and type only)."""

    name: str
    field_type: str


@dataclass(frozen=True)
class Form:
    """HTML form discovered during crawling. Forms are not submitted."""

    action_url: str
    method: str
    fields: tuple[FormField, ...]
    source_url: str


@dataclass(frozen=True)
class Endpoint:
    """A requestable in-scope URL and method for later scanners."""

    method: str
    url: str
    path: str
    parameters: tuple[Parameter, ...]
    source: str
    content_type: str | None = None


@dataclass(frozen=True)
class RobotsEntry:
    """A robots.txt directive. Not treated as a finding."""

    user_agent: str
    directive: str
    value: str


@dataclass(frozen=True)
class WebAttackSurface:
    """Structured surface of one HTTP origin."""

    base_url: str
    endpoints: tuple[Endpoint, ...] = ()
    forms: tuple[Form, ...] = ()
    parameters: tuple[Parameter, ...] = ()
    robots_entries: tuple[RobotsEntry, ...] = ()
    external_references: tuple[str, ...] = ()
    pages_crawled: int = 0
    error: str | None = None
