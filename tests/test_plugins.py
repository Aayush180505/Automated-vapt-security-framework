"""Plugin contract and registry tests."""

from __future__ import annotations

import pytest

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.registry import PluginRegistry, default_registry
from vapt_framework.core.exceptions import PluginRegistryError
from vapt_framework.core.models import Finding, ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.scanners.base import SecurityPlugin
from vapt_framework.scanners.headers.scanner import SecurityHeadersPlugin
from vapt_framework.scanners.information_disclosure.scanner import (
    InformationDisclosurePlugin,
)
from vapt_framework.scanners.path_traversal.scanner import PathTraversalPlugin
from vapt_framework.scanners.sql_injection.scanner import SQLInjectionPlugin
from vapt_framework.scanners.xss.scanner import ReflectedXSSPlugin


class DummyPlugin(SecurityPlugin):
    name = "dummy"
    description = "Test plugin"
    version = "9.9.9"
    supported_types = ("http",)

    def check(self, context: AssessmentContext) -> list[Finding]:
        return []


def test_plugin_interface_and_metadata() -> None:
    plugin = DummyPlugin()
    assert plugin.name == "dummy"
    assert plugin.description
    assert plugin.version == "9.9.9"
    context = AssessmentContext(scan=ScanContext(target=parse_target("10.10.10.10")))
    assert plugin.applies_to(context) is False
    assert plugin.check(context) == []


def test_plugin_registration_and_retrieval() -> None:
    registry = PluginRegistry()
    first = DummyPlugin()
    registry.register(first)
    assert registry.get("dummy") is first
    assert registry.get_all() == (first,)
    assert registry.names() == ("dummy",)


def test_duplicate_registration_rejected() -> None:
    registry = PluginRegistry()
    registry.register(DummyPlugin())
    with pytest.raises(PluginRegistryError, match="already registered"):
        registry.register(DummyPlugin())


def test_builtin_plugin_metadata() -> None:
    headers = SecurityHeadersPlugin()
    disclosure = InformationDisclosurePlugin()
    assert headers.name == "security-headers"
    assert "header" in headers.description.lower()
    assert disclosure.name == "information-disclosure"
    assert headers.supported_types == ("http",)
    assert headers.is_active is False
    assert disclosure.is_active is False
    assert SQLInjectionPlugin().is_active is True
    assert ReflectedXSSPlugin().is_active is True
    assert PathTraversalPlugin().is_active is True


def test_default_registry_order() -> None:
    assert default_registry().names() == (
        "security-headers",
        "information-disclosure",
        "sql-injection",
        "reflected-xss",
        "path-traversal",
    )
