"""Explicit plugin registry. No import-path scanning in Phase 4."""

from __future__ import annotations

from vapt_framework.core.exceptions import PluginRegistryError
from vapt_framework.scanners.base import SecurityPlugin
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.assessment.registry")


class PluginRegistry:
    """Name-keyed set of assessment plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, SecurityPlugin] = {}

    def register(self, plugin: SecurityPlugin) -> None:
        name = getattr(plugin, "name", "") or ""
        if not name.strip():
            raise PluginRegistryError("Plugin is missing a name.")
        if name in self._plugins:
            raise PluginRegistryError(f"Plugin already registered: {name}")
        self._plugins[name] = plugin
        logger.info("Plugin loaded: %s v%s", name, getattr(plugin, "version", "?"))

    def get(self, name: str) -> SecurityPlugin | None:
        return self._plugins.get(name)

    def get_all(self) -> tuple[SecurityPlugin, ...]:
        return tuple(self._plugins.values())

    def names(self) -> tuple[str, ...]:
        return tuple(self._plugins)


def default_registry() -> PluginRegistry:
    """Built-in plugins in execution order: passive, then active."""
    from vapt_framework.scanners.headers.scanner import SecurityHeadersPlugin
    from vapt_framework.scanners.information_disclosure.scanner import (
        InformationDisclosurePlugin,
    )
    from vapt_framework.scanners.path_traversal.scanner import PathTraversalPlugin
    from vapt_framework.scanners.sql_injection.scanner import SQLInjectionPlugin
    from vapt_framework.scanners.xss.scanner import ReflectedXSSPlugin

    registry = PluginRegistry()
    registry.register(SecurityHeadersPlugin())
    registry.register(InformationDisclosurePlugin())
    registry.register(SQLInjectionPlugin())
    registry.register(ReflectedXSSPlugin())
    registry.register(PathTraversalPlugin())
    return registry
