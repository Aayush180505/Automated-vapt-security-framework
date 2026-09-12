"""Scanner plugins."""

from __future__ import annotations

from typing import Any

__all__ = ["ActivePlugin", "SecurityPlugin"]


def __getattr__(name: str) -> Any:
    if name in {"ActivePlugin", "SecurityPlugin"}:
        from vapt_framework.scanners.base import ActivePlugin, SecurityPlugin

        return ActivePlugin if name == "ActivePlugin" else SecurityPlugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
