"""Assessment plugin contract.

Future scanners implement this same interface without changing
the engine, CLI, or Finding model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.models import Finding


class SecurityPlugin(ABC):
    """Base class for all security assessment plugins."""

    name: str
    description: str
    version: str = "0.1.0"
    is_active: bool = False
    supported_types: tuple[str, ...] = ("http",)

    def applies_to(self, context: AssessmentContext) -> bool:
        """Return True when this plugin has enough input to run."""
        if self.is_active:
            if context.settings is not None and not context.settings.enable_active_scanners:
                return False
            if context.scanner_client is None:
                return False
        if "http" in self.supported_types:
            return context.has_reachable_http()
        return True

    @abstractmethod
    def check(self, context: AssessmentContext) -> list[Finding]:
        """Return findings. Active plugins send GET via ScannerHttpClient only."""


class ActivePlugin(SecurityPlugin):
    """Plugins that send additional in-scope GET requests for detection only."""

    is_active = True
