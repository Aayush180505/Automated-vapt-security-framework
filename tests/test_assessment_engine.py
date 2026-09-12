"""Assessment engine tests."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPResponseInfo, HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.engine import AssessmentEngine
from vapt_framework.assessment.registry import PluginRegistry
from vapt_framework.config.settings import Settings
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Finding, ScanContext
from vapt_framework.core.target import parse_target
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.base import SecurityPlugin
from vapt_framework.scanners.sql_injection.scanner import SQLInjectionPlugin
from tests.test_plugins import DummyPlugin


def _http_context(headers: dict[str, str] | None = None) -> AssessmentContext:
    target = parse_target("http://10.10.10.10")
    service = HTTPService(
        scheme="http",
        host="10.10.10.10",
        port=80,
        base_url="http://10.10.10.10/",
        detected_service="http",
        reachable=True,
        response=HTTPResponseInfo(
            requested_url="http://10.10.10.10/",
            final_url="http://10.10.10.10/",
            status_code=200,
            headers=headers or {},
        ),
    )
    return AssessmentContext(
        scan=ScanContext(target=target, http_services=(service,))
    )


class FindingPlugin(SecurityPlugin):
    name = "finder"
    description = "emits one finding"
    version = "0.1.0"

    def check(self, context: AssessmentContext) -> list[Finding]:
        return [
            make_finding(
                title="Example",
                description="An example finding.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                plugin_name=self.name,
                finding_type="example",
                category="test",
                target=context.target,
                affected_url="http://10.10.10.10/",
                evidence=None,
                remediation="n/a",
            )
        ]


class BoomPlugin(SecurityPlugin):
    name = "boom"
    description = "raises"
    version = "0.1.0"

    def check(self, context: AssessmentContext) -> list[Finding]:
        raise RuntimeError("plugin exploded")


class SshOnlyPlugin(SecurityPlugin):
    name = "ssh-only"
    description = "never http"
    version = "0.1.0"
    supported_types = ("ssh",)

    def applies_to(self, context: AssessmentContext) -> bool:
        return False

    def check(self, context: AssessmentContext) -> list[Finding]:
        raise AssertionError("should not run")


def test_engine_executes_plugin() -> None:
    registry = PluginRegistry()
    registry.register(FindingPlugin())
    result = AssessmentEngine(registry).assess(_http_context())
    assert result.executed_plugins == ("finder",)
    assert len(result.findings) == 1
    assert result.findings[0].title == "Example"


def test_engine_runs_multiple_plugins() -> None:
    registry = PluginRegistry()
    registry.register(FindingPlugin())
    registry.register(DummyPlugin())
    result = AssessmentEngine(registry).assess(_http_context())
    assert set(result.executed_plugins) == {"finder", "dummy"}


def test_engine_skips_when_not_applicable() -> None:
    registry = PluginRegistry()
    registry.register(SshOnlyPlugin())
    result = AssessmentEngine(registry).assess(_http_context())
    assert result.skipped_plugins == ("ssh-only",)
    assert result.executed_plugins == ()
    assert result.findings == ()


def test_engine_skips_http_plugins_without_http() -> None:
    registry = PluginRegistry()
    registry.register(DummyPlugin())
    context = AssessmentContext(
        scan=ScanContext(target=parse_target("10.10.10.10"))
    )
    result = AssessmentEngine(registry).assess(context)
    assert result.skipped_plugins == ("dummy",)


def test_plugin_failure_is_isolated() -> None:
    registry = PluginRegistry()
    registry.register(BoomPlugin())
    registry.register(FindingPlugin())
    result = AssessmentEngine(registry).assess(_http_context())
    assert result.findings[0].plugin_name == "finder"
    assert any("boom" in error for error in result.errors)
    assert "finder" in result.executed_plugins
    assert "boom" not in result.executed_plugins


def test_engine_skips_active_plugins_when_disabled() -> None:
    registry = PluginRegistry()
    registry.register(DummyPlugin())
    registry.register(SQLInjectionPlugin())
    context = AssessmentContext(
        scan=_http_context().scan,
        settings=Settings(enable_active_scanners=False),
        http_client=object(),  # type: ignore[arg-type]
    )
    result = AssessmentEngine(registry).assess(context)
    assert "dummy" in result.executed_plugins
    assert "sql-injection" in result.skipped_plugins
    assert "sql-injection" not in result.executed_plugins
