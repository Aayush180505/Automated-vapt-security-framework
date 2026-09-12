"""Assessment engine: run plugins, validate, and deduplicate findings."""

from __future__ import annotations

from dataclasses import replace

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.assessment.registry import PluginRegistry, default_registry
from vapt_framework.assessment.result import AssessmentResult
from vapt_framework.assessment.prioritizer import prioritize_findings
from vapt_framework.assessment.summary import build_summary
from vapt_framework.findings.deduplicator import deduplicate_findings
from vapt_framework.findings.validator import validate_finding
from vapt_framework.scanners.active.client import ScannerHttpClient, allowed_origins
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.assessment.engine")


class AssessmentEngine:
    """Orchestrates plugins. Contains no scanner-specific detection rules."""

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        self._registry = registry or default_registry()

    def assess(self, context: AssessmentContext) -> AssessmentResult:
        logger.info("Assessment started")
        executed: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        collected: list = []
        active_requests = 0
        settings = context.settings
        max_requests = settings.max_scanner_requests if settings else 25
        origins = _plugin_origins(context)

        for plugin in self._registry.get_all():
            plugin_context = context
            scanner: ScannerHttpClient | None = None
            if getattr(plugin, "is_active", False):
                if settings is not None and not settings.enable_active_scanners:
                    logger.info("Plugin skipped (active disabled): %s", plugin.name)
                    skipped.append(plugin.name)
                    continue
                if context.http_client is None:
                    logger.info("Plugin skipped (no HTTP client): %s", plugin.name)
                    skipped.append(plugin.name)
                    continue
                scanner = ScannerHttpClient(
                    context.http_client,
                    origins,
                    max_requests,
                )
                plugin_context = replace(context, scanner_client=scanner)
            if not plugin.applies_to(plugin_context):
                logger.info("Plugin skipped: %s", plugin.name)
                skipped.append(plugin.name)
                continue
            logger.info("Plugin applicable: %s", plugin.name)
            try:
                raw = plugin.check(plugin_context)
            except Exception as exc:  # noqa: BLE001 - isolate plugin faults
                message = f"{plugin.name}: {exc}"
                logger.error("Plugin error: %s", message)
                errors.append(message)
                if scanner is not None:
                    active_requests += scanner.request_count
                continue
            logger.info("Plugin executed: %s", plugin.name)
            executed.append(plugin.name)
            if scanner is not None:
                active_requests += scanner.request_count
            for item in raw:
                valid = validate_finding(item)
                if valid is None:
                    continue
                logger.info("Finding generated: %s", valid.title)
                collected.append(valid)

        unique = deduplicate_findings(collected)
        ranked = prioritize_findings(unique)
        summary = build_summary(ranked)
        logger.info("Assessment completed: %s finding(s)", len(ranked))
        return AssessmentResult(
            findings=ranked,
            executed_plugins=tuple(executed),
            skipped_plugins=tuple(skipped),
            errors=tuple(errors),
            active_requests=active_requests,
            summary=summary,
        )


def _plugin_origins(context: AssessmentContext) -> tuple[str, ...]:
    urls = [surface.base_url for surface in context.web_attack_surfaces]
    urls.extend(service.base_url for service in context.reachable_http_services())
    return allowed_origins(tuple(urls))
