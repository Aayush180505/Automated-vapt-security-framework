"""Reflected XSS *detection* via a unique marker on GET parameters.

Does not execute JavaScript, steal cookies, or test stored/DOM XSS.
Reflection of a harmless marker in HTML is reported as potential XSS.
"""

from __future__ import annotations

import re

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.active.targets import query_targets
from vapt_framework.scanners.base import ActivePlugin
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import replace_query_param

logger = get_logger("vapt_framework.scanners.xss")

PLUGIN_NAME = "reflected-xss"
MARKER = "VAPTREFLECT123"
_ATTR = re.compile(
    r"""=\s*(['"])[^'"]*""" + re.escape(MARKER) + r"""[^'"]*\1""",
    re.IGNORECASE,
)


class ReflectedXSSPlugin(ActivePlugin):
    """Detects unencoded reflection of a unique marker. Detection only."""

    name = PLUGIN_NAME
    description = (
        "Checks whether a unique marker in a GET parameter is reflected in HTML."
    )
    version = "0.1.0"

    def applies_to(self, context: AssessmentContext) -> bool:
        if not super().applies_to(context):
            return False
        if not query_targets(context):
            logger.info("Reflected XSS Scanner: No eligible GET parameters found. Skipped.")
            return False
        return True

    def check(self, context: AssessmentContext) -> list[Finding]:
        client = context.scanner_client
        if client is None:
            return []
        findings: list[Finding] = []
        for endpoint, name in query_targets(context):
            if client.limit_reached:
                break
            finding = self._test_parameter(context, endpoint.url, name)
            if finding is not None:
                findings.append(finding)
            if client.limit_reached:
                break
        return findings

    def _test_parameter(
        self,
        context: AssessmentContext,
        url: str,
        name: str,
    ) -> Finding | None:
        client = context.scanner_client
        assert client is not None
        test_url = replace_query_param(url, name, MARKER)
        if test_url is None:
            return None
        try:
            response = client.get(test_url, plugin=self.name, parameter=name)
        except HTTPProbeError as exc:
            logger.info("XSS probe failed param=%s (%s)", name, exc)
            return None
        if response is None or not response.body:
            return None
        if MARKER not in response.body:
            return None
        content_type = (response.content_type or "").lower()
        if content_type and "html" not in content_type and "text/" not in content_type:
            return None
        context_kind = _reflection_context(response.body)
        if context_kind is None:
            return None
        return make_finding(
            title="Potential Reflected XSS",
            description=(
                f"Parameter '{name}' reflected marker {MARKER} into an HTML "
                f"response ({context_kind} context). Reflection is not proof "
                "of script execution."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            plugin_name=self.name,
            finding_type="potential-reflected-xss",
            category="xss",
            target=context.target,
            affected_url=url,
            parameter=name,
            evidence=Evidence(
                description=f"Marker reflected in {context_kind} context.",
                url=url,
                method="GET",
                status_code=response.status_code,
                excerpt=_excerpt_around(response.body, MARKER),
            ),
            remediation=(
                "Apply context-appropriate output encoding and input validation."
            ),
        )


def _reflection_context(body: str) -> str | None:
    if _ATTR.search(body):
        return "html-attribute"
    if MARKER in body:
        return "html-text"
    return None


def _excerpt_around(body: str, marker: str) -> str:
    idx = body.find(marker)
    if idx < 0:
        return marker
    start = max(0, idx - 40)
    return body[start : idx + len(marker) + 40][:200]
