"""Path traversal *detection* on likely file/path GET parameters.

Uses a single relative-path probe and known file-content indicators that
were absent from the baseline. Does not write, delete, or execute files.
"""

from __future__ import annotations

from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.exceptions import HTTPProbeError
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.active.targets import query_targets
from vapt_framework.scanners.base import ActivePlugin
from vapt_framework.utils.logging import get_logger
from vapt_framework.utils.urls import replace_query_param

logger = get_logger("vapt_framework.scanners.path_traversal")

PLUGIN_NAME = "path-traversal"
_PROBE = "../etc/passwd"
_INDICATORS = ("root:x:0:0", "root:x:0:", "[fonts]")


class PathTraversalPlugin(ActivePlugin):
    """Detects lab-style file disclosure via path-like GET parameters."""

    name = PLUGIN_NAME
    description = (
        "Controlled relative-path probe on file-like GET parameters. Detection only."
    )
    version = "0.1.0"

    def applies_to(self, context: AssessmentContext) -> bool:
        if not super().applies_to(context):
            return False
        if not query_targets(context, path_like_only=True):
            logger.info(
                "Path Traversal Scanner: No eligible path parameters found. Skipped."
            )
            return False
        return True

    def check(self, context: AssessmentContext) -> list[Finding]:
        client = context.scanner_client
        if client is None:
            return []
        findings: list[Finding] = []
        for endpoint, name in query_targets(context, path_like_only=True):
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
        try:
            baseline = client.get(url, plugin=self.name, parameter=name)
            if baseline is None:
                return None
            test_url = replace_query_param(url, name, _PROBE)
            if test_url is None:
                return None
            tested = client.get(test_url, plugin=self.name, parameter=name)
            if tested is None:
                return None
        except HTTPProbeError as exc:
            logger.info("Path traversal probe failed param=%s (%s)", name, exc)
            return None
        indicator = _new_indicator(baseline.body or "", tested.body or "")
        if indicator is None:
            return None
        return make_finding(
            title="Potential Path Traversal",
            description=(
                f"Parameter '{name}' on GET {url} returned content consistent "
                "with a file outside the intended path after a relative-path "
                "probe. This is indicative, not a confirmed arbitrary read."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            plugin_name=self.name,
            finding_type="potential-path-traversal",
            category="path-traversal",
            target=context.target,
            affected_url=url,
            parameter=name,
            evidence=Evidence(
                description=f"Response contained indicator {indicator!r} after path probe.",
                url=url,
                method="GET",
                status_code=tested.status_code,
                excerpt=indicator,
            ),
            remediation=(
                "Canonicalize paths, reject '..' sequences, and restrict reads "
                "to an allowlisted directory."
            ),
        )


def _new_indicator(baseline: str, tested: str) -> str | None:
    for item in _INDICATORS:
        if item in tested and item not in baseline:
            return item
    return None
