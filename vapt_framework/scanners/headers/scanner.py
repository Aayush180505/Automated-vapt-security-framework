"""Passive security-header absence checks using existing HTTP responses."""

from __future__ import annotations

from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.base import SecurityPlugin

PLUGIN_NAME = "security-headers"

# (header-name, finding-type, title, severity, https_only)
_HEADER_CHECKS: tuple[tuple[str, str, str, Severity, bool], ...] = (
    (
        "content-security-policy",
        "missing-csp",
        "Missing Content-Security-Policy Header",
        Severity.LOW,
        False,
    ),
    (
        "strict-transport-security",
        "missing-hsts",
        "Missing Strict-Transport-Security Header",
        Severity.LOW,
        True,
    ),
    (
        "x-content-type-options",
        "missing-x-content-type-options",
        "Missing X-Content-Type-Options Header",
        Severity.LOW,
        False,
    ),
    (
        "referrer-policy",
        "missing-referrer-policy",
        "Missing Referrer-Policy Header",
        Severity.LOW,
        False,
    ),
    (
        "permissions-policy",
        "missing-permissions-policy",
        "Missing Permissions-Policy Header",
        Severity.INFO,
        False,
    ),
    (
        "x-frame-options",
        "missing-x-frame-options",
        "Missing X-Frame-Options Header",
        Severity.LOW,
        False,
    ),
)


class SecurityHeadersPlugin(SecurityPlugin):
    """Reports missing security headers. Does not prove exploitability."""

    name = PLUGIN_NAME
    description = (
        "Passive check for common HTTP security headers on probed services."
    )
    version = "0.1.0"
    supported_types = ("http",)

    def check(self, context: AssessmentContext) -> list[Finding]:
        findings: list[Finding] = []
        for service in context.reachable_http_services():
            findings.extend(self._check_service(context, service))
        return findings

    def _check_service(
        self,
        context: AssessmentContext,
        service: HTTPService,
    ) -> list[Finding]:
        response = service.response
        if response is None:
            return []
        headers = {key.lower(): value for key, value in response.headers.items()}
        findings: list[Finding] = []
        for header, finding_type, title, severity, https_only in _HEADER_CHECKS:
            if https_only and service.scheme != "https":
                continue
            if headers.get(header):
                continue
            url = service.base_url
            findings.append(
                make_finding(
                    title=title,
                    description=(
                        f"The HTTP response from {url} does not include the "
                        f"{header} header. This is a hardening gap, not proof "
                        "that an attack succeeded."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    plugin_name=self.name,
                    finding_type=finding_type,
                    category="security-headers",
                    target=context.target,
                    affected_url=url,
                    evidence=Evidence(
                        description=f"Header '{header}' was not present.",
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        headers=dict(headers),
                    ),
                    remediation=(
                        f"Add an appropriate {header} header on HTTP responses "
                        "for this origin."
                    ),
                )
            )
        return findings
