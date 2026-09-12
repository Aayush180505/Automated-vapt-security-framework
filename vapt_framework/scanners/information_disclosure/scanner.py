"""Passive technology/version disclosure checks on collected headers."""

from __future__ import annotations

import re

from vapt_framework.adapters.http.models import HTTPService
from vapt_framework.assessment.context import AssessmentContext
from vapt_framework.core.enums import Confidence, Severity
from vapt_framework.core.models import Evidence, Finding
from vapt_framework.findings.factory import make_finding
from vapt_framework.scanners.base import SecurityPlugin

PLUGIN_NAME = "information-disclosure"
_VERSION_HINT = re.compile(r"[\d/]")


class InformationDisclosurePlugin(SecurityPlugin):
    """Reports verbose Server/X-Powered-By style headers. Conservative severity."""

    name = PLUGIN_NAME
    description = (
        "Passive review of already-collected HTTP headers for software version leak."
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
        server = headers.get("server") or response.server
        if server and _VERSION_HINT.search(server):
            findings.append(
                self._disclosure(
                    context,
                    service,
                    finding_type="server-version",
                    title="Web Server Version Disclosure",
                    header="server",
                    value=server,
                )
            )
        powered = headers.get("x-powered-by")
        if powered:
            findings.append(
                self._disclosure(
                    context,
                    service,
                    finding_type="x-powered-by",
                    title="X-Powered-By Header Disclosure",
                    header="x-powered-by",
                    value=powered,
                )
            )
        return findings

    def _disclosure(
        self,
        context: AssessmentContext,
        service: HTTPService,
        *,
        finding_type: str,
        title: str,
        header: str,
        value: str,
    ) -> Finding:
        url = service.base_url
        status = service.response.status_code if service.response else None
        return make_finding(
            title=title,
            description=(
                f"The {header} response header from {url} discloses software "
                f"details ({value!s}). This is informational and does not by "
                "itself prove a vulnerability."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            plugin_name=self.name,
            finding_type=finding_type,
            category="information-disclosure",
            target=context.target,
            affected_url=url,
            evidence=Evidence(
                description=f"{header}: {value}",
                url=url,
                method="GET",
                status_code=status,
                headers={header: value},
            ),
            remediation=(
                "Reduce unnecessary product and version disclosure in HTTP "
                "response headers where operationally practical."
            ),
        )
