"""Conservative SQL injection *detection* on GET query parameters.

Sends a single syntax-probe character and looks for database error
signatures that were not present in the baseline. Does not dump data,
run stacked queries, or perform time-based/blind techniques.
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

logger = get_logger("vapt_framework.scanners.sql_injection")

PLUGIN_NAME = "sql-injection"
_PROBE = "'"
_SQL_ERRORS: tuple[tuple[str, str], ...] = (
    ("mysql", "you have an error in your sql syntax"),
    ("mysql", "mysql_fetch"),
    ("mysql", "mysqli_sql_exception"),
    ("postgres", "pg_query"),
    ("postgres", "unterminated quoted string"),
    ("postgres", "postgresql"),
    ("mssql", "unclosed quotation mark"),
    ("mssql", "microsoft ole db"),
    ("mssql", "odbc sql server driver"),
    ("oracle", "ora-01756"),
    ("oracle", "ora-00933"),
    ("sqlite", "sqlite3.operationalerror"),
    ("sqlite", "unrecognized token"),
    ("sqlite", "sqlite error"),
)


class SQLInjectionPlugin(ActivePlugin):
    """Error-based SQLi indicators on GET parameters. Detection only."""

    name = PLUGIN_NAME
    description = (
        "Controlled GET syntax probe for database error signatures. "
        "Does not extract data or execute SQL."
    )
    version = "0.1.0"

    def applies_to(self, context: AssessmentContext) -> bool:
        if not super().applies_to(context):
            return False
        if not query_targets(context):
            logger.info("SQL Injection Scanner: No eligible GET parameters found. Skipped.")
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
                logger.info("SQL injection scanner stopped at request limit")
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
            logger.info("SQL injection probe failed param=%s (%s)", name, exc)
            return None
        match = _new_sql_error(baseline.body or "", tested.body or "")
        if match is None:
            return None
        family, snippet = match
        excerpt = snippet[:200]
        return make_finding(
            title="Potential SQL Injection",
            description=(
                f"Parameter '{name}' on GET {url} produced a {family} "
                "database error signature after a controlled syntax probe. "
                "This is indicative, not proof of data access."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            plugin_name=self.name,
            finding_type="potential-sqli",
            category="injection",
            target=context.target,
            affected_url=url,
            parameter=name,
            evidence=Evidence(
                description=f"{family} error signature after syntax probe on '{name}'.",
                url=url,
                method="GET",
                status_code=tested.status_code,
                excerpt=excerpt,
            ),
            remediation=(
                "Use parameterized queries or prepared statements and validate input."
            ),
        )


def _new_sql_error(baseline: str, tested: str) -> tuple[str, str] | None:
    base = baseline.lower()
    body = tested.lower()
    for family, needle in _SQL_ERRORS:
        if needle in body and needle not in base:
            start = body.find(needle)
            snippet = tested[max(0, start) : start + 160]
            return family, snippet
    return None
