"""Recon HTTP isolation tests (mocked HTTP, fixture Nmap XML)."""

from __future__ import annotations

from vapt_framework.config.settings import Settings
from vapt_framework.core.target import parse_target
from vapt_framework.recon.engine import enumerate_web, run_scan
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from tests.conftest import fixture_text, lab_client


def test_enumerate_web_continues_when_https_missing() -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    client = lab_client()
    try:
        services, surfaces = enumerate_web(
            discovery,
            parse_target("10.10.10.10"),
            client,
            Settings(),
        )
        assert any(item.reachable and item.scheme == "http" for item in services)
        assert surfaces
        assert surfaces[0].pages_crawled >= 1
    finally:
        client.close()


def test_run_scan_attaches_findings(monkeypatch) -> None:
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    monkeypatch.setattr(
        "vapt_framework.recon.engine.discover_services",
        lambda target, timeout: discovery,
    )
    client = lab_client()
    try:
        context = run_scan(
            parse_target("http://10.10.10.10"),
            Settings(),
            http_client=client,
        )
        assert context.findings
        plugins = {item.plugin_name for item in context.findings}
        assert "security-headers" in plugins
        assert all(item.affected_url for item in context.findings)
        assert context.assessment_summary is not None
        assert context.assessment_summary.total_findings == len(context.findings)
        assert all(item.risk_score is not None for item in context.findings)
        assert context.scan_id
        assert context.status.value == "completed"
    finally:
        client.close()
