"""Nmap adapter and ScanContext integration tests (mocked Nmap)."""

from __future__ import annotations

import pytest

from vapt_framework.adapters.nmap.adapter import NmapAdapter
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.core.models import ScanContext
from vapt_framework.core.target import parse_target
from tests.conftest import fixture_text


def test_adapter_discover(monkeypatch: pytest.MonkeyPatch) -> None:
    xml = fixture_text("nmap_single_host.xml")
    captured: dict[str, object] = {}

    def fake_run(command, timeout):  # type: ignore[no-untyped-def]
        captured["command"] = list(command)
        captured["timeout"] = timeout
        return xml

    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.adapter.find_nmap_executable",
        lambda: "/usr/bin/nmap",
    )
    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.adapter.run_nmap",
        fake_run,
    )

    target = parse_target("10.10.10.10")
    result = NmapAdapter().discover(target, timeout=45)
    assert captured["timeout"] == 45
    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == "/usr/bin/nmap"
    assert command[-1] == "10.10.10.10"
    assert result.hosts[0].address == "10.10.10.10"
    assert result.port_count == 4


def test_scan_context_without_discovery_results() -> None:
    context = ScanContext(target=parse_target("10.10.10.10"))
    assert context.discovery_results is None


def test_scan_context_stores_discovery_results() -> None:
    target = parse_target("10.10.10.10")
    discovery = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    context = ScanContext(target=target, discovery_results=discovery)
    assert context.target.hostname == "10.10.10.10"
    assert context.discovery_results is not None
    assert context.discovery_results.host_count == 1
    assert context.discovery_results.hosts[0].ports[0].number == 22
