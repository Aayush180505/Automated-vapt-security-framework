"""Nmap runner tests. These tests never invoke a real Nmap process."""

from __future__ import annotations

import subprocess

import pytest

from vapt_framework.adapters.nmap.runner import (
    build_nmap_command,
    find_nmap_executable,
    run_nmap,
)
from vapt_framework.core.exceptions import NmapExecutionError, NmapNotFoundError
from tests.conftest import fixture_text


def test_find_nmap_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.runner.shutil.which",
        lambda name: "C:\\nmap\\nmap.exe" if name in {"nmap", "nmap.exe"} else None,
    )
    assert find_nmap_executable().endswith("nmap.exe")


def test_nmap_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.runner.shutil.which",
        lambda name: None,
    )
    with pytest.raises(NmapNotFoundError, match="Nmap was not found on PATH"):
        find_nmap_executable()


def test_build_nmap_command() -> None:
    command = build_nmap_command("10.10.10.10", nmap_executable="nmap")
    assert command == ["nmap", "-sV", "-T3", "-oX", "-", "10.10.10.10"]
    assert "-A" not in command
    assert "--script" not in command
    assert all(isinstance(part, str) for part in command)


def test_build_nmap_command_with_port() -> None:
    command = build_nmap_command(
        "example.local",
        nmap_executable="/usr/bin/nmap",
        port=8443,
    )
    assert command == [
        "/usr/bin/nmap",
        "-sV",
        "-T3",
        "-oX",
        "-",
        "-p",
        "8443",
        "example.local",
    ]


def test_build_nmap_command_rejects_option_like_host() -> None:
    with pytest.raises(NmapExecutionError):
        build_nmap_command("-sV")


def test_run_nmap_success(monkeypatch: pytest.MonkeyPatch) -> None:
    xml = fixture_text("nmap_empty.xml")

    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 30
        return subprocess.CompletedProcess(command, 0, stdout=xml, stderr="")

    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.runner.subprocess.run",
        fake_run,
    )
    assert run_nmap(["nmap", "-sV", "-oX", "-", "10.10.10.10"], timeout=30) == xml


def test_run_nmap_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="failed"
        )

    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.runner.subprocess.run",
        fake_run,
    )
    with pytest.raises(NmapExecutionError, match="Nmap service discovery failed"):
        run_nmap(["nmap", "-sV"], timeout=5)


def test_run_nmap_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs["timeout"])

    monkeypatch.setattr(
        "vapt_framework.adapters.nmap.runner.subprocess.run",
        fake_run,
    )
    with pytest.raises(NmapExecutionError, match="timed out"):
        run_nmap(["nmap", "-sV"], timeout=1)
