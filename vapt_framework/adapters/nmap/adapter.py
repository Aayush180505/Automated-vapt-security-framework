"""High-level Nmap service-discovery interface for the rest of the framework."""

from __future__ import annotations

from vapt_framework.adapters.nmap.models import NmapScanResult
from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.adapters.nmap.runner import (
    build_nmap_command,
    find_nmap_executable,
    run_nmap,
)
from vapt_framework.core.target import Target
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.adapters.nmap")


class NmapAdapter:
    """Orchestrates executable lookup, execution, and XML parsing."""

    def require_executable(self) -> str:
        """Return the Nmap path, raising if it is not installed."""
        logger.info("Checking Nmap availability")
        path = find_nmap_executable()
        logger.info("Nmap found")
        return path

    def discover(self, target: Target, timeout: float) -> NmapScanResult:
        """Run conservative service discovery against ``target``."""
        executable = self.require_executable()
        command = build_nmap_command(
            target.hostname,
            nmap_executable=executable,
            output_path="-",
            port=target.port,
        )
        logger.info("Starting Nmap service discovery for %s", target.hostname)
        xml_text = run_nmap(command, timeout=timeout)
        logger.info("Parsing Nmap XML")
        result = parse_nmap_xml(xml_text)
        logger.info(
            "Service discovery complete: %s host(s), %s port(s)",
            result.host_count,
            result.port_count,
        )
        return result
