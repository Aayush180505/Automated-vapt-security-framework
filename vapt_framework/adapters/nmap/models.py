"""Structured service-discovery results.

These models are independent of Nmap XML and subprocess details.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceInfo:
    """Service identity reported for a port."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass(frozen=True)
class PortResult:
    """A single discovered port."""

    number: int
    protocol: str
    state: str
    service: ServiceInfo | None = None

    @property
    def label(self) -> str:
        return f"{self.number}/{self.protocol}"

    @property
    def service_name(self) -> str:
        if self.service and self.service.name:
            return self.service.name
        return "-"

    @property
    def version_label(self) -> str:
        if self.service is None:
            return "-"
        parts = [
            part
            for part in (self.service.product, self.service.version)
            if part
        ]
        return " ".join(parts) if parts else "-"


@dataclass(frozen=True)
class HostResult:
    """A host observed during service discovery."""

    address: str
    status: str
    ports: tuple[PortResult, ...] = ()


@dataclass(frozen=True)
class NmapScanResult:
    """Complete service-discovery result for one Nmap run."""

    hosts: tuple[HostResult, ...] = ()

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def port_count(self) -> int:
        return sum(len(host.ports) for host in self.hosts)

    def open_tcp_ports(self) -> tuple[PortResult, ...]:
        return tuple(
            port
            for host in self.hosts
            for port in host.ports
            if port.state == "open" and port.protocol.lower() == "tcp"
        )
