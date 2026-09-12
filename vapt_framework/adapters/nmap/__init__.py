"""Nmap service-discovery adapter."""

from vapt_framework.adapters.nmap.adapter import NmapAdapter
from vapt_framework.adapters.nmap.models import (
    HostResult,
    NmapScanResult,
    PortResult,
    ServiceInfo,
)

__all__ = [
    "HostResult",
    "NmapAdapter",
    "NmapScanResult",
    "PortResult",
    "ServiceInfo",
]
