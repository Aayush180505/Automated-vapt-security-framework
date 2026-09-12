"""Parse Nmap XML into structured discovery models."""

from __future__ import annotations

import re
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from vapt_framework.adapters.nmap.models import (
    HostResult,
    NmapScanResult,
    PortResult,
    ServiceInfo,
)
from vapt_framework.core.exceptions import NmapParseError
from vapt_framework.utils.logging import get_logger

_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)
logger = get_logger("vapt_framework.adapters.nmap.parser")


def parse_nmap_xml(xml_text: str) -> NmapScanResult:
    """Convert Nmap XML text into an :class:`NmapScanResult`."""
    if xml_text is None or not str(xml_text).strip():
        raise NmapParseError("Failed to parse Nmap output.")

    sanitized = _DOCTYPE_RE.sub("", xml_text, count=1)
    try:
        root = ElementTree.fromstring(sanitized)
    except (ParseError, DefusedXmlException, SyntaxError, ValueError) as exc:
        raise NmapParseError("Failed to parse Nmap output.") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("Failed to parse Nmap output.")

    hosts = tuple(
        host
        for host_el in root.findall("host")
        if (host := _parse_host(host_el)) is not None
    )
    logger.info(
        "Parsed Nmap XML: %s host(s), %s port(s)",
        len(hosts),
        sum(len(host.ports) for host in hosts),
    )
    return NmapScanResult(hosts=hosts)


def _parse_host(host_el: Element) -> HostResult | None:
    address = _host_address(host_el)
    if not address:
        logger.warning("Skipping Nmap host without an address")
        return None

    status_el = host_el.find("status")
    status = (status_el.get("state") if status_el is not None else None) or "unknown"
    ports_el = host_el.find("ports")
    port_elements = ports_el.findall("port") if ports_el is not None else []
    ports = tuple(
        port
        for port_el in port_elements
        if (port := _parse_port(port_el)) is not None
    )
    return HostResult(address=address, status=status, ports=ports)


def _host_address(host_el: Element) -> str | None:
    first: str | None = None
    for address_el in host_el.findall("address"):
        value = address_el.get("addr")
        if not value:
            continue
        if first is None:
            first = value
        if address_el.get("addrtype") == "ipv4":
            return value
    return first


def _parse_port(port_el: Element) -> PortResult | None:
    raw_id = port_el.get("portid")
    protocol = (port_el.get("protocol") or "tcp").lower()
    if raw_id is None or not raw_id.isdigit():
        logger.warning("Skipping Nmap port with invalid portid")
        return None

    state_el = port_el.find("state")
    state = (state_el.get("state") if state_el is not None else None) or "unknown"
    service_el = port_el.find("service")
    service = None
    if service_el is not None:
        service = ServiceInfo(
            name=_optional(service_el.get("name")),
            product=_optional(service_el.get("product")),
            version=_optional(service_el.get("version")),
            extra_info=_optional(service_el.get("extrainfo")),
        )
    return PortResult(
        number=int(raw_id),
        protocol=protocol,
        state=state,
        service=service,
    )


def _optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
