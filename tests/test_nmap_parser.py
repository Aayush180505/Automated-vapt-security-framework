"""Nmap XML parser tests. Fixtures are local files; no network I/O."""

from __future__ import annotations

import pytest

from vapt_framework.adapters.nmap.parser import parse_nmap_xml
from vapt_framework.core.exceptions import NmapParseError
from tests.conftest import fixture_text


def test_parse_single_host_services() -> None:
    result = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    assert result.host_count == 1
    host = result.hosts[0]
    assert host.address == "10.10.10.10"
    assert host.status == "up"
    assert result.port_count == 4

    by_port = {port.number: port for port in host.ports}
    assert by_port[22].protocol == "tcp"
    assert by_port[22].state == "open"
    assert by_port[22].service_name == "ssh"
    assert by_port[22].service is not None
    assert by_port[22].service.product == "OpenSSH"
    assert by_port[22].service.version == "8.2p1"
    assert by_port[80].service_name == "http"
    assert by_port[3306].service_name == "mysql"
    assert "MySQL" in by_port[3306].version_label


def test_parse_missing_product_and_version() -> None:
    result = parse_nmap_xml(fixture_text("nmap_single_host.xml"))
    ftp = next(port for port in result.hosts[0].ports if port.number == 21)
    assert ftp.service_name == "ftp"
    assert ftp.version_label == "-"
    assert ftp.service is not None
    assert ftp.service.product is None
    assert ftp.service.version is None


def test_parse_port_without_service_element() -> None:
    xml = """
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.10.10.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    port = result.hosts[0].ports[0]
    assert port.number == 443
    assert port.service is None
    assert port.service_name == "-"
    assert port.version_label == "-"


def test_parse_multiple_hosts() -> None:
    result = parse_nmap_xml(fixture_text("nmap_multiple_hosts.xml"))
    assert result.host_count == 2
    addresses = {host.address for host in result.hosts}
    assert addresses == {"10.10.10.10", "10.10.10.11"}
    assert result.port_count == 2


def test_parse_empty_scan() -> None:
    result = parse_nmap_xml(fixture_text("nmap_empty.xml"))
    assert result.hosts == ()
    assert result.open_tcp_ports() == ()


def test_parse_malformed_xml() -> None:
    with pytest.raises(NmapParseError, match="Failed to parse Nmap output"):
        parse_nmap_xml("not xml")
    with pytest.raises(NmapParseError):
        parse_nmap_xml("")
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<root/>")
