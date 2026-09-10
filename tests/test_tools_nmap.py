from __future__ import annotations

from intelforge.domain.state import TargetState
from intelforge.tools.nmap import NmapScanner

_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.6p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" version="2.4.41"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_xml_populates_ports_services_and_ip(state: TargetState) -> None:
    state.data.ip_address = ""
    NmapScanner(state).parse_xml(_XML)

    assert state.data.ip_address == "10.10.10.5"
    ports = {(p.protocol, p.number): p for p in state.data.open_ports}
    assert ports[("tcp", 22)].service == "ssh"
    assert ports[("tcp", 22)].version == "7.6p1"
    assert ports[("udp", 53)].service == "unknown"
    assert {s.name for s in state.data.services} == {"ssh", "http"}


def test_parse_xml_is_idempotent(state: TargetState) -> None:
    scanner = NmapScanner(state)
    scanner.parse_xml(_XML)
    scanner.parse_xml(_XML)
    assert len(state.data.open_ports) == 3


def test_parse_xml_ignores_garbage(state: TargetState) -> None:
    NmapScanner(state).parse_xml("not xml at all")
    assert state.data.open_ports == []
