"""Nmap scanner: runs the configured scan profiles and parses the XML."""

from __future__ import annotations

import shlex
import xml.etree.ElementTree as ET

from intelforge.config import Settings, settings
from intelforge.domain.models import Port, Service
from intelforge.domain.state import TargetState
from intelforge.tools.base import run_command

_PROFILE_PURPOSE = {
    "tcp_full": "Full TCP scan (all ports, service + default scripts)",
    "udp_top": "UDP scan (top 200 ports, service detection)",
    "tcp_light": "Fast TCP scan (top 1000 ports)",
    "udp_light": "Fast UDP scan (top 100 ports)",
}


class NmapScanner:
    def __init__(self, state: TargetState, config: Settings = settings) -> None:
        self.state = state
        self.config = config

    def run_profile(self, target: str, profile: str) -> str:
        flags = shlex.split(self.config.nmap_profiles[profile])
        # "--" terminates option parsing so a hostile target can never be read
        # as an Nmap flag. The target is validated upstream (domain.target).
        argv = ["nmap", *flags, "-oX", "-", "--", target]
        xml = run_command(
            self.state,
            name=f"nmap_{profile}",
            argv=argv,
            purpose=_PROFILE_PURPOSE.get(profile, f"Nmap {profile}"),
            timeout=self.config.scan_timeout,
            combine_stderr=False,
        )
        self.parse_xml(xml)
        return xml

    def parse_xml(self, xml_output: str) -> None:
        if not xml_output.strip():
            return
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return

        data = self.state.data
        for host in root.findall("host"):
            addr = host.find('./address[@addrtype="ipv4"]')
            if addr is not None and addr.get("addr") and not data.ip_address:
                data.ip_address = addr.get("addr", "")

            for port_el in host.findall(".//port"):
                service_el = port_el.find("service")
                name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                version = service_el.get("version", "") if service_el is not None else ""
                data.add_port(
                    Port(
                        number=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        service=name,
                        version=version,
                    )
                )
                if name != "unknown":
                    data.add_service(Service(name=name, version=version))
        self.state.save()

    def run_all(self, target: str) -> None:
        for profile in self.config.nmap_profiles:
            self.run_profile(target, profile)
