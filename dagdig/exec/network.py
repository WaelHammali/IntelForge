#!/usr/bin/env python3
"""
Network scanning with nmap (TCP/UDP, full & light)
"""
import subprocess
import xml.etree.ElementTree as ET
from core.state import StateManager
from core.schema import Port, Service
from core.banner import print_status, print_good, print_warn, print_error

class NetworkScanner:
    def __init__(self, state: StateManager):
        self.state = state

    def _run_nmap(self, cmd: list, scan_name: str, purpose: str = "") -> str:
        """Run nmap and return XML output, save raw + register the command."""
        print_status(f"Running {scan_name}...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout
            self.state.record_command(scan_name, cmd, purpose or scan_name, output)
            return output
        except subprocess.TimeoutExpired:
            print_warn(f"{scan_name} timed out")
            return ""
        except Exception as e:
            print_error(f"{scan_name} error: {e}")
            return ""

    def _parse_nmap_xml(self, xml_output: str):
        """Parse XML to extract ports, services, and IP"""
        if not xml_output or not xml_output.strip():
            return
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall('host'):
                # Extract IP
                addr = host.find('./address[@addrtype="ipv4"]')
                if addr is not None:
                    ip = addr.get('addr')
                    if ip and not self.state.data.ip_address:
                        self.state.data.ip_address = ip
                # Extract ports
                for port_elem in host.findall('.//port'):
                    port_num = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        version = service_elem.get('version', '')
                    else:
                        service_name = 'unknown'
                        version = ''
                    port = Port(number=port_num, protocol=protocol, service=service_name, version=version)
                    self.state.data.add_port(port)
                    if service_name != 'unknown':
                        self.state.data.add_service(Service(name=service_name, version=version))
            self.state.save()
        except ET.ParseError:
            # Silent fallback if nmap output was incomplete or non-XML
            pass
        except Exception as e:
            print_warn(f"XML parse error: {e}")


    # ---------- Scans ----------

    def scan_tcp_full(self, target: str):
        """Full TCP scan: -sS -sV -sC -p- --min-rate 1000 -T4"""
        cmd = [
            'nmap', '-sS', '-sV', '-sC', '-p-',
            '--min-rate', '1000', '-T4',
            '-oX', '-', target
        ]
        xml_out = self._run_nmap(cmd, 'tcp_full', 'Full TCP scan (all ports, service + script)')
        self._parse_nmap_xml(xml_out)
        return xml_out

    def scan_udp_top(self, target: str):
        """UDP top ports: -sU -sV --top-ports 200 --min-rate 500 -T4"""
        cmd = [
            'nmap', '-sU', '-sV', '--top-ports', '200',
            '--min-rate', '500', '-T4',
            '-oX', '-', target
        ]
        xml_out = self._run_nmap(cmd, 'udp_top', 'UDP scan (top 200 ports, service detection)')
        self._parse_nmap_xml(xml_out)
        return xml_out

    def scan_tcp_light(self, target: str):
        """Lightweight TCP: -sS --top-ports 1000 -T5"""
        cmd = [
            'nmap', '-sS', '--top-ports', '1000',
            '--min-rate', '5000', '-T5',
            '-oX', '-', target
        ]
        xml_out = self._run_nmap(cmd, 'tcp_light', 'Fast TCP scan (top 1000 ports)')
        self._parse_nmap_xml(xml_out)
        return xml_out

    def scan_udp_light(self, target: str):
        """Lightweight UDP: -sU --top-ports 100 -T5"""
        cmd = [
            'nmap', '-sU', '--top-ports', '100',
            '--min-rate', '2000', '-T5',
            '-oX', '-', target
        ]
        xml_out = self._run_nmap(cmd, 'udp_light', 'Fast UDP scan (top 100 ports)')
        self._parse_nmap_xml(xml_out)
        return xml_out
