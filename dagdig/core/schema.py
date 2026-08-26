#!/usr/bin/env python3
"""
Data models for DAGDIG
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Port:
    number: int
    protocol: str          # 'tcp' or 'udp'
    service: str = ''
    version: str = ''

    def __eq__(self, other):
        if not isinstance(other, Port):
            return False
        return (self.number == other.number and
                self.protocol == other.protocol and
                self.service == other.service)

@dataclass
class Service:
    name: str
    version: str = ''

    def __eq__(self, other):
        if not isinstance(other, Service):
            return False
        return self.name == other.name and self.version == other.version

@dataclass
class PageAnalysis:
    url: str
    auth_requirement: str = 'Public'  # 'Public', 'Registration', 'Auth Required', 'Admin'
    downloadable_files: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    summary: str = ''

@dataclass
class TargetData:
    target: str = ''
    ip_address: str = ''
    open_ports: List[Port] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    vhosts: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    page_analyses: List[PageAnalysis] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    notes: str = ''
    timestamp: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'ip_address': self.ip_address,
            'open_ports': [p.__dict__ for p in self.open_ports],
            'protocols': self.protocols,
            'services': [s.__dict__ for s in self.services],
            'domains': self.domains,
            'subdomains': self.subdomains,
            'vhosts': self.vhosts,
            'directories': self.directories,
            'endpoints': self.endpoints,
            'parameters': self.parameters,
            'technologies': self.technologies,
            'page_analyses': [pa.__dict__ for pa in self.page_analyses],
            'emails': self.emails,
            'notes': self.notes,
            'timestamp': self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'TargetData':
        td = cls(
            target=data.get('target', ''),
            ip_address=data.get('ip_address', ''),
            protocols=data.get('protocols', []),
            domains=data.get('domains', []),
            subdomains=data.get('subdomains', []),
            vhosts=data.get('vhosts', []),
            directories=data.get('directories', []),
            endpoints=data.get('endpoints', []),
            parameters=data.get('parameters', []),
            technologies=data.get('technologies', []),
            emails=data.get('emails', []),
            notes=data.get('notes', ''),
            timestamp=data.get('timestamp', ''),
        )
        for p in data.get('open_ports', []):
            td.open_ports.append(Port(**p))
        for s in data.get('services', []):
            td.services.append(Service(**s))
        for pa in data.get('page_analyses', []):
            td.page_analyses.append(PageAnalysis(**pa))
        return td

    def add_port(self, port: Port):
        if port not in self.open_ports:
            self.open_ports.append(port)
            if port.protocol not in self.protocols:
                self.protocols.append(port.protocol)

    def add_service(self, service: Service):
        if service not in self.services:
            self.services.append(service)

    def add_domain(self, domain: str):
        if domain not in self.domains:
            self.domains.append(domain)

    def add_subdomain(self, sub: str):
        if sub not in self.subdomains:
            self.subdomains.append(sub)

    def add_vhost(self, vhost: str):
        if vhost not in self.vhosts:
            self.vhosts.append(vhost)

    def add_directory(self, dir_path: str):
        if dir_path not in self.directories:
            self.directories.append(dir_path)
