"""Typed domain models shared across the pipeline.

These are plain data containers (Pydantic v2) with no behaviour beyond
validation. Aggregation and persistence live in :mod:`intelforge.domain.state`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Port(BaseModel):
    number: int
    protocol: str  # "tcp" | "udp"
    service: str = ""
    version: str = ""

    def identity(self) -> tuple[int, str, str]:
        """Key used for de-duplication (matches the legacy __eq__)."""
        return (self.number, self.protocol, self.service)


class Service(BaseModel):
    name: str
    version: str = ""

    def identity(self) -> tuple[str, str]:
        return (self.name, self.version)


class CommandResult(BaseModel):
    """One executed recon command with its LLM-cleaned output.

    Produced by the command-cleaner node: every Nmap sweep and every
    FinalRecon section becomes one row of the Command Outputs table.
    """

    command: str
    purpose: str = ""
    clean_output: str = ""
    raw_ref: str = ""

    def identity(self) -> tuple[str, str]:
        return (self.command, self.purpose)


class PageAnalysis(BaseModel):
    """Per-URL intelligence, enriched stage by stage."""

    url: str
    auth_requirement: str = "Public"
    downloadable_files: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    summary: str = ""

    # Stage 2 — attack surface
    bypass_paths: list[str] = Field(default_factory=list)
    auth_pages: list[str] = Field(default_factory=list)
    upload_points: list[dict[str, str]] = Field(default_factory=list)
    download_points: list[str] = Field(default_factory=list)
    injectable_params: list[dict[str, str]] = Field(default_factory=list)
    keyword_fingerprints: list[str] = Field(default_factory=list)
    suspicious_items: list[str] = Field(default_factory=list)

    # Stage 3 — exploit research
    llm_recon_paragraph: str = ""
    research_tuples: list[dict[str, Any]] = Field(default_factory=list)
    exploit_report: dict[str, Any] = Field(default_factory=dict)


class TargetData(BaseModel):
    """The full picture of a target — persisted to ``data/state.json``."""

    target: str = ""
    ip_address: str = ""
    open_ports: list[Port] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    vhosts: list[str] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    page_analyses: list[PageAnalysis] = Field(default_factory=list)
    command_results: list[CommandResult] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    notes: str = ""
    timestamp: str = ""

    # ── de-duplicating adders ────────────────────────────────────────────────
    def add_port(self, port: Port) -> None:
        if all(p.identity() != port.identity() for p in self.open_ports):
            self.open_ports.append(port)
            if port.protocol not in self.protocols:
                self.protocols.append(port.protocol)

    def add_service(self, service: Service) -> None:
        if all(s.identity() != service.identity() for s in self.services):
            self.services.append(service)

    def _add_unique(self, bucket: list[str], value: str) -> None:
        if value and value not in bucket:
            bucket.append(value)

    def add_domain(self, value: str) -> None:
        self._add_unique(self.domains, value)

    def add_subdomain(self, value: str) -> None:
        self._add_unique(self.subdomains, value)

    def add_vhost(self, value: str) -> None:
        self._add_unique(self.vhosts, value)

    def add_directory(self, value: str) -> None:
        self._add_unique(self.directories, value)

    def add_endpoint(self, value: str) -> None:
        self._add_unique(self.endpoints, value)

    def add_email(self, value: str) -> None:
        if value and value.lower() not in {e.lower() for e in self.emails}:
            self.emails.append(value)

    def add_command_result(self, result: CommandResult) -> None:
        for i, existing in enumerate(self.command_results):
            if existing.identity() == result.identity():
                self.command_results[i] = result
                return
        self.command_results.append(result)

    def upsert_page_analysis(self, analysis: PageAnalysis) -> None:
        for i, existing in enumerate(self.page_analyses):
            if existing.url == analysis.url:
                self.page_analyses[i] = analysis
                break
        else:
            self.page_analyses.append(analysis)
        for tech in analysis.technologies:
            self._add_unique(self.technologies, tech)
