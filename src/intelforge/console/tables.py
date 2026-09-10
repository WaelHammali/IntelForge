"""Render a :class:`TargetData` snapshot as Rich tables."""

from __future__ import annotations

from rich.table import Table

from intelforge.console.theme import console
from intelforge.domain.models import TargetData


def _table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    if not rows:
        return
    table = Table(title=title, title_style="heading", header_style="info", expand=False)
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)


def _clip(text: str, limit: int = 320) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def render(data: TargetData) -> None:
    """Print every populated section of ``data``."""
    summary = Table(show_header=False, box=None, pad_edge=False)
    summary.add_column(style="info")
    summary.add_column(style="heading")
    summary.add_row("Target", data.target or "N/A")
    summary.add_row("IP address", data.ip_address or "N/A")
    summary.add_row("Scanned", (data.timestamp[:19].replace("T", " ") if data.timestamp else "N/A"))
    console.print(summary)

    _table(
        "Open Ports",
        ["Port", "Proto", "Service", "Version"],
        [
            [str(p.number), p.protocol.upper(), p.service or "unknown", p.version or "-"]
            for p in sorted(data.open_ports, key=lambda p: (p.protocol, p.number))
        ],
    )
    _table("Services", ["Name", "Version"], [[s.name, s.version or "-"] for s in data.services])
    _table("Domains", ["Domain"], [[d] for d in data.domains])
    _table("Subdomains", ["Subdomain"], [[s] for s in data.subdomains])
    _table("Virtual Hosts", ["VHost"], [[v] for v in data.vhosts])
    _table("Directories", ["Path"], [[f"/{d.lstrip('/')}"] for d in data.directories])
    _table("Endpoints", ["URL"], [[e] for e in data.endpoints])
    _table("Technologies", ["Technology"], [[t] for t in data.technologies])
    _table(
        "Command Outputs",
        ["Purpose", "Command", "Cleaned Findings"],
        [[cr.purpose or "-", cr.command, _clip(cr.clean_output)] for cr in data.command_results],
    )
    _table(
        "AI Page Intelligence",
        ["URL / Path", "Access", "Downloadable", "Tech"],
        [
            [
                pa.url,
                pa.auth_requirement,
                ", ".join(pa.downloadable_files) or "-",
                ", ".join(pa.technologies) or "-",
            ]
            for pa in data.page_analyses
        ],
    )
    _table("Emails", ["Address"], [[e] for e in data.emails])

    if data.notes:
        console.print(f"\n[heading]Notes[/heading]\n{data.notes}\n")

    _table(
        "Summary",
        ["Category", "Count"],
        [
            ["Open Ports", str(len(data.open_ports))],
            ["Services", str(len(data.services))],
            ["Subdomains", str(len(data.subdomains))],
            ["VHosts", str(len(data.vhosts))],
            ["Directories", str(len(data.directories))],
            ["Technologies", str(len(data.technologies))],
            ["Page analyses", str(len(data.page_analyses))],
        ],
    )
