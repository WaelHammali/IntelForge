#!/usr/bin/env python3
"""
State manager for DAGDIG
Handles persistence, raw output storage, and Unicode-box-drawing table display.
"""
import json
from pathlib import Path
from datetime import datetime
from .schema import TargetData

# ANSI color codes
R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
B   = "\033[1;34m"
M   = "\033[1;35m"
C   = "\033[1;36m"
W   = "\033[1;37m"
DIM = "\033[2m"
RST = "\033[0m"
BD  = "\033[1;34m"   # bright blue for box borders
HDR = "\033[1;36m"   # cyan for header cells


def _box_table(title: str, columns: list, rows: list):
    """
    Render a full Unicode-box-drawing table.

    Example:
      Open Ports
      +-------+-------+---------+---------+
      | Port  | Proto | Service | Version |
      +-------+-------+---------+---------+
      | 80    | TCP   | http    |    -    |
      | 443   | TCP   | https   |    -    |
      +-------+-------+---------+---------+
    """
    if not rows:
        return

    # Compute max content width per column
    widths = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    # Each cell gets 1 space padding on each side  =>  display width = w + 2
    def hseg(w):
        return "─" * (w + 2)

    def top():
        return BD + "┌" + "┬".join(hseg(w) for w in widths) + "┐" + RST

    def mid():
        return BD + "├" + "┼".join(hseg(w) for w in widths) + "┤" + RST

    def bot():
        return BD + "└" + "┴".join(hseg(w) for w in widths) + "┘" + RST

    def make_row(cells, is_header=False):
        parts = []
        for i, (cell, w) in enumerate(zip(cells, widths)):
            text = str(cell)
            pad  = w - len(text)

            if is_header:
                colored = HDR + text + RST
            else:
                t = text.upper()
                if i == 0 and text.isdigit():
                    colored = G + text + RST
                elif t in ("TCP", "UDP"):
                    colored = Y + text + RST
                elif text.startswith("http") or text.startswith("/"):
                    colored = M + text + RST
                elif text in ("-", "—", ""):
                    colored = DIM + text + RST
                else:
                    colored = W + text + RST

            parts.append(" " + colored + " " * pad + " ")

        return BD + "│" + RST + (BD + "│" + RST).join(parts) + BD + "│" + RST

    print(f"\n  {C}{title}{RST}")
    print("  " + top())
    print("  " + make_row(columns, is_header=True))
    print("  " + mid())
    for row in rows:
        padded = list(row) + [""] * max(0, len(columns) - len(row))
        print("  " + make_row(padded))
    print("  " + bot())
    print()


class StateManager:
    def __init__(self, state_file: str = "data/state.json"):
        self.state_file = Path(state_file)
        self.raw_dir    = Path("data/raw")
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.data = TargetData()
        # Commands executed this run, awaiting the CommandOutputCleaner stage.
        # Each entry: {name, command, purpose, raw_ref}
        self.pending_commands: list = []
        self.load()

    def set_target(self, target: str):
        self.data.target     = target
        self.data.ip_address = target
        self.data.timestamp  = datetime.now().isoformat()
        self.save()

    def save(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(self.data.to_dict(), f, indent=2)

    def load(self):
        if self.state_file.exists():
            with open(self.state_file, "r") as f:
                try:
                    self.data = TargetData.from_dict(json.load(f))
                except Exception:
                    pass

    def export(self, filename: str):
        # Always save relative to project root (parent of this file's directory)
        path = Path(filename)
        if not path.is_absolute():
            root = Path(__file__).resolve().parent.parent
            path = root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.data.to_dict(), f, indent=2)
        return str(path)

    def set_field(self, field: str, value: str):
        if hasattr(self.data, field):
            current = getattr(self.data, field)
            if isinstance(current, list):
                if value not in current:
                    current.append(value)
            else:
                setattr(self.data, field, value)
            self.save()

    def add_page_analysis(self, analysis):
        """Add or update an AI PageAnalysis entry"""
        existing = [i for i, pa in enumerate(self.data.page_analyses) if pa.url == analysis.url]
        if existing:
            self.data.page_analyses[existing[0]] = analysis
        else:
            self.data.page_analyses.append(analysis)

        for tech in analysis.technologies:
            if tech and tech not in self.data.technologies:
                self.data.technologies.append(tech)

        self.save()

    def save_raw(self, scanner_name: str, output: str) -> str:
        """Save raw output from a scanner (e.g., nmap XML). Returns the file path."""
        filename = self.raw_dir / f"{scanner_name}_{self.data.target}.txt"
        with open(filename, "w") as f:
            f.write(output)
        return str(filename)

    def record_command(self, name: str, cmd, purpose: str, raw_output: str) -> str:
        """Persist a command's raw output and queue it for the CommandOutputCleaner.

        `cmd` may be an argv list or a string. Returns the raw file path.
        """
        raw_ref = self.save_raw(name, raw_output)
        command_str = " ".join(str(c) for c in cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        self.pending_commands.append({
            "name": name,
            "command": command_str,
            "purpose": purpose,
            "raw_ref": raw_ref,
        })
        return raw_ref

    def get_command_table(self) -> str:
        """Human-readable digest of cleaned command outputs, for the Analyst prompt."""
        lines = []
        for cr in self.data.command_results:
            header = cr.purpose or cr.command
            lines.append(f"### {header}")
            lines.append(f"$ {cr.command}")
            lines.append(cr.clean_output.strip() or "(no findings)")
            lines.append("")
        return "\n".join(lines).strip()

    def get_nmap_summary(self) -> str:
        """Return a concise, human-readable summary of discovered ports and services.

        Format example:
          tcp/80: http 2.4.41
          udp/53: domain -
          \nServices:
          - openssh 7.6p1
        """
        lines = []
        if self.data.open_ports:
            for p in sorted(self.data.open_ports, key=lambda x: (x.protocol, x.number)):
                svc = p.service or "unknown"
                ver = p.version or "-"
                lines.append(f"{p.protocol}/{p.number}: {svc} {ver}")

        if self.data.services:
            lines.append("")
            lines.append("Services:")
            for s in self.data.services:
                ver = s.version or ""
                lines.append(f"- {s.name} {ver}".strip())

        return "\n".join(lines).strip()

    # ──────────────────────────────────────────────────────────────────────────
    def print_table(self):
        """Display all scan results as Unicode box-drawing tables."""

        ts = self.data.timestamp[:19].replace("T", " ") if self.data.timestamp else "N/A"

        # ── Target info box ───────────────────────────────────────────────────
        IW = 50   # inner width of the info box

        def _itop(): return f"  {BD}+{'-' * IW}+{RST}"
        def _idiv(): return f"  {BD}+{'-' * IW}+{RST}"
        def _ibot(): return f"  {BD}+{'-' * IW}+{RST}"

        def _irow(label, value, vcol=W):
            content = f" {C}{label:<10}{RST}: {vcol}{value}{RST}"
            # Visible length (no ANSI)
            vis = 1 + len(label) + 2 + len(value)
            pad = max(0, IW - vis - 1)
            return f"  {BD}|{RST}{content}{' ' * pad}{BD}|{RST}"

        print()
        print(_itop())
        print(_irow("Target",  self.data.target      or "N/A", W))
        print(_idiv())
        print(_irow("IP Addr", self.data.ip_address  or "N/A", G))
        print(_idiv())
        print(_irow("Scanned", ts,                             DIM))
        print(_ibot())

        has_data = any([
            self.data.open_ports, self.data.services,
            self.data.domains, self.data.subdomains,
            self.data.vhosts, self.data.directories,
            self.data.endpoints, self.data.technologies, self.data.emails,
            self.data.command_results,
        ])
        if not has_data:
            print(f"\n  {Y}No scan data yet. Run: python dagdig.py scan <target>{RST}\n")
            return

        # ── Open Ports ────────────────────────────────────────────────────────
        if self.data.open_ports:
            rows = [
                [str(p.number), p.protocol.upper(), p.service or "unknown", p.version or "-"]
                for p in sorted(self.data.open_ports, key=lambda p: p.number)
            ]
            _box_table("Open Ports", ["Port", "Proto", "Service", "Version"], rows)

        # ── Services ──────────────────────────────────────────────────────────
        if self.data.services:
            _box_table("Services", ["Name", "Version"],
                       [[s.name, s.version or "-"] for s in self.data.services])

        # ── Domains ───────────────────────────────────────────────────────────
        if self.data.domains:
            _box_table("Domains", ["Domain"], [[d] for d in self.data.domains])

        # ── Subdomains ────────────────────────────────────────────────────────
        if self.data.subdomains:
            _box_table("Subdomains", ["Subdomain"], [[s] for s in self.data.subdomains])

        # ── Virtual Hosts ─────────────────────────────────────────────────────
        if self.data.vhosts:
            _box_table("Virtual Hosts", ["VHost"], [[v] for v in self.data.vhosts])

        # ── Directories ───────────────────────────────────────────────────────
        if self.data.directories:
            _box_table("Directories", ["Path"], [[f"/{d}"] for d in self.data.directories])

        # ── Endpoints ────────────────────────────────────────────────────────
        if self.data.endpoints:
            _box_table("Endpoints", ["URL"], [[e] for e in self.data.endpoints])

        # ── Technologies ─────────────────────────────────────────────────────
        if self.data.technologies:
            _box_table("Technologies", ["Technology"], [[t] for t in self.data.technologies])

        # ── AI Page Intelligence (Groq) ───────────────────────────────────────
        if self.data.page_analyses:
            rows = [
                [
                    pa.url,
                    pa.auth_requirement,
                    ", ".join(pa.downloadable_files) if pa.downloadable_files else "-",
                    ", ".join(pa.technologies) if pa.technologies else "-"
                ]
                for pa in self.data.page_analyses
            ]
            _box_table("AI Page Intelligence (Groq)", ["URL / Path", "Access / Auth Level", "Downloadable Files", "Tech & Version"], rows)

        # ── Command Outputs (LLM-cleaned) ────────────────────────────────────
        if self.data.command_results:
            def _clip(text, limit=280):
                flat = " ".join(text.split())
                return flat if len(flat) <= limit else flat[:limit - 1] + "…"
            rows = [
                [cr.purpose or "-", cr.command, _clip(cr.clean_output)]
                for cr in self.data.command_results
            ]
            _box_table("Command Outputs", ["Purpose", "Command", "Cleaned Findings"], rows)

        # ── Emails ────────────────────────────────────────────────────────────
        if self.data.emails:
            _box_table("Emails", ["Address"], [[e] for e in self.data.emails])

        # ── Notes ─────────────────────────────────────────────────────────────
        if self.data.notes:
            print(f"  {C}Notes{RST}\n  {'─' * 40}\n  {self.data.notes}\n")

        # ── Summary table ─────────────────────────────────────────────────────
        total = (
            len(self.data.open_ports) + len(self.data.subdomains) +
            len(self.data.vhosts) + len(self.data.directories)
        )
        _box_table("Summary", ["Category", "Count"], [
            ["Open Ports",   str(len(self.data.open_ports))],
            ["Services",     str(len(self.data.services))],
            ["Subdomains",   str(len(self.data.subdomains))],
            ["VHosts",       str(len(self.data.vhosts))],
            ["Directories",  str(len(self.data.directories))],
            ["Technologies", str(len(self.data.technologies))],
            ["Total",        str(total)],
        ])
