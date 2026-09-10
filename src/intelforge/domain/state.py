"""Persistence and derived-view helpers for a target's :class:`TargetData`."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from pathlib import Path

from intelforge.domain.models import CommandResult, PageAnalysis, TargetData


class TargetState:
    """Owns a :class:`TargetData`, its on-disk JSON, and raw command output.

    A single instance is threaded through every pipeline node; nodes mutate
    ``state.data`` and call :meth:`save`.
    """

    def __init__(self, data_dir: str | Path = "data", state_filename: str = "state.json") -> None:
        self.data_dir = Path(data_dir)
        self.state_file = self.data_dir / state_filename
        self.raw_dir = self.data_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.data = TargetData()
        # Commands run this session, awaiting the command-cleaner node.
        # Each entry: {"name", "command", "purpose", "raw_ref"}
        self.pending_commands: list[dict[str, str]] = []
        self.load()

    # ── persistence ─────────────────────────────────────────────────────────
    def load(self) -> None:
        if self.state_file.exists():
            with contextlib.suppress(ValueError):
                self.data = TargetData.model_validate_json(self.state_file.read_text())

    def save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(self.data.model_dump_json(indent=2))

    def export(self, filename: str | Path) -> Path:
        path = Path(filename)
        if not path.is_absolute():
            path = Path.cwd() / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.data.model_dump_json(indent=2))
        return path

    # ── mutation ────────────────────────────────────────────────────────────
    def set_target(self, target: str) -> None:
        self.data.target = target
        self.data.ip_address = target
        self.data.timestamp = datetime.now(UTC).isoformat()
        self.save()

    def set_field(self, field: str, value: str) -> None:
        if not hasattr(self.data, field):
            return
        current = getattr(self.data, field)
        if isinstance(current, list):
            if value not in current:
                current.append(value)
        else:
            setattr(self.data, field, value)
        self.save()

    def add_page_analysis(self, analysis: PageAnalysis) -> None:
        self.data.upsert_page_analysis(analysis)
        self.save()

    # ── raw command output ──────────────────────────────────────────────────
    def save_raw(self, name: str, output: str) -> str:
        target = self.data.target or "target"
        path = self.raw_dir / f"{name}_{target}.txt"
        path.write_text(output)
        return str(path)

    def record_command(self, name: str, cmd: object, purpose: str, raw_output: str) -> str:
        """Persist a command's raw output and queue it for the command-cleaner."""
        raw_ref = self.save_raw(name, raw_output)
        command_str = " ".join(map(str, cmd)) if isinstance(cmd, (list, tuple)) else str(cmd)
        self.pending_commands.append(
            {"name": name, "command": command_str, "purpose": purpose, "raw_ref": raw_ref}
        )
        return raw_ref

    # ── derived views for the LLM prompts ───────────────────────────────────
    def get_nmap_summary(self) -> str:
        lines: list[str] = []
        if self.data.open_ports:
            for p in sorted(self.data.open_ports, key=lambda x: (x.protocol, x.number)):
                lines.append(f"{p.protocol}/{p.number}: {p.service or 'unknown'} {p.version or '-'}")
        if self.data.services:
            lines.append("")
            lines.append("Services:")
            for s in self.data.services:
                lines.append(f"- {s.name} {s.version}".strip())
        return "\n".join(lines).strip()

    def get_command_table(self) -> str:
        blocks: list[str] = []
        for cr in self.data.command_results:
            blocks.append(f"### {cr.purpose or cr.command}")
            blocks.append(f"$ {cr.command}")
            blocks.append(cr.clean_output.strip() or "(no findings)")
            blocks.append("")
        return "\n".join(blocks).strip()

    def command_result(self, **kwargs: str) -> CommandResult:
        """Convenience factory used by the command-cleaner node."""
        return CommandResult(**kwargs)
