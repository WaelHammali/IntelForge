"""The second cleaner — condense raw tool output into a Command Outputs table.

Where :class:`HtmlCleaner` condenses web pages, this condenses the raw stdout
of every recon command. Nmap sweeps become one row each; FinalRecon is fanned
out into per-section rows. Falls back to a deterministic strip when no model
is available so a run never fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from intelforge.agents._json import loads
from intelforge.agents.llm import complete
from intelforge.agents.prompts import load_prompt
from intelforge.console.theme import good, status, warn
from intelforge.domain.models import CommandResult
from intelforge.domain.state import TargetState

_SECTIONED_PREFIXES = ("finalrecon",)
_RAW_CHAR_LIMIT = 16_000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def naive_strip(text: str) -> str:
    text = _ANSI_RE.sub("", text or "")
    out: list[str] = []
    blank = False
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            if not blank:
                out.append("")
            blank = True
        else:
            out.append(line)
            blank = False
    cleaned = "\n".join(out).strip()
    return cleaned[:2000] + ("…" if len(cleaned) > 2000 else "")


class CommandCleaner:
    def __init__(self, model: BaseChatModel | None) -> None:
        self.model = model
        self.system = load_prompt("command_clean")

    # ── LLM calls ──────────────────────────────────────────────────────────
    def _clean_single(self, command: str, purpose: str, raw: str) -> str:
        assert self.model is not None
        user = (
            f"COMMAND: {command}\nPURPOSE: {purpose}\nMODE: single-command\n\n"
            f"RAW OUTPUT:\n{raw[:_RAW_CHAR_LIMIT]}"
        )
        data = loads(complete(self.model, self.system, user))
        return (data.get("clean_output") or "").strip() or "NONE"

    def _clean_sectioned(
        self, command: str, purpose: str, raw: str
    ) -> list[tuple[str | None, str]]:
        assert self.model is not None
        user = (
            f"COMMAND: {command}\nPURPOSE: {purpose}\nMODE: sectioned\n\n"
            "Split this run into its logical sections (Headers, WHOIS, DNS, SSL, "
            "Subdomains, Directories, Wayback) and clean each.\n\n"
            f"RAW OUTPUT:\n{raw[:_RAW_CHAR_LIMIT]}"
        )
        data = loads(complete(self.model, self.system, user))
        sections = data.get("sections")
        if isinstance(sections, list) and sections:
            return [
                (s.get("section", "Section"), (s.get("clean_output") or "").strip() or "NONE")
                for s in sections
                if isinstance(s, dict)
            ]
        return [(None, (data.get("clean_output") or "").strip() or "NONE")]

    # ── orchestration ──────────────────────────────────────────────────────
    def run(self, state: TargetState) -> int:
        pending = list(state.pending_commands)
        if not pending:
            return 0
        if self.model is None:
            warn("No LLM configured — command cleaner using naive strip")
        status(f"Cleaning {len(pending)} command output(s)")

        produced = 0
        for entry in pending:
            name, command = entry["name"], entry["command"]
            purpose = entry["purpose"] or name
            raw_ref = entry["raw_ref"]
            try:
                raw = Path(raw_ref).read_text(encoding="utf-8", errors="ignore") if raw_ref else ""
            except OSError:
                raw = ""

            sectioned = name.startswith(_SECTIONED_PREFIXES)
            try:
                if self.model is None:
                    raise RuntimeError("no-model")
                rows = (
                    self._clean_sectioned(command, purpose, raw)
                    if sectioned
                    else [(None, self._clean_single(command, purpose, raw))]
                )
            except Exception as exc:
                if self.model is not None:
                    warn(f"Command cleaner LLM failed for '{name}': {exc}")
                rows = [(None, naive_strip(raw))]

            for section, clean_output in rows:
                state.data.add_command_result(
                    CommandResult(
                        command=command,
                        purpose=f"{purpose} · {section}" if section else purpose,
                        clean_output=clean_output,
                        raw_ref=raw_ref,
                    )
                )
                produced += 1

        state.pending_commands.clear()
        state.save()
        good(f"Command cleaner produced {produced} row(s)")
        return produced
