#!/usr/bin/env python3
"""
CommandOutputCleaner — the second cleaner in the DAGDIG pipeline.

Where the HTML cleaner condenses web pages, this stage condenses the raw
output of every *command* the framework runs (the Nmap sweeps) and every
command FinalRecon runs on our behalf (split per section). Each cleaned
result becomes one row of the Command Outputs table and is handed to the
Analyst alongside the Nmap summary and the FinalRecon parse.

Engine: LLM for everything (per design decision). Falls back to a naive
text strip if Groq is unavailable so a run never hard-fails here.
"""
import os
import re
import json

from core.schema import CommandResult
from core.banner import print_status, print_good, print_warn
from .client import GroqClient
from .llm_bridge import _load_prompt, _strip_json_fences

# Commands whose output should be fanned out into per-section rows.
SECTIONED_PREFIXES = ("osint_finalrecon",)

_RAW_CHAR_LIMIT = 16000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_PROMPT: str = ""


def _get_prompt() -> str:
    global _PROMPT
    if not _PROMPT:
        _PROMPT = _load_prompt("command_clean.txt")
    return _PROMPT


def _naive_strip(text: str) -> str:
    """Deterministic fallback: drop ANSI + blank runs, clip length."""
    text = _ANSI_RE.sub("", text or "")
    lines = [ln.rstrip() for ln in text.splitlines()]
    out, blank = [], False
    for ln in lines:
        if not ln.strip():
            if not blank:
                out.append("")
            blank = True
        else:
            out.append(ln)
            blank = False
    cleaned = "\n".join(out).strip()
    return cleaned[:2000] + ("…" if len(cleaned) > 2000 else "")


class CommandOutputCleaner:
    """Turns state.pending_commands into state.data.command_results."""

    def __init__(self, client: GroqClient = None):
        self.client = client or GroqClient(
            api_key=os.environ.get("GROQ_API_KEY"),
            model=os.environ.get("GROQ_MODEL"),
        )

    # ── LLM calls ────────────────────────────────────────────────────────────

    def _clean_single(self, command: str, purpose: str, raw: str) -> str:
        user = (
            f"COMMAND: {command}\nPURPOSE: {purpose}\nMODE: single-command\n\n"
            f"RAW OUTPUT:\n{raw[:_RAW_CHAR_LIMIT]}"
        )
        resp = self.client.chat_completion(_get_prompt(), user, temperature=0.1)
        data = json.loads(_strip_json_fences(resp))
        return (data.get("clean_output") or "").strip() or "NONE"

    def _clean_sectioned(self, command: str, purpose: str, raw: str) -> list:
        user = (
            f"COMMAND: {command}\nPURPOSE: {purpose}\nMODE: sectioned\n\n"
            "Split this run into its logical sections (e.g. Headers, WHOIS, DNS, "
            "SSL, Subdomains, Directories, Wayback) and clean each.\n\n"
            f"RAW OUTPUT:\n{raw[:_RAW_CHAR_LIMIT]}"
        )
        resp = self.client.chat_completion(_get_prompt(), user, temperature=0.1)
        data = json.loads(_strip_json_fences(resp))
        sections = data.get("sections")
        if isinstance(sections, list) and sections:
            return [
                (s.get("section", "Section"), (s.get("clean_output") or "").strip() or "NONE")
                for s in sections
                if isinstance(s, dict)
            ]
        # Model ignored sectioning — treat as one blob.
        return [(None, (data.get("clean_output") or "").strip() or "NONE")]

    # ── Orchestration ────────────────────────────────────────────────────────

    def run(self, state) -> int:
        """Process every queued command. Returns the number of rows produced."""
        pending = list(state.pending_commands)
        if not pending:
            return 0

        configured = self.client.is_configured()
        if not configured:
            print_warn("Groq not configured – CommandOutputCleaner using naive strip.")

        print_status(f"Cleaning {len(pending)} command output(s)...")
        produced = 0

        for entry in pending:
            name = entry.get("name", "")
            command = entry.get("command", "")
            purpose = entry.get("purpose", "") or name
            raw_ref = entry.get("raw_ref", "")

            try:
                raw = open(raw_ref, "r", encoding="utf-8", errors="ignore").read() if raw_ref else ""
            except OSError:
                raw = ""

            sectioned = name.startswith(SECTIONED_PREFIXES)

            try:
                if not configured:
                    raise RuntimeError("groq-unconfigured")
                rows = (
                    self._clean_sectioned(command, purpose, raw)
                    if sectioned
                    else [(None, self._clean_single(command, purpose, raw))]
                )
            except Exception as e:
                if configured:
                    print_warn(f"CommandOutputCleaner LLM failed for '{name}': {e}")
                rows = [(None, _naive_strip(raw))]

            for section, clean_output in rows:
                row_purpose = f"{purpose} · {section}" if section else purpose
                state.data.add_command_result(CommandResult(
                    command=command,
                    purpose=row_purpose,
                    clean_output=clean_output,
                    raw_ref=raw_ref,
                ))
                produced += 1

        state.pending_commands.clear()
        state.save()
        print_good(f"CommandOutputCleaner produced {produced} cleaned row(s)")
        return produced
