#!/usr/bin/env python3
"""
AttackTracker — tracks per-URL progress through the 3-stage recon pipeline.
"""
from dataclasses import dataclass, field
from typing import Dict
from datetime import datetime

# ANSI colors
G   = "\033[1;32m"
Y   = "\033[1;33m"
C   = "\033[1;36m"
W   = "\033[1;37m"
R   = "\033[1;31m"
DIM = "\033[2m"
RST = "\033[0m"

STAGES = ["fetch", "clean", "intel", "exploit"]
STAGE_LABELS = {
    "fetch":   "Fetching HTML",
    "clean":   "Stage 1 — HTML Cleaner",
    "intel":   "Stage 2 — Recon Intelligence",
    "exploit": "Stage 3 — Exploit Research",
}


@dataclass
class URLProgress:
    url: str
    current_stage: str = "pending"
    completed_stages: list = field(default_factory=list)
    error: str = ""
    started_at: str = ""
    finished_at: str = ""


class AttackTracker:
    """
    Tracks the 3-stage pipeline progress per URL.
    Provides a pretty-print status display for the DAGDIG console.
    """

    def __init__(self):
        self._urls: Dict[str, URLProgress] = {}

    def register(self, url: str):
        """Register a URL for tracking."""
        self._urls[url] = URLProgress(url=url, started_at=datetime.now().isoformat())

    def advance(self, url: str, stage: str):
        """Move a URL to the given stage."""
        if url not in self._urls:
            self.register(url)
        entry = self._urls[url]
        if entry.current_stage and entry.current_stage not in entry.completed_stages:
            entry.completed_stages.append(entry.current_stage)
        entry.current_stage = stage
        self._print_status(url, stage)

    def complete(self, url: str):
        """Mark a URL as fully completed."""
        if url not in self._urls:
            return
        entry = self._urls[url]
        if entry.current_stage and entry.current_stage not in entry.completed_stages:
            entry.completed_stages.append(entry.current_stage)
        entry.current_stage = "done"
        entry.finished_at = datetime.now().isoformat()
        print(f"  {G}[✔]{RST} {W}{url}{RST} — {G}All stages complete{RST}")

    def fail(self, url: str, error: str):
        """Mark a URL as failed."""
        if url not in self._urls:
            self.register(url)
        entry = self._urls[url]
        entry.current_stage = "failed"
        entry.error = error
        entry.finished_at = datetime.now().isoformat()
        print(f"  {R}[✘]{RST} {W}{url}{RST} — {R}Failed:{RST} {error[:80]}")

    def _print_status(self, url: str, stage: str):
        label = STAGE_LABELS.get(stage, stage)
        bar = self._progress_bar(stage)
        short_url = url if len(url) <= 55 else url[:52] + "..."
        print(f"  {C}[→]{RST} {DIM}{short_url}{RST}")
        print(f"      {bar}  {Y}{label}{RST}")

    def _progress_bar(self, current_stage: str) -> str:
        filled = "█"
        empty  = "░"
        width  = len(STAGES)
        try:
            idx = STAGES.index(current_stage)
        except ValueError:
            idx = 0
        bar = filled * (idx + 1) + empty * (width - idx - 1)
        pct = int(((idx + 1) / width) * 100)
        return f"{G}[{bar}]{RST} {DIM}{pct}%{RST}"

    def print_summary(self):
        """Print a summary table of all tracked URLs."""
        if not self._urls:
            return
        print(f"\n  {C}Pipeline Summary{RST}")
        print(f"  {'─' * 60}")
        for url, entry in self._urls.items():
            short = url if len(url) <= 45 else url[:42] + "..."
            if entry.current_stage == "done":
                status = f"{G}Complete{RST}"
            elif entry.current_stage == "failed":
                status = f"{R}Failed{RST}"
            else:
                status = f"{Y}{entry.current_stage}{RST}"
            print(f"  {DIM}{short:<47}{RST}  {status}")
        print()
