"""ASCII banner and interactive-prompt rendering."""

from __future__ import annotations

import random
import shutil
import subprocess

from rich.text import Text

from intelforge import __version__
from intelforge.console.theme import console

_FIGLET_FONTS = ("slant", "standard", "shadow", "small", "smslant")
_PALETTES: tuple[tuple[str, ...], ...] = (
    ("bright_cyan", "cyan", "bright_magenta", "magenta", "bright_blue"),
    ("red", "bright_red", "yellow", "bright_yellow", "white"),
    ("bright_green", "green", "green", "bright_green", "cyan"),
    ("bright_magenta", "bright_red", "yellow", "bright_yellow", "white"),
)

_FALLBACK = r"""
 ___       _       _ _____
|_ _|_ __ | |_ ___| |  ___|__  _ __ __ _  ___
 | || '_ \| __/ _ \ | |_ / _ \| '__/ _` |/ _ \
 | || | | | ||  __/ |  _| (_) | | | (_| |  __/
|___|_| |_|\__\___|_|_|  \___/|_|  \__, |\___|
                                   |___/
"""


def _figlet(text: str) -> str | None:
    font = random.choice(_FIGLET_FONTS)
    if shutil.which("figlet"):
        for args in (["figlet", "-f", font, text], ["figlet", text]):
            try:
                res = subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
            except (OSError, subprocess.SubprocessError):
                continue
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout
    try:
        import pyfiglet  # type: ignore[import-not-found]

        return str(pyfiglet.figlet_format(text, font=font))
    except Exception:
        return None


def render_banner(text: str = "IntelForge") -> Text:
    art = _figlet(text) or _FALLBACK
    palette = random.choice(_PALETTES)
    banner = Text()
    for i, line in enumerate([ln for ln in art.splitlines() if ln.strip()]):
        banner.append(line + "\n", style=palette[i % len(palette)])
    return banner


def print_banner() -> None:
    console.print(render_banner())
    console.print(
        f"  [accent]IntelForge v{__version__}[/accent] "
        "[dim]· Autonomous Pentest & AI Recon · LangGraph pipeline[/dim]"
    )
    console.print(
        "  [dim]Passive OSINT (FinalRecon) · Active Recon (Nmap) · Web Fuzzer · "
        "Cleaner → Analyst → Researcher → Synthesis[/dim]\n"
    )


def prompt_text(context: str = "") -> str:
    """Plain-text prompt for :func:`input` (Rich markup is not usable here)."""
    return f"intelforge ({context}) > " if context else "intelforge > "
