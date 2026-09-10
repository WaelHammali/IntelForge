"""Terminal presentation: theme, banner, and result tables."""

from intelforge.console import tables
from intelforge.console.banner import print_banner, prompt_text, render_banner
from intelforge.console.theme import console, error, good, info, status, warn

__all__ = [
    "console",
    "error",
    "good",
    "info",
    "print_banner",
    "prompt_text",
    "render_banner",
    "status",
    "tables",
    "warn",
]
