"""Single source of truth for terminal styling.

Everything user-facing goes through the shared :data:`console` (Rich) or the
:func:`status` / :func:`good` / :func:`warn` / :func:`error` / :func:`info`
helpers. Raw ANSI escapes should not appear anywhere else in the codebase.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

THEME = Theme(
    {
        "status": "bold cyan",
        "good": "bold green",
        "warn": "bold yellow",
        "error": "bold red",
        "info": "cyan",
        "dim": "dim",
        "heading": "bold white",
        "accent": "bold magenta",
    }
)

console = Console(theme=THEME, highlight=False)


def status(message: str) -> None:
    console.print(f"[status]\\[*][/status] {message}")


def good(message: str) -> None:
    console.print(f"[good]\\[+] {message}[/good]")


def warn(message: str) -> None:
    console.print(f"[warn]\\[!] {message}[/warn]")


def error(message: str) -> None:
    console.print(f"[error]\\[-] {message}[/error]")


def info(message: str) -> None:
    console.print(f"[info]\\[i][/info] {message}")
