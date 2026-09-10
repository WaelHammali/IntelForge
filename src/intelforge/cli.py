"""Command-line entrypoint: subcommands plus an interactive console."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import click

from intelforge import __version__
from intelforge.config import settings
from intelforge.console import print_banner, prompt_text
from intelforge.console.theme import console, error, good, warn
from intelforge.domain.models import TargetData
from intelforge.domain.state import TargetState
from intelforge.graph import ScanOptions, mermaid, run


def _state() -> TargetState:
    return TargetState(data_dir=settings.data_dir)


def _run_scan(target: str, *, no_web: bool, no_osint: bool, no_llm: bool) -> None:
    state = _state()
    state.set_target(target)
    run(state, ScanOptions(skip_web=no_web, skip_osint=no_osint, skip_llm=no_llm))


def _run_osint(target: str) -> None:
    state = _state()
    state.set_target(target)
    run(state, ScanOptions(skip_nmap=True, skip_web=True, skip_llm=True))


def _run_webanalyze(url: str | None) -> None:
    state = _state()
    if url and not state.data.target:
        state.set_target(urlparse(url).hostname or url)
    if not url and not state.data.target:
        warn("No target. Run 'scan <target>' first, or pass a URL: webanalyze <url>")
        return
    run(state, ScanOptions(skip_recon=True, direct_urls=[url] if url else []))


# ── click subcommands ──────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="intelforge")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """IntelForge — autonomous pentest & AI reconnaissance framework."""
    if ctx.invoked_subcommand is None:
        console_repl()


@cli.command()
@click.argument("target")
@click.option("--no-web", is_flag=True, help="Skip directory/subdomain/vhost fuzzing.")
@click.option("--no-osint", is_flag=True, help="Skip FinalRecon OSINT harvesting.")
@click.option("--no-llm", is_flag=True, help="Skip the AI page-analysis stages.")
def scan(target: str, no_web: bool, no_osint: bool, no_llm: bool) -> None:
    """Full pipeline: recon → command-clean → analyst → researcher → report."""
    _run_scan(target, no_web=no_web, no_osint=no_osint, no_llm=no_llm)


@cli.command()
@click.argument("target")
def osint(target: str) -> None:
    """Passive OSINT only (FinalRecon + command-clean)."""
    _run_osint(target)


@cli.command()
@click.argument("url", required=False)
def webanalyze(url: str | None) -> None:
    """AI web analysis (clean → analyst → researcher → synthesis) without recon."""
    _run_webanalyze(url)


@cli.command()
def show() -> None:
    """Render the current target state as tables."""
    from intelforge.console import tables

    tables.render(_state().data)


@cli.command("set")
@click.argument("field")
@click.argument("value")
def set_field(field: str, value: str) -> None:
    """Manually populate a state field."""
    state = _state()
    state.set_field(field, value)
    good(f"set {field} = {value}")


@cli.command()
@click.argument("filename", default="report.json")
def export(filename: str) -> None:
    """Export the current state to JSON."""
    good(f"exported to {_state().export(filename)}")


@cli.command()
def clear() -> None:
    """Reset the stored target state."""
    state = _state()
    state.data = TargetData()
    state.save()
    good("state reset")


@cli.command()
def banner() -> None:
    """Print a fresh banner."""
    print_banner()


@cli.command("graph")
def show_graph() -> None:
    """Print the pipeline as a Mermaid diagram."""
    console.print(mermaid())


# ── interactive console ────────────────────────────────────────────────────
_HELP = """\
Commands
  use <target>            set the current target
  scan [target] [flags]   full pipeline (--no-web --no-osint --no-llm)
  osint [target]          passive OSINT only
  webanalyze [url]        AI web analysis without recon
  show                    render current results
  set <field> <value>     populate a state field
  export [filename]       write state JSON
  graph                   print the pipeline diagram
  clear                   reset state
  banner                  redraw the banner
  help | exit
"""


def console_repl() -> None:
    print_banner()
    console.print("[dim]Type 'help' for commands, 'exit' to quit.[/dim]\n")
    current = ""

    while True:
        try:
            raw = input(prompt_text(current)).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye[/dim]")
            return
        if not raw:
            continue
        try:
            args = shlex.split(raw)
        except ValueError as exc:
            error(f"parse error: {exc}")
            continue

        cmd, rest = args[0].lower(), args[1:]
        if cmd in {"exit", "quit", "q"}:
            return
        if cmd in {"help", "?"}:
            console.print(_HELP)
        elif cmd == "banner":
            print_banner()
        elif cmd in {"use", "target"} and rest:
            current = rest[0]
            _state().set_target(current)
            good(f"target = {current}")
        elif cmd == "scan":
            target = rest[0] if rest and not rest[0].startswith("-") else current
            if not target:
                warn("usage: scan <target>")
                continue
            current = target
            _run_scan(
                target,
                no_web="--no-web" in rest,
                no_osint="--no-osint" in rest,
                no_llm="--no-llm" in rest,
            )
        elif cmd == "osint":
            target = rest[0] if rest else current
            if not target:
                warn("usage: osint <target>")
                continue
            current = target
            _run_osint(target)
        elif cmd == "webanalyze":
            _run_webanalyze(rest[0] if rest else None)
        elif cmd == "show":
            from intelforge.console import tables

            tables.render(_state().data)
        elif cmd == "set" and len(rest) >= 2:
            _state().set_field(rest[0], rest[1])
            good(f"set {rest[0]} = {rest[1]}")
        elif cmd == "export":
            good(f"exported to {_state().export(rest[0] if rest else 'report.json')}")
        elif cmd == "graph":
            console.print(mermaid())
        elif cmd in {"clear", "reset"}:
            state = _state()
            state.data = TargetData()
            state.save()
            good("state reset")
        else:
            warn(f"unknown command: {cmd!r} — try 'help'")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
