"""Command-line entrypoint: subcommands plus an interactive console.

Every user command — typed as ``intelforge <cmd>`` or at the interactive
prompt — is handled by exactly one ``_cmd_*`` function below. The Click
subcommands and the REPL are thin front-ends over that shared layer, so the
two interfaces can never drift apart.
"""

from __future__ import annotations

import shlex
from typing import NoReturn

import click

from intelforge import __version__
from intelforge.config import settings
from intelforge.console import print_banner, prompt_text
from intelforge.console.theme import console, error, good, warn
from intelforge.domain.models import TargetData
from intelforge.domain.state import TargetState
from intelforge.graph import GraphState, ScanOptions, mermaid, run


def _state() -> TargetState:
    return TargetState(data_dir=settings.data_dir)


def _fail(message: str) -> NoReturn:
    """Abort the current command with a clean message and exit code 1."""
    raise click.ClickException(message)


# ── shared command handlers ────────────────────────────────────────────────
def _cmd_set_target(state: TargetState, target: str) -> None:
    try:
        state.set_target(target)
    except ValueError as exc:
        _fail(str(exc))


def _cmd_pipeline(state: TargetState, options: ScanOptions) -> GraphState:
    try:
        result = run(state, options)
    except Exception as exc:  # surface any pipeline failure as a clean exit 1
        _fail(f"pipeline failed: {exc}")
    if not result.get("report_path"):
        _fail("pipeline finished without producing a report")
    return result


def _cmd_scan(target: str, *, no_web: bool, no_osint: bool, no_llm: bool) -> GraphState:
    state = _state()
    _cmd_set_target(state, target)
    return _cmd_pipeline(state, ScanOptions(skip_web=no_web, skip_osint=no_osint, skip_llm=no_llm))


def _cmd_osint(target: str) -> GraphState:
    state = _state()
    _cmd_set_target(state, target)
    return _cmd_pipeline(state, ScanOptions(skip_nmap=True, skip_web=True, skip_llm=True))


def _cmd_webanalyze(url: str | None) -> GraphState | None:
    state = _state()
    if url:
        _cmd_set_target(state, url)
    elif not state.data.target:
        warn("No target. Run 'scan <target>' first, or pass a URL: webanalyze <url>")
        return None
    return _cmd_pipeline(state, ScanOptions(skip_recon=True, direct_urls=[url] if url else []))


def _cmd_show() -> None:
    from intelforge.console import tables

    tables.render(_state().data)


def _cmd_set_field(field: str, value: str) -> None:
    state = _state()
    if not hasattr(state.data, field):
        _fail(f"unknown state field: {field!r}")
    state.set_field(field, value)
    good(f"set {field} = {value}")


def _cmd_export(filename: str) -> None:
    good(f"exported to {_state().export(filename)}")


def _cmd_clear() -> None:
    state = _state()
    state.data = TargetData()
    state.save()
    good("state reset")


def _cmd_graph() -> None:
    console.print(mermaid())


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
    _cmd_scan(target, no_web=no_web, no_osint=no_osint, no_llm=no_llm)


@cli.command()
@click.argument("target")
def osint(target: str) -> None:
    """Passive OSINT only (FinalRecon + command-clean)."""
    _cmd_osint(target)


@cli.command()
@click.argument("url", required=False)
def webanalyze(url: str | None) -> None:
    """AI web analysis (clean → analyst → researcher → synthesis) without recon."""
    _cmd_webanalyze(url)


@cli.command()
def show() -> None:
    """Render the current target state as tables."""
    _cmd_show()


@cli.command("set")
@click.argument("field")
@click.argument("value")
def set_field(field: str, value: str) -> None:
    """Manually populate a state field."""
    _cmd_set_field(field, value)


@cli.command()
@click.argument("filename", default="report.json")
def export(filename: str) -> None:
    """Export the current state to JSON."""
    _cmd_export(filename)


@cli.command()
def clear() -> None:
    """Reset the stored target state."""
    _cmd_clear()


@cli.command()
def banner() -> None:
    """Print a fresh banner."""
    print_banner()


@cli.command("graph")
def show_graph() -> None:
    """Print the pipeline as a Mermaid diagram."""
    _cmd_graph()


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


def _repl_dispatch(cmd: str, rest: list[str], current: str) -> str:
    """Run one REPL command; return the (possibly updated) current target."""
    if cmd in {"help", "?"}:
        console.print(_HELP)
    elif cmd == "banner":
        print_banner()
    elif cmd in {"use", "target"} and rest:
        _cmd_set_target(_state(), rest[0])
        good(f"target = {rest[0]}")
        return rest[0]
    elif cmd == "scan":
        target = rest[0] if rest and not rest[0].startswith("-") else current
        if not target:
            warn("usage: scan <target>")
            return current
        _cmd_scan(
            target,
            no_web="--no-web" in rest,
            no_osint="--no-osint" in rest,
            no_llm="--no-llm" in rest,
        )
        return target
    elif cmd == "osint":
        target = rest[0] if rest else current
        if not target:
            warn("usage: osint <target>")
            return current
        _cmd_osint(target)
        return target
    elif cmd == "webanalyze":
        _cmd_webanalyze(rest[0] if rest else None)
    elif cmd == "show":
        _cmd_show()
    elif cmd == "set" and len(rest) >= 2:
        _cmd_set_field(rest[0], rest[1])
    elif cmd == "export":
        _cmd_export(rest[0] if rest else "report.json")
    elif cmd == "graph":
        _cmd_graph()
    elif cmd in {"clear", "reset"}:
        _cmd_clear()
    else:
        warn(f"unknown command: {cmd!r} — try 'help'")
    return current


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
        try:
            current = _repl_dispatch(cmd, rest, current)
        except click.ClickException as exc:
            error(exc.format_message())


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
