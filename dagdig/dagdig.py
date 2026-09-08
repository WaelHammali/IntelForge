#!/usr/bin/env python3
"""
DAGDIG - Domain & Gateway Discovery Intelligence Gathering
Main CLI entry point with interactive shell mode.
"""
import sys
import shlex
import click
from pathlib import Path
from core import StateManager, TargetData
from core.banner import (
    print_banner, print_good, print_status, print_warn, print_error, print_info, get_prompt,
    W, G, Y, R, C, DIM, RST
)
from exec.runner import DiscoveryRunner
from llm import GroqClient, DualGroqAnalyzer, TripleGroqAnalyzer
from attack import WebAttackAdvisor

try:
    import readline
except ImportError:
    pass


def start_shell(state: StateManager):
    """Interactive Metasploit-style console REPL"""
    print_banner()
    print(f"  {DIM}Type {C}'help'{DIM} or {C}'?'{DIM} for commands, {C}'exit'{DIM} to leave.{RST}\n")

    current_target = ""

    while True:
        prompt_str = get_prompt(current_target)

        try:
            user_input = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{W}[*] Exiting DAGDIG.{RST}")
            break

        if not user_input:
            continue

        try:
            args = shlex.split(user_input)
        except Exception as e:
            print_error(f"Command parse error: {e}")
            continue

        cmd = args[0].lower()

        if cmd in ("exit", "quit", "q"):
            print(f"{W}[*] Exiting DAGDIG.{RST}")
            break

        elif cmd in ("help", "?"):
            print(f"\n{W}Core Commands{RST}")
            print(f"{DIM}============={RST}\n")
            print(f"  {C}Command{RST}                   {C}Description{RST}")
            print(f"  {DIM}-------                   -----------{RST}")
            print(f"  {G}use <target>{RST}              Set current target IP address or domain for session")
            print(f"  {G}scan [target]{RST}             Run full reconnaissance scan (nmap + web fuzzing + FinalRecon OSINT)")
            print(f"  {G}osint [target]{RST}            Run standalone FinalRecon OSINT scan")
            print(f"  {G}show{RST}                      Display current scan results in Unicode box tables")
            print(f"  {G}analyze{RST}                   Basic Dual-Groq AI page analysis")
            print(f"  {G}webanalyze [url]{RST}          {Y}3-Stage deep CTF recon: clean→intel→exploit research{RST}")
            print(f"  {G}set <field> <val>{RST}         Manually populate a state field/cell")
            print(f"  {G}export [filename]{RST}         Export current scan state to JSON file")
            print(f"  {G}clear / reset{RST}             Reset current target state")
            print(f"  {G}banner{RST}                    Display a new random ASCII banner")
            print(f"  {G}help / ?{RST}                  Display this help menu")
            print(f"  {G}exit / quit{RST}               Exit DAGDIG console\n")

        elif cmd == "banner":
            print_banner()

        elif cmd in ("use", "target"):
            if len(args) < 2:
                print_warn("Usage: use <IP or domain>  (e.g., use 192.168.1.1)")
                continue
            current_target = args[1]
            state.set_target(current_target)
            print_good(f"Selected target: {current_target}")

        elif cmd == "scan":
            target = args[1] if len(args) > 1 else current_target
            if not target:
                print_warn("No target specified. Usage: scan <IP or domain>  OR  type 'use <target>' first.")
                continue
            current_target = target
            no_web = "--no-web" in args
            no_osint = "--no-osint" in args
            state.set_target(target)
            print_status(f"Starting reconnaissance on target: {target}")
            runner = DiscoveryRunner(state)
            runner.run_discovery(no_web=no_web, no_osint=no_osint)
            print_good("Scan complete. Run 'show' to view results.")

        elif cmd == "osint":
            target = args[1] if len(args) > 1 else current_target
            if not target:
                print_warn("No target specified. Usage: osint <IP or domain>  OR  type 'use <target>' first.")
                continue
            current_target = target
            state.set_target(target)
            from exec.osint import OsintScanner
            osint_scanner = OsintScanner(state)
            osint_scanner.run_osint(target)
            print_good("OSINT scan complete. Run 'show' to view results.")

        elif cmd == "show":
            if not state.data.target:
                print_warn("No target set yet. Type 'use <ip>' or 'scan <ip>' first.")
            else:
                state.print_table()

        elif cmd == "analyze":
            run_ai_analysis(state)

        elif cmd == "webanalyze":
            url_arg = args[1] if len(args) > 1 else None
            run_web_analyze(state, url_arg)

        elif cmd == "set":
            if len(args) < 3:
                print_warn("Usage: set <field> <value>  (e.g., set target 192.168.1.1 or set directories admin)")
                continue
            field, val = args[1], args[2]
            state.set_field(field, val)
            if field == "target":
                current_target = val
            print_good(f"Set {field} = {val}")

        elif cmd == "export":
            filename = args[1] if len(args) > 1 else "results.json"
            saved_path = state.export(filename)
            print_good(f"Exported to {saved_path}")


        elif cmd in ("clear", "reset"):
            state.data = TargetData()
            state.save()
            current_target = ""
            print_good("State reset.")

        else:
            print_warn(f"Unknown command: '{cmd}'. Type 'help' for available commands.")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """DAGDIG - Advanced Reconnaissance Tool"""
    ctx.ensure_object(dict)
    state = StateManager()
    ctx.obj['state'] = state

    # Bare invocation without arguments launches interactive console
    if ctx.invoked_subcommand is None:
        if len(sys.argv) == 1:
            start_shell(state)
        else:
            print_banner()
            click.echo(ctx.get_help())
    elif ctx.invoked_subcommand != "banner":
        print_banner()


@cli.command()
@click.argument('target')
@click.option('--no-web', is_flag=True, help='Skip web fuzzing')
@click.pass_context
def scan(ctx, target, no_web):
    """Full reconnaissance scan: discover + process"""
    state = ctx.obj['state']
    state.set_target(target)
    print_status(f"Starting reconnaissance on target: {target}")
    runner = DiscoveryRunner(state)
    runner.run_discovery(no_web=no_web)
    print_good("Scan complete. Run 'show' to view results.")


@cli.command()
@click.pass_context
def show(ctx):
    """Show current target data in box-drawn tables"""
    state = ctx.obj['state']
    if not state.data.target:
        print_warn("No scan data found. Run 'scan <target>' first.")
        return
    state.print_table()


@cli.command()
@click.argument('field')
@click.argument('value')
@click.pass_context
def set(ctx, field, value):
    """Manually set a field in the target data"""
    state = ctx.obj['state']
    state.set_field(field, value)
    print_good(f"Set {field} = {value}")


@cli.command()
@click.argument('filename', default='data/state.json')
@click.pass_context
def export(ctx, filename):
    """Export current state to JSON"""
    state = ctx.obj['state']
    state.export(filename)
    print_good(f"Exported to {filename}")



@cli.command()
@click.pass_context
def clear(ctx):
    """Clear current state"""
    state = ctx.obj['state']
    state.data = TargetData()
    state.save()
    print_good("State cleared.")


@cli.command()
@click.pass_context
def banner(ctx):
    """Display a new random banner (like msfconsole's 'banner' command)"""
    print_banner()


def run_ai_analysis(state: StateManager):
    """Run Dual-Groq AI target analysis across discovered URLs/paths"""
    if not state.data.target:
        print_warn("No target set yet. Type 'use <ip>' or 'scan <ip>' first.")
        return

    import requests

    client = GroqClient()
    if not client.is_configured():
        print_warn("GROQ_API_KEY is missing or unconfigured!")
        print_info("Set GROQ_API_KEY in your .env file or environment variable.")
        print_info("Example: export GROQ_API_KEY=\"your-groq-key\"")
        return

    analyzer = DualGroqAnalyzer(client)

    target = state.data.target
    urls_to_analyze = set()

    base_url = target if target.startswith('http') else f"http://{target}"
    urls_to_analyze.add(base_url)

    for d in state.data.directories:
        clean_d = d.lstrip('/')
        urls_to_analyze.add(f"{base_url}/{clean_d}")

    for sub in state.data.subdomains + state.data.vhosts:
        urls_to_analyze.add(f"http://{sub}")

    print_status(f"Starting Dual-Groq AI Analysis on {len(urls_to_analyze)} target page(s)...")

    session = requests.Session()
    session.verify = False

    for url in sorted(urls_to_analyze):
        print_status(f"Fetching content from: {url}")
        try:
            resp = session.get(url, timeout=5, allow_redirects=True)
            raw_html = resp.text
        except Exception as e:
            print_warn(f"Could not fetch {url}: {e}")
            continue

        print_status(f"Processing Dual-Groq AI Pipeline for {url}...")
        try:
            analysis = analyzer.process_url(url, raw_html)
            state.add_page_analysis(analysis)
            print_good(f"Analyzed {url} -> Access: {analysis.auth_requirement} | Tech: {', '.join(analysis.technologies) if analysis.technologies else 'None detected'}")
        except Exception as e:
            print_error(f"AI analysis failed for {url}: {e}")

    print_good("Dual-Groq AI Analysis complete!")
    state.print_table()


def run_web_analyze(state: StateManager, direct_url: str = None):
    """
    Run the full 3-stage WebAttackAdvisor pipeline.
    If direct_url is given, analyse only that URL.
    Otherwise, build the URL list from state (same as analyze command).
    """
    client = GroqClient()
    if not client.is_configured():
        print_warn("GROQ_API_KEY is missing or unconfigured!")
        print_info("Set GROQ_API_KEY in your .env file or environment variable.")
        return

    urls_to_analyze: list[str] = []

    if direct_url:
        urls_to_analyze.append(direct_url)
        # If a target is not yet set, derive it from the URL
        if not state.data.target:
            from urllib.parse import urlparse
            parsed = urlparse(direct_url)
            state.set_target(parsed.hostname or direct_url)
    else:
        if not state.data.target:
            print_warn("No target set. Use 'use <ip>' or 'scan <ip>' first, or pass a URL directly: webanalyze <url>")
            return

        target = state.data.target
        base_url = target if target.startswith('http') else f"http://{target}"
        urls_to_analyze.append(base_url)
        for d in state.data.directories:
            clean_d = d.lstrip('/')
            urls_to_analyze.append(f"{base_url}/{clean_d}")
        for sub in state.data.subdomains + state.data.vhosts:
            urls_to_analyze.append(f"http://{sub}")

    advisor = WebAttackAdvisor(state)
    advisor.run(urls=list(dict.fromkeys(urls_to_analyze)))  # deduplicate preserving order
    state.print_table()


@cli.command()
@click.argument('target')
@click.pass_context
def osint(ctx, target):
    """Run standalone FinalRecon OSINT scan on target"""
    state = ctx.obj['state']
    state.set_target(target)
    from exec.osint import OsintScanner
    osint_scanner = OsintScanner(state)
    osint_scanner.run_osint(target)
    print_good("OSINT scan complete. Run 'show' to view results.")


@cli.command()
@click.pass_context
def analyze(ctx):
    """Analyze target web pages using Dual-Groq AI pipeline"""
    run_ai_analysis(ctx.obj['state'])


@cli.command()
@click.argument('url', required=False)
@click.pass_context
def webanalyze(ctx, url):
    """3-Stage deep CTF web recon: clean → intel → exploit research → JSON report"""
    run_web_analyze(ctx.obj['state'], url)


if __name__ == '__main__':
    cli(obj={})

