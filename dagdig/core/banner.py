#!/usr/bin/env python3
"""
DAGDIG - Metasploit-style banner and startup display
"""
import random
from datetime import datetime

# ── ANSI color codes (no external deps) ───────────────────────────────────────
R  = "\033[1;31m"   # bold red
G  = "\033[1;32m"   # bold green
Y  = "\033[1;33m"   # bold yellow
B  = "\033[1;34m"   # bold blue
M  = "\033[1;35m"   # bold magenta
C  = "\033[1;36m"   # bold cyan
W  = "\033[1;37m"   # bold white
DIM = "\033[2m"     # dim
RST = "\033[0m"     # reset

# ── ASCII art banners (randomly selected, like msfconsole) ────────────────────
BANNERS = [
    rf"""{R}
    ██████╗  █████╗  ██████╗ ██████╗ ██╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔════╝ ██╔══██╗██║██╔════╝ 
    ██║  ██║███████║██║  ███╗██║  ██║██║██║  ███╗
    ██║  ██║██╔══██║██║   ██║██║  ██║██║██║   ██║
    ██████╔╝██║  ██║╚██████╔╝██████╔╝██║╚██████╔╝
    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝ ╚═════╝ {RST}""",

    rf"""{C}
    ____   ____   ____   ____  _  ____  
   |  _ \ / _ \ / ___| |  _ \| |/ ___| 
   | | | | | | | |  _  | | | | | |  _  
   | |_| | |_| | |_| | | |_| | | |_| | 
   |____/ \___/ \____| |____/|_|\____| {RST}""",

    rf"""{M}
     _____     ___     ___   ____   _  _____ 
    |  __ \   / _ \   / __| |  _ \ | ||  ___| 
    | |  | | / /_\ \ | |  _ | | | || || |__ 
    | |  | |/  ___  \| | | || | | || ||  __|
    | |__| |/ /   \ \| |_| || |_| || || |___ 
    |_____//_/     \_\\____| |____/ |_||_____| {RST}""",

    rf"""{G}
   ____   __   ___  ____  ____  ___ 
  |  _ \ / /  / _ \|  _ \|  _ \|_ _|
  | | | | |  | | | | |_) | | | || | 
  | |_| | |__| |_| |  __/| |_| || | 
  |____/ \____\___/|_|   |____/|___|{RST}""",
]

VERSION = "1.0.0"

def print_banner():
    """Print the Metasploit-style startup banner"""
    art = random.choice(BANNERS)
    print(art)

    # ── Stats row (like msf6's module count table) ─────────────────────────────
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    col_w = 60

    def stat_line(left, right=""):
        pad = col_w - len(left) - len(right) - 2
        return f"{W}  {Y}={RST} {left}" + (" " * max(1, pad)) + f"{DIM}{right}{RST}"

    border = f"{W}  {'=' * col_w}{RST}"

    print(border)
    print(f"{W}  {Y}={RST}[ {C}dagdig v{VERSION}{RST} - Domain & Gateway Discovery Intelligence{' ' * 2}]")
    print(f"{W}+ {R}--{W} --={RST}[ {G}Network Scanner{RST}  · {G}Web Fuzzer{RST}  · {G}State Manager{RST}  · {G}LLM Bridge{RST} {' ' * 2}]")
    print(f"{W}+ {R}--{W} --={RST}[ {Y}Recon{RST}: tcp_full · tcp_light · udp_top · udp_light{' ' * 10}]")
    print(f"{W}+ {R}--{W} --={RST}[ {Y}Fuzz{RST}:  dirs · subdomains · vhosts · parameters{' ' * 11}]")
    print(border)
    print()


def get_prompt(context: str = "") -> str:
    """Return the styled dagdig prompt (like msf6 >)"""
    if context:
        return f"{W}dagdig{RST} {R}{context}{RST} {W}>{RST} "
    return f"{W}dagdig{RST} {W}>{RST} "


def print_status(msg: str):
    print(f"{W}[{G}*{W}]{RST} {msg}")

def print_good(msg: str):
    print(f"{W}[{G}+{W}]{RST} {G}{msg}{RST}")

def print_warn(msg: str):
    print(f"{W}[{Y}!{W}]{RST} {Y}{msg}{RST}")

def print_error(msg: str):
    print(f"{W}[{R}-{W}]{RST} {R}{msg}{RST}")

def print_info(msg: str):
    print(f"{W}[{C}i{W}]{RST} {msg}")
