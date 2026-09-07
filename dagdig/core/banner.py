#!/usr/bin/env python3
"""
DAGDIG - Metasploit-style banner and startup display
"""
import random
import shutil
import subprocess
from datetime import datetime

# ── ANSI color codes (no external deps) ───────────────────────────────────────
R   = "\033[1;31m"   # bold red
LR  = "\033[1;91m"   # light/bright red
G   = "\033[1;32m"   # bold green
LG  = "\033[1;92m"   # light/bright green
Y   = "\033[1;33m"   # bold yellow
LY  = "\033[1;93m"   # light/bright yellow
B   = "\033[1;34m"   # bold blue
LB  = "\033[1;94m"   # light/bright blue
M   = "\033[1;35m"   # bold magenta
LM  = "\033[1;95m"   # light/bright magenta
C   = "\033[1;36m"   # bold cyan
LC  = "\033[1;96m"   # light/bright cyan
W   = "\033[1;37m"   # bold white
DIM = "\033[2m"     # dim
RST = "\033[0m"     # reset

# ── Color Palettes for Figlet Rendering ───────────────────────────────────────
COLOR_PALETTES = [
    # Cyberpunk (Cyan -> Sky Blue -> Magenta -> Pink)
    [LC, C, LM, M, LB],
    # Fire & Flame (Bold Red -> Bright Red -> Orange/Yellow -> Light Yellow -> White)
    [R, LR, Y, LY, W],
    # Matrix Terminal (Bright Green -> Bold Green -> Dim Green -> Cyan)
    [LG, G, "\033[0;32m", G, LG],
    # Electric Cyan & Blue
    [LC, C, LB, B, LC],
    # Sunset Synthwave (Magenta -> Red -> Yellow -> Light Yellow)
    [LM, LR, Y, LY, W],
    # Blood Red & Crimson
    [R, LR, "\033[0;31m", LR, R],
]

# ── Figlet Fonts to cycle through ─────────────────────────────────────────────
FIGLET_FONTS = ["slant", "standard", "shadow", "small", "smslant"]

# ── Fallback ASCII art banners (used if figlet binary / pyfiglet is unavailable) ──
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

def get_figlet_banner(text: str = "DAGDIG", font: str = None) -> str:
    """Generate colored ASCII art for text using system figlet or pyfiglet, with fallback"""
    selected_font = font or random.choice(FIGLET_FONTS)
    palette = random.choice(COLOR_PALETTES)
    raw_art = None

    # 1. Try system figlet executable
    if shutil.which("figlet"):
        try:
            res = subprocess.run(
                ["figlet", "-f", selected_font, text],
                capture_output=True,
                text=True,
                timeout=2,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                raw_art = res.stdout
            else:
                # Fall back to default standard font if custom font fails
                res_std = subprocess.run(
                    ["figlet", text],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False
                )
                if res_std.returncode == 0 and res_std.stdout.strip():
                    raw_art = res_std.stdout
        except Exception:
            pass

    # 2. Try pyfiglet package if system figlet was not available
    if not raw_art:
        try:
            import pyfiglet
            raw_art = pyfiglet.figlet_format(text, font=selected_font)
        except Exception:
            pass

    # 3. Apply coloration if raw_art was successfully generated
    if raw_art:
        lines = [line for line in raw_art.splitlines() if line.strip()]
        colored_lines = []
        for i, line in enumerate(lines):
            col = palette[i % len(palette)]
            colored_lines.append(f"{col}{line}{RST}")
        return "\n" + "\n".join(colored_lines)

    # 4. Fallback to built-in static banners
    return random.choice(BANNERS)

def print_banner():
    """Print the colored figlet banner and startup status box"""
    art = get_figlet_banner("DAGDIG")
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
