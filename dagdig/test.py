#!/usr/bin/env python3
"""
Test script for DAGDIG penetration core.
Runs all scans on a target and displays the results table.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core.state import StateManager
from exec.runner import DiscoveryRunner

def main():
    target = "example.com"  # Change to your target
    print(f"[*] Testing DAGDIG penetration core on {target}\n")

    state = StateManager()
    state.set_target(target)

    runner = DiscoveryRunner(state)
    runner.run_discovery()

    state.print_table()
    state.export("data/report.json")
    print("[+] Report exported to data/report.json")

if __name__ == "__main__":
    main()
