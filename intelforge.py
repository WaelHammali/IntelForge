#!/usr/bin/env python3
"""
IntelForge Scanning Framework — Root Launcher Script
Keystone Groupe, Tunisia · AI & CyberSecurity Project 2026
"""
import sys
import os
from pathlib import Path

# Set working directory to the inner package folder
child_dir = Path(__file__).parent / "dagdig"
if child_dir.exists():
    sys.path.insert(0, str(child_dir))
    os.chdir(child_dir)

from dagdig import cli

if __name__ == "__main__":
    cli(obj={})
