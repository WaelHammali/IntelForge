#!/usr/bin/env python3
"""
Demo script: fetch a URL, clean it with Groq Model 1, then extract intelligence with Groq Model 2.
Uses the DualGroqAnalyzer (cleaner + filler) already in the DAGDIG codebase.

Ensure you have a valid GROQ_API_KEY and GROQ_MODEL set in a .env file or environment.
"""

import sys
import json
import requests
from pathlib import Path

# Add the DAGDIG package to PYTHONPATH (script resides in <repo>/dagdig/scripts)
project_root = Path(__file__).resolve().parents[2]  # <repo> directory
sys.path.insert(0, str(project_root / "dagdig"))

from llm import DualGroqAnalyzer, GroqClient
from core.banner import print_warn, print_good


def fetch_raw_html(url: str) -> str:
    """Retrieve the raw HTML of *url* (returns empty string on error)."""
    try:
        resp = requests.get(url, timeout=12, verify=False)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print_warn(f"Failed to fetch {url}: {e}")
        return ""


def main():
    # ---------------------------------------------------------------------
    # 1️⃣ Choose a target URL – replace with any site you want to analyse.
    # ---------------------------------------------------------------------
    target_url = "https://example.com"

    # ---------------------------------------------------------------------
    # 2️⃣ Pull the raw page content.
    # ---------------------------------------------------------------------
    raw_html = fetch_raw_html(target_url)
    if not raw_html:
        print_warn("No HTML retrieved – exiting demo.")
        return

    # ---------------------------------------------------------------------
    # 3️⃣ Initialise the dual‑Groq pipeline (cleaner + filler).
    # ---------------------------------------------------------------------
    client   = GroqClient()
    analyzer = DualGroqAnalyzer(client)

    if not client.is_configured():
        print_warn("Groq API not configured – aborting demo.")
        return

    # ---------------------------------------------------------------------
    # 4️⃣ Cleaner model – produce a noise‑free text representation.
    # ---------------------------------------------------------------------
    print("\n=== Cleaner model output (raw → cleaned) ===\n")
    cleaned_text = analyzer.clean_page(raw_html)
    # Show a preview – truncate for readability.
    print(cleaned_text[:800])
    if len(cleaned_text) > 800:
        print("\n…[truncated]…\n")

    # ---------------------------------------------------------------------
    # 5️⃣ Filler (Intelligence) model – extract structured data.
    # ---------------------------------------------------------------------
    print("\n=== Filler model output (structured JSON) ===\n")
    analysis = analyzer.analyze_page(target_url, cleaned_text)
    # Pretty‑print the dataclass as JSON for easy viewing.
    print(json.dumps(analysis.__dict__, indent=2))

    print_good("Demo completed.")


if __name__ == "__main__":
    main()
