#!/usr/bin/env python3
"""
WebAttackAdvisor — orchestrates the full 3-stage pipeline per URL and
exports a structured JSON exploit report.
"""
import json
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core.state import StateManager
from core.schema import PageAnalysis
from llm import GroqClient, TripleGroqAnalyzer
from attack.tracker import AttackTracker

# ANSI colors (mirrored from banner.py for standalone use)
G   = "\033[1;32m"
Y   = "\033[1;33m"
C   = "\033[1;36m"
W   = "\033[1;37m"
R   = "\033[1;31m"
DIM = "\033[2m"
RST = "\033[0m"


class WebAttackAdvisor:
    """
    Full-pipeline web recon advisor for CTF/HackTheBox machines.

    Usage:
        advisor = WebAttackAdvisor(state)
        advisor.run(urls=["http://10.10.11.1", "http://10.10.11.1/admin"])
    """

    def __init__(self, state: StateManager):
        self.state = state
        self.tracker = AttackTracker()
        self.analyzer = TripleGroqAnalyzer()
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        })

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, urls: list[str]) -> list[PageAnalysis]:
        """
        Run the full 3-stage pipeline on all given URLs.
        Saves each result to state and exports the final JSON report.
        Returns a list of completed PageAnalysis objects.
        """
        if not urls:
            print(f"  {Y}[!] No URLs provided for analysis.{RST}")
            return []

        print(f"\n  {C}[*]{RST} {W}WebAttackAdvisor — Starting 3-Stage Pipeline{RST}")
        print(f"  {DIM}{'─' * 55}{RST}")
        print(f"  {DIM}Target pages: {len(urls)}{RST}\n")

        results: list[PageAnalysis] = []

        for url in urls:
            analysis = self._process_url(url)
            if analysis:
                results.append(analysis)
                self.state.add_page_analysis(analysis)

        self.tracker.print_summary()

        if results:
            report_path = self._export_report(results)
            print(f"  {G}[✔]{RST} Exploit report saved → {W}{report_path}{RST}\n")

        return results

    def run_single(self, url: str) -> PageAnalysis | None:
        """Convenience wrapper: run the pipeline on a single URL."""
        results = self.run([url])
        return results[0] if results else None

    # ── Internal pipeline ─────────────────────────────────────────────────────

    def _process_url(self, url: str) -> PageAnalysis | None:
        """Run all 3 stages for one URL, tracking progress."""
        self.tracker.register(url)

        # Stage 0: Fetch
        self.tracker.advance(url, "fetch")
        raw_html = self._fetch(url)
        if raw_html is None:
            self.tracker.fail(url, "Could not fetch page (connection error or timeout)")
            return None

        try:
            # Stage 1: Cleaner AI
            self.tracker.advance(url, "clean")
            cleaned = self.analyzer.clean_page(raw_html)

            # Stage 2: Analyst AI (Initial Extraction & Suspicious Items)
            self.tracker.advance(url, "intel")
            analysis = self.analyzer.analyze_page_deep(url, cleaned)

            # Stage 3: Researcher AI (DeepSeek R1 Vulnerability & Pentest Research)
            self.tracker.advance(url, "research")
            exploit_report = self.analyzer.research_exploits(analysis)

            # Stage 4: Analyst AI (Final Synthesis with Research Tuples)
            self.tracker.advance(url, "synthesize")
            analysis = self.analyzer.synthesize_final_report(analysis, exploit_report)

            self.tracker.complete(url)
            self._print_analysis_summary(analysis)
            return analysis

        except Exception as e:
            self.tracker.fail(url, str(e))
            return None

    def _fetch(self, url: str) -> str | None:
        """Fetch raw HTML from a URL, returns None on failure."""
        try:
            resp = self._session.get(url, timeout=10, allow_redirects=True)
            return resp.text
        except Exception as e:
            print(f"  {R}[!]{RST} Fetch error for {url}: {e}")
            return None

    def _print_analysis_summary(self, analysis: PageAnalysis):
        """Print a human-readable summary of the findings and research tuples."""
        print(f"\n  {C}╔══ Analysis: {W}{analysis.url}{RST}")
        print(f"  {C}║{RST}  Auth Level       : {Y}{analysis.auth_requirement}{RST}")
        print(f"  {C}║{RST}  Technologies     : {', '.join(analysis.technologies) or DIM + 'None detected' + RST}")

        if analysis.bypass_paths:
            print(f"  {C}║{RST}  Bypass Paths     : {G}{', '.join(analysis.bypass_paths)}{RST}")

        if analysis.auth_pages:
            print(f"  {C}║{RST}  Auth Pages       : {Y}{', '.join(analysis.auth_pages)}{RST}")

        if analysis.upload_points:
            pts = [f"{u.get('path','')} ({u.get('method','')})" for u in analysis.upload_points]
            print(f"  {C}║{RST}  Upload Points    : {R}{', '.join(pts)}{RST}")

        if analysis.injectable_params:
            params = [f"{p.get('param','')} → {p.get('risk','')}" for p in analysis.injectable_params]
            print(f"  {C}║{RST}  Injectable       : {R}{'; '.join(params)}{RST}")

        if analysis.suspicious_items:
            print(f"  {C}║{RST}  Investigated Items: {W}{', '.join(analysis.suspicious_items[:5])}{RST}")

        tuples = analysis.research_tuples or analysis.exploit_report.get('research_tuples', []) or analysis.exploit_report.get('vectors', [])
        if tuples:
            print(f"  {C}║{RST}  Research Tuples  : {R}{len(tuples)} analyzed by DeepSeek{RST}")
            for t in tuples[:4]:
                kw = t.get('keyword', '')
                cve = t.get('cve', 'N/A')
                v_name = t.get('vulnerability_name', '')
                sev = t.get('severity', '')
                relevance = t.get('pentest_relevance', '')
                sev_color = R if sev == "Critical" else Y if sev == "High" else W
                print(f"  {C}║{RST}    {DIM}•{RST} {W}[{kw}]{RST} → {sev_color}[{sev}]{RST} {cve} ({v_name})")
                if relevance:
                    print(f"  {C}║{RST}      {DIM}↳ Pentest Angle: {relevance[:75]}...{RST}")

        attack_order = analysis.exploit_report.get('recommended_attack_order', [])
        if attack_order:
            print(f"  {C}║{RST}  Attack Priority  :")
            for step in attack_order[:3]:
                print(f"  {C}║{RST}    {Y}▶{RST} {DIM}{step}{RST}")

        print(f"  {C}╚{'═' * 55}{RST}\n")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_report(self, analyses: list[PageAnalysis]) -> str:
        """Export all analyses to a structured JSON file in data/."""
        target = self.state.data.target or "unknown"
        hostname = urlparse(target if "://" in target else f"http://{target}").hostname or target
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exploit_{hostname}_{timestamp}.json"

        data_dir = Path(__file__).resolve().parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        out_path = data_dir / filename

        report = {
            "target": self.state.data.target,
            "analyzed_at": datetime.now().isoformat(),
            "pages": [pa.to_dict() for pa in analyses],
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return str(out_path)
