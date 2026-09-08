#!/usr/bin/env python3
"""
Orchestrates all discovery tasks in parallel
"""
import concurrent.futures
import requests
from core.state import StateManager
from core.banner import print_status, print_good, print_warn, print_error
from .network import NetworkScanner
from .web import WebFuzzer
from .osint import OsintScanner
from llm import TripleGroqAnalyzer, GroqClient

class DiscoveryRunner:
    def __init__(self, state: StateManager):
        self.state = state
        self.network = NetworkScanner(state)
        self.web = WebFuzzer(state)
        self.osint = OsintScanner(state)
        self.analyzer = TripleGroqAnalyzer(GroqClient())

    def run_discovery(self, no_web: bool = False, no_llm: bool = False, no_osint: bool = False):
        """Run all nmap scans, web fuzzing tasks, and FinalRecon OSINT in parallel, then optionally run LLM analysis on discovered URLs."""
        target = self.state.data.target
        print_status(f"Starting discovery on {target}")

        # Build task list: (name, callable)
        tasks = [
            ('nmap_tcp_full', lambda: self.network.scan_tcp_full(target)),
            ('nmap_udp_top', lambda: self.network.scan_udp_top(target)),
            ('nmap_tcp_light', lambda: self.network.scan_tcp_light(target)),
            ('nmap_udp_light', lambda: self.network.scan_udp_light(target)),
        ]

        if not no_osint:
            tasks.append(('finalrecon_osint', lambda: self.osint.run_osint(target)))

        # Add web fuzzing if target looks like a domain (contains non-digit) and no_web is disabled
        if not no_web and not target.replace('.', '').isdigit():
            tasks.append(('fuzz_dirs', lambda: self.web.fuzz_directories(target)))
            tasks.append(('fuzz_subdomains', lambda: self.web.fuzz_subdomains(target)))
            tasks.append(('fuzz_vhosts', lambda: self.web.fuzz_vhosts(target)))

        # Run everything in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {executor.submit(func): name for name, func in tasks}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    print_good(f"{name} completed")
                except Exception as e:
                    print_error(f"{name} failed: {e}")

        # --- LLM post‑processing -------------------------------------------------
        if not no_llm and self.analyzer.cleaner_client.is_configured():
            # Build a list of URLs to analyze (subdomains, vhosts, directories)
            base_scheme = 'https' if target.startswith('https') else 'http'
            urls = set()
            for sub in self.state.data.subdomains:
                urls.add(f"{base_scheme}://{sub}")
            for vhost in self.state.data.vhosts:
                urls.add(f"{base_scheme}://{vhost}")
            for dir_path in self.state.data.directories:
                # Assume directory on the main target host
                urls.add(f"{base_scheme}://{target}/{dir_path.lstrip('/')}")

            print_status(f"Running LLM analysis on {len(urls)} discovered URLs")
            
            cleaned_pages = {}
            for url in urls:
                try:
                    resp = requests.get(url, timeout=10, verify=False)
                    raw_html = resp.text
                except Exception as e:
                    print_warn(f"Failed to fetch {url}: {e}")
                    continue

                # Stage 1: Clean each page individually
                cleaned = self.analyzer.clean_page(raw_html)
                cleaned_pages[url] = cleaned
                print_good(f"Cleaned {url}")
                
            if cleaned_pages:
                print_status(f"Sending {len(cleaned_pages)} cleaned pages to Analyzer for combined report...")
                # Stage 2: Analyze all cleaned pages at once
                analyses = self.analyzer.analyze_multiple_pages(cleaned_pages)
                for analysis in analyses:
                    # Save initial analysis
                    self.state.add_page_analysis(analysis)

                # Perform Stage 3 research (exploit research) using Nmap findings
                nmap_summary = self.state.get_nmap_summary()
                for analysis in analyses:
                    try:
                        exploit_report = self.analyzer.research_exploits(analysis, nmap_summary=nmap_summary)
                        enriched = self.analyzer.synthesize_final_report(analysis, exploit_report)
                        self.state.add_page_analysis(enriched)
                    except Exception as e:
                        print_warn(f"Research/synthesis failed for {analysis.url}: {e}")

                print_good("Intelligence analysis complete")
        else:
            if not self.analyzer.cleaner_client.is_configured():
                print_warn("Groq API not configured – skipping LLM analysis.")

        print_good("All discovery tasks finished")
        self.state.print_table()
