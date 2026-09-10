"""Pipeline nodes — thin wrappers binding tools and agents to graph state."""

from __future__ import annotations

import concurrent.futures
from typing import Any
from urllib.parse import urlparse

import requests
from langchain_core.language_models import BaseChatModel

from intelforge.agents.analyst import Analyst
from intelforge.agents.command_cleaner import CommandCleaner
from intelforge.agents.html_cleaner import HtmlCleaner
from intelforge.agents.llm import chat_model
from intelforge.agents.researcher import Researcher
from intelforge.config import settings
from intelforge.console.theme import good, status, warn
from intelforge.graph.state import GraphState
from intelforge.tools.finalrecon import FinalReconScanner
from intelforge.tools.http import new_session
from intelforge.tools.nmap import NmapScanner
from intelforge.tools.webfuzz import WebFuzzer


def _maybe_model(role: str) -> BaseChatModel | None:
    try:
        return chat_model(role)
    except Exception as exc:  # missing key, unknown provider, ...
        warn(f"LLM role '{role}' unavailable ({exc}); related steps will be skipped")
        return None


# ── recon ──────────────────────────────────────────────────────────────────
def recon(gstate: GraphState) -> dict[str, Any]:
    state, opts = gstate["target"], gstate["options"]
    if opts.skip_recon:
        return {}
    ti = state.target_info()
    web_target = ti.url or ti.host

    tasks: list[tuple[str, Any]] = []
    if not opts.skip_nmap:
        tasks.append(("nmap", lambda: NmapScanner(state).run_all(ti.host)))
    if not opts.skip_osint:
        tasks.append(("finalrecon", lambda: FinalReconScanner(state).run(web_target)))
    if not opts.skip_web and not ti.is_ip:
        tasks.append(("webfuzz", lambda: WebFuzzer(state).run_all(web_target)))
    if not tasks:
        return {}

    status(f"Reconnaissance on {ti.raw} — {len(tasks)} collectors")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                future.result()
                good(f"{name} finished")
            except Exception as exc:
                warn(f"{name} failed: {exc}")
    state.save()
    return {}


# ── command cleaner ────────────────────────────────────────────────────────
def clean_commands(gstate: GraphState) -> dict[str, Any]:
    CommandCleaner(_maybe_model("cleaner")).run(gstate["target"])
    return {}


# ── page fetch ─────────────────────────────────────────────────────────────
def _page_urls(gstate: GraphState) -> list[str]:
    opts = gstate["options"]
    if opts.direct_urls:
        return list(dict.fromkeys(opts.direct_urls))
    state = gstate["target"]
    if not state.data.target:
        return []
    ti = state.target_info()
    base = ti.url.rstrip("/") if ti.url else f"http://{ti.host}"
    scheme = urlparse(base).scheme
    urls: set[str] = {base}
    for host in [*state.data.subdomains, *state.data.vhosts]:
        urls.add(f"{scheme}://{host}")
    for directory in state.data.directories:
        urls.add(f"{base}/{directory.lstrip('/')}")
    return sorted(urls)


def fetch_pages(gstate: GraphState) -> dict[str, Any]:
    if gstate["options"].skip_llm:
        return {"raw_pages": {}}
    urls = _page_urls(gstate)
    status(f"Fetching {len(urls)} page(s)")
    session = new_session()
    pages: dict[str, str] = {}
    for url in urls:
        try:
            resp = session.get(url, timeout=settings.request_timeout)
            pages[url] = resp.text
        except requests.RequestException as exc:
            warn(f"fetch failed {url}: {exc}")
    return {"raw_pages": pages}


# ── HTML cleaner ───────────────────────────────────────────────────────────
def clean_html(gstate: GraphState) -> dict[str, Any]:
    raw_pages = gstate.get("raw_pages") or {}
    model = _maybe_model("cleaner")
    if not raw_pages or model is None:
        return {"cleaned_pages": {}}
    cleaner = HtmlCleaner(model)
    cleaned = {url: cleaner.clean(html) for url, html in raw_pages.items()}
    good(f"Cleaned {len(cleaned)} page(s)")
    return {"cleaned_pages": cleaned}


# ── analyst (Stage 2) ──────────────────────────────────────────────────────
def analyst(gstate: GraphState) -> dict[str, Any]:
    cleaned = gstate.get("cleaned_pages") or {}
    model = _maybe_model("analyst")
    if not cleaned or model is None:
        return {"analyses": []}
    analyses = Analyst(model).extract_surface(cleaned)
    for analysis in analyses:
        gstate["target"].add_page_analysis(analysis)
    good(f"Analyst mapped {len(analyses)} page(s)")
    return {"analyses": analyses}


# ── researcher + synthesis (Stage 3 + 4) ──────────────────────────────────
def research(gstate: GraphState) -> dict[str, Any]:
    analyses = gstate.get("analyses") or []
    r_model, a_model = _maybe_model("researcher"), _maybe_model("analyst")
    if not analyses or r_model is None or a_model is None:
        return {}
    state = gstate["target"]
    nmap_summary = state.get_nmap_summary()
    command_summary = state.get_command_table()
    researcher, synthesizer = Researcher(r_model), Analyst(a_model)
    for analysis in analyses:
        try:
            report = researcher.research(analysis, nmap_summary, command_summary)
            enriched = synthesizer.synthesize(analysis, report, command_summary)
            state.add_page_analysis(enriched)
        except Exception as exc:
            warn(f"research/synthesis failed for {analysis.url}: {exc}")
    good("Intelligence synthesis complete")
    return {}


# ── report ─────────────────────────────────────────────────────────────────
def report(gstate: GraphState) -> dict[str, Any]:
    from intelforge.console import tables
    from intelforge.reporting.json_report import write_report

    state = gstate["target"]
    state.save()
    path = write_report(state)
    tables.render(state.data)
    good(f"Report written to {path}")
    return {"report_path": str(path)}


__all__ = [
    "analyst",
    "clean_commands",
    "clean_html",
    "fetch_pages",
    "recon",
    "report",
    "research",
]
