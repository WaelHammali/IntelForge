"""Stage 3 — deep vulnerability / exploit research (reasoning model)."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel

from intelforge.agents._json import loads
from intelforge.agents.llm import complete
from intelforge.agents.prompts import load_prompt
from intelforge.console.theme import warn
from intelforge.domain.models import PageAnalysis

_EMPTY_REPORT: dict[str, Any] = {
    "summary": "No recon items available for research.",
    "risk_level": "Unknown",
    "research_tuples": [],
    "vectors": [],
    "recommended_attack_order": [],
}


class Researcher:
    def __init__(self, model: BaseChatModel) -> None:
        self.model = model
        self.system = load_prompt("exploit_research")

    def research(
        self,
        analysis: PageAnalysis,
        nmap_summary: str = "",
        command_summary: str = "",
    ) -> dict[str, Any]:
        items = list(dict.fromkeys(analysis.suspicious_items + analysis.keyword_fingerprints))
        if not items and not analysis.llm_recon_paragraph and not nmap_summary:
            return dict(_EMPTY_REPORT)

        context: list[str] = []
        if nmap_summary:
            context += ["Nmap Discovered Ports & Service Versions:", nmap_summary, ""]
        if items:
            context.append("Suspicious Items / Keywords to Investigate:")
            context += [f"- {item}" for item in items]
            context.append("")
        if analysis.llm_recon_paragraph:
            context += [f"Analyst Recon Brief:\n{analysis.llm_recon_paragraph}", ""]
        if analysis.upload_points:
            context.append(
                "Upload endpoints: "
                + "; ".join(
                    f"{u.get('path', '')} [{u.get('method', '')}]" for u in analysis.upload_points
                )
            )
        if analysis.injectable_params:
            context.append(
                "Injectable parameters: "
                + "; ".join(
                    f"{p.get('param', '')} in {p.get('location', '')} ({p.get('risk', '')})"
                    for p in analysis.injectable_params
                )
            )
        if analysis.technologies:
            context.append(f"Technologies: {', '.join(analysis.technologies)}")
        if command_summary:
            context += ["", "Cleaned Command Outputs:", command_summary]

        user = (
            f"Target URL: {analysis.url}\n\n"
            + "\n".join(context)
            + "\n\nPerform deep vulnerability and exploit research for every item and Nmap "
            "service version. Return the research_tuples and prioritized attack order."
        )
        try:
            report = loads(complete(self.model, self.system, user))
        except (ValueError, KeyError) as exc:
            warn(f"Researcher parse error for {analysis.url}: {exc}")
            return {**_EMPTY_REPORT, "summary": f"Exploit research failed: {exc}"}

        tuples = report.get("research_tuples") or report.get("vectors") or []
        report["research_tuples"] = tuples
        report["vectors"] = tuples
        return report
