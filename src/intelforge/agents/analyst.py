"""Stage 2 (attack-surface extraction) and Stage 4 (final synthesis)."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.language_models import BaseChatModel

from intelforge.agents._json import loads
from intelforge.agents.llm import complete
from intelforge.agents.prompts import load_prompt
from intelforge.console.theme import warn
from intelforge.domain.models import PageAnalysis

_CHUNK_SIZE = 3
_PER_PAGE_CHARS = 4_000


def _page_from_dict(payload: dict[str, Any], fallback_url: str = "") -> PageAnalysis:
    suspicious = payload.get("suspicious_items") or list(payload.get("keyword_fingerprints") or [])
    return PageAnalysis(
        url=payload.get("url") or fallback_url,
        auth_requirement=payload.get("auth_requirement", "Public"),
        downloadable_files=payload.get("downloadable_files", []),
        technologies=payload.get("technologies", []),
        summary=payload.get("summary", ""),
        bypass_paths=payload.get("bypass_paths", []),
        auth_pages=payload.get("auth_pages", []),
        upload_points=payload.get("upload_points", []),
        download_points=payload.get("download_points", []),
        injectable_params=payload.get("injectable_params", []),
        keyword_fingerprints=payload.get("keyword_fingerprints", []),
        suspicious_items=suspicious,
        llm_recon_paragraph=payload.get("llm_recon_paragraph", ""),
    )


class Analyst:
    def __init__(self, model: BaseChatModel) -> None:
        self.model = model
        self.surface_prompt = load_prompt("web_parse")
        self.synthesis_prompt = load_prompt("analyst_synthesis")

    # ── Stage 2 ────────────────────────────────────────────────────────────
    def extract_surface(self, cleaned_pages: dict[str, str]) -> list[PageAnalysis]:
        items = list(cleaned_pages.items())
        results: list[PageAnalysis] = []
        for start in range(0, len(items), _CHUNK_SIZE):
            chunk = items[start : start + _CHUNK_SIZE]
            user = "Target URLs and cleaned content:\n\n" + "".join(
                f"--- URL: {url} ---\n{content[:_PER_PAGE_CHARS]}\n\n" for url, content in chunk
            )
            try:
                data = loads(complete(self.model, self.surface_prompt, user))
            except (ValueError, KeyError) as exc:
                warn(f"Analyst chunk parse error: {exc}")
                continue
            for page in data.get("pages", []):
                if page.get("url"):
                    results.append(_page_from_dict(page))
        return results

    # ── Stage 4 ────────────────────────────────────────────────────────────
    def synthesize(
        self,
        analysis: PageAnalysis,
        exploit_report: dict[str, Any],
        command_summary: str = "",
    ) -> PageAnalysis:
        tuples = exploit_report.get("research_tuples", [])
        analysis.research_tuples = tuples
        analysis.exploit_report = exploit_report

        if not tuples and not exploit_report.get("summary") and not command_summary:
            return analysis

        payload = {
            "target_url": analysis.url,
            "auth_requirement": analysis.auth_requirement,
            "technologies": analysis.technologies,
            "bypass_paths": analysis.bypass_paths,
            "upload_points": analysis.upload_points,
            "injectable_params": analysis.injectable_params,
            "research_tuples_from_researcher": tuples,
            "researcher_attack_order": exploit_report.get("recommended_attack_order", []),
            "researcher_summary": exploit_report.get("summary", ""),
            "cleaned_command_outputs": command_summary,
        }
        user = (
            "Target reconnaissance & research findings:\n"
            f"{json.dumps(payload, indent=2)}\n\nProduce the final synthesized report."
        )
        try:
            synth = loads(complete(self.model, self.synthesis_prompt, user))
        except (ValueError, KeyError):
            return analysis

        if synth.get("summary"):
            analysis.summary = synth["summary"]
        if synth.get("synthesized_attack_surface"):
            analysis.llm_recon_paragraph = synth["synthesized_attack_surface"]
        if synth.get("priority_exploit_vectors"):
            analysis.exploit_report["priority_exploit_vectors"] = synth["priority_exploit_vectors"]
        if synth.get("final_verdict"):
            analysis.exploit_report["final_verdict"] = synth["final_verdict"]
        if synth.get("open_services"):
            analysis.exploit_report["open_services"] = synth["open_services"]
        if synth.get("access_map"):
            access_map = synth["access_map"] or {}
            analysis.exploit_report["access_map"] = access_map
            for path in access_map.get("register_required", []):
                if path and path not in analysis.auth_pages:
                    analysis.auth_pages.append(path)
            for path in access_map.get("bypass_candidates", []):
                if path and path not in analysis.bypass_paths:
                    analysis.bypass_paths.append(path)
        return analysis
