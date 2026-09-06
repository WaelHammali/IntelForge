#!/usr/bin/env python3
"""
Triple-Groq AI Analysis Engine for DAGDIG:
  Model 1 (HTML Cleaner AI)          -> strips noise from raw HTML
  Model 2 (Recon Intelligence AI)    -> extracts full attack-surface signals
  Model 3 (Exploit Research AI)      -> researches CVEs and exploitation techniques
"""
import json
import re
from pathlib import Path
from core.schema import PageAnalysis
from .client import GroqClient

# ── Load system prompts from files ────────────────────────────────────────────

def _load_prompt(filename: str) -> str:
    """Load a system prompt from the prompts/ directory."""
    here = Path(__file__).resolve().parent.parent / "prompts" / filename
    if here.exists():
        return here.read_text(encoding="utf-8").strip()
    raise FileNotFoundError(f"Prompt file not found: {here}")


CLEANER_SYSTEM_PROMPT = (
    "You are an expert HTML cleaner and web scraper pre-processor for security analysis.\n"
    "Your job is to take raw HTML / cURL output from a target URL and strip away heavy CSS styles, "
    "javascript code blocks, base64 images, SVGs, and advertising noise.\n"
    "Output a clean, condensed, structured text representation of the web page containing:\n"
    "- Page title and Meta tags\n"
    "- Visible headings and main text\n"
    "- Form elements (action URLs, input names, input types, buttons)\n"
    "- Links, script src tags, and technical footprint hints (headers, comments, footer software names)."
)

# Stage 2 and Stage 3 prompts are loaded from files at runtime
_WEB_PARSE_PROMPT: str = ""
_EXPLOIT_RESEARCH_PROMPT: str = ""


def _get_web_parse_prompt() -> str:
    global _WEB_PARSE_PROMPT
    if not _WEB_PARSE_PROMPT:
        _WEB_PARSE_PROMPT = _load_prompt("web_parse.txt")
    return _WEB_PARSE_PROMPT


def _get_exploit_research_prompt() -> str:
    global _EXPLOIT_RESEARCH_PROMPT
    if not _EXPLOIT_RESEARCH_PROMPT:
        _EXPLOIT_RESEARCH_PROMPT = _load_prompt("exploit_research.txt")
    return _EXPLOIT_RESEARCH_PROMPT


def _strip_json_fences(text: str) -> str:
    """Remove potential markdown ```json ... ``` wrappers from LLM output."""
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    return text.strip()


# ── DualGroqAnalyzer (legacy / basic, kept for backward compat) ───────────────

class DualGroqAnalyzer:
    """Original two-model pipeline (HTML cleaner + basic intelligence).
    Kept for backward compatibility with the existing `analyze` command."""

    def __init__(self, cleaner_client: GroqClient = None, analyzer_client: GroqClient = None):
        import os

        self.cleaner_client = cleaner_client or GroqClient(
            api_key=os.environ.get('GROQ_API_KEY'),
            model=os.environ.get('GROQ_MODEL', 'qwen/qwen3-8b')
        )

        api_key_2 = os.environ.get('GROQ_API_KEY_2') or os.environ.get('GROQ_API_KEY')
        model_2 = os.environ.get('GROQ_MODEL_2', os.environ.get('GROQ_MODEL', 'qwen/qwen3-8b'))
        self.analyzer_client = analyzer_client or GroqClient(
            api_key=api_key_2,
            model=model_2
        )

    def clean_page(self, raw_html: str) -> str:
        """Model 1: Clean raw cURL/HTML response."""
        if not raw_html or not raw_html.strip():
            return "Empty response"
        truncated_raw = raw_html[:15000]
        prompt = f"Clean and structure the following raw HTML content:\n\n{truncated_raw}"
        return self.cleaner_client.chat_completion(CLEANER_SYSTEM_PROMPT, prompt, temperature=0.1)

    def analyze_multiple_pages(self, cleaned_pages: dict) -> list:
        """Model 2 (basic): Extract security intelligence from multiple cleaned pages (chunked)."""
        # Use the full web_parse prompt for consistency
        intelligence_prompt = _get_web_parse_prompt()
        results = []
        items = list(cleaned_pages.items())
        chunk_size = 3

        for i in range(0, len(items), chunk_size):
            chunk = dict(items[i:i + chunk_size])
            prompt = "Target URLs and Cleaned Content:\n\n"
            for url, content in chunk.items():
                prompt += f"--- URL: {url} ---\n{content[:4000]}\n\n"

            try:
                response_text = self.analyzer_client.chat_completion(intelligence_prompt, prompt, temperature=0.1)
                data = json.loads(_strip_json_fences(response_text))

                for page_data in data.get('pages', []):
                    url = page_data.get('url', '')
                    if url:
                        results.append(PageAnalysis(
                            url=url,
                            auth_requirement=page_data.get('auth_requirement', 'Public'),
                            downloadable_files=page_data.get('downloadable_files', []),
                            technologies=page_data.get('technologies', []),
                            summary=page_data.get('summary', ''),
                            bypass_paths=page_data.get('bypass_paths', []),
                            auth_pages=page_data.get('auth_pages', []),
                            upload_points=page_data.get('upload_points', []),
                            download_points=page_data.get('download_points', []),
                            injectable_params=page_data.get('injectable_params', []),
                            keyword_fingerprints=page_data.get('keyword_fingerprints', []),
                            llm_recon_paragraph=page_data.get('llm_recon_paragraph', ''),
                        ))
            except Exception as e:
                print(f"[!] Analysis parsing error on chunk: {e}")

        return results

    def process_url(self, url: str, raw_html: str) -> PageAnalysis:
        """Run the full Dual-Groq pipeline: Model 1 -> Model 2"""
        cleaned = self.clean_page(raw_html)
        analyses = self.analyze_multiple_pages({url: cleaned})
        if analyses:
            return analyses[0]
        return PageAnalysis(url=url, summary="Analysis failed or returned no data.")


# ── TripleGroqAnalyzer (full 3-stage CTF pipeline) ────────────────────────────

class TripleGroqAnalyzer(DualGroqAnalyzer):
    """
    Full 3-stage web recon pipeline for CTF/HackTheBox machines:
      Stage 1 — HTML Cleaner    : strip noise, produce structured text
      Stage 2 — Recon Intel     : extract attack surface (bypass, uploads, params, keywords)
      Stage 3 — Exploit Research: research CVEs, methods, tools per keyword/finding
    """

    def __init__(
        self,
        cleaner_client: GroqClient = None,
        analyzer_client: GroqClient = None,
        researcher_client: GroqClient = None,
    ):
        import os
        super().__init__(cleaner_client, analyzer_client)

        # Stage 3: uses GROQ_API_KEY_3 / GROQ_MODEL_3 (falls back to key 2)
        api_key_3 = (
            os.environ.get('GROQ_API_KEY_3')
            or os.environ.get('GROQ_API_KEY_2')
            or os.environ.get('GROQ_API_KEY')
        )
        model_3 = os.environ.get(
            'GROQ_MODEL_3',
            os.environ.get('GROQ_MODEL_2', os.environ.get('GROQ_MODEL', 'qwen/qwen3-8b'))
        )
        self.researcher_client = researcher_client or GroqClient(
            api_key=api_key_3,
            model=model_3
        )

    # ── Stage 2: Full intelligence extraction ─────────────────────────────────

    def analyze_page_deep(self, url: str, cleaned_content: str) -> PageAnalysis:
        """
        Stage 2 — Run full attack-surface intelligence extraction on a single cleaned page.
        Returns a PageAnalysis with all new fields populated.
        """
        intelligence_prompt = _get_web_parse_prompt()
        prompt = f"--- URL: {url} ---\n{cleaned_content[:6000]}\n"

        try:
            response_text = self.analyzer_client.chat_completion(
                intelligence_prompt, prompt, temperature=0.1
            )
            data = json.loads(_strip_json_fences(response_text))

            # The model may return a top-level object or a pages array
            pages = data.get('pages', [])
            if not pages and 'url' in data:
                # Model returned a single page object directly
                pages = [data]

            if pages:
                p = pages[0]
                return PageAnalysis(
                    url=p.get('url', url),
                    auth_requirement=p.get('auth_requirement', 'Public'),
                    technologies=p.get('technologies', []),
                    summary=p.get('summary', ''),
                    downloadable_files=p.get('downloadable_files', []),
                    bypass_paths=p.get('bypass_paths', []),
                    auth_pages=p.get('auth_pages', []),
                    upload_points=p.get('upload_points', []),
                    download_points=p.get('download_points', []),
                    injectable_params=p.get('injectable_params', []),
                    keyword_fingerprints=p.get('keyword_fingerprints', []),
                    llm_recon_paragraph=p.get('llm_recon_paragraph', ''),
                )
        except Exception as e:
            print(f"[!] Stage 2 parse error for {url}: {e}")

        return PageAnalysis(url=url, summary="Stage 2 analysis failed.")

    # ── Stage 3: Exploit research ─────────────────────────────────────────────

    def research_exploits(self, analysis: PageAnalysis) -> dict:
        """
        Stage 3 — Given a PageAnalysis with a recon paragraph and keyword fingerprints,
        query the research model to produce a structured CVE/technique/exploit report.
        Returns the exploit_report dict.
        """
        if not analysis.llm_recon_paragraph and not analysis.keyword_fingerprints:
            return {"summary": "No recon data available for research.", "vectors": []}

        research_prompt = _get_exploit_research_prompt()

        # Build a rich context paragraph for Stage 3
        context_parts = []
        if analysis.llm_recon_paragraph:
            context_parts.append(analysis.llm_recon_paragraph)
        if analysis.keyword_fingerprints:
            context_parts.append(
                f"Key fingerprints identified: {', '.join(analysis.keyword_fingerprints)}"
            )
        if analysis.upload_points:
            upload_desc = "; ".join(
                f"{u.get('path','')} [{u.get('method','')}]" for u in analysis.upload_points
            )
            context_parts.append(f"Upload endpoints: {upload_desc}")
        if analysis.injectable_params:
            param_desc = "; ".join(
                f"{p.get('param','')} in {p.get('location','')} ({p.get('risk','')})"
                for p in analysis.injectable_params
            )
            context_parts.append(f"Injectable parameters: {param_desc}")
        if analysis.technologies:
            context_parts.append(f"Technologies: {', '.join(analysis.technologies)}")

        full_context = "\n".join(context_parts)
        prompt = (
            f"Target URL: {analysis.url}\n\n"
            f"Reconnaissance Summary:\n{full_context}\n\n"
            "Produce the full exploit research report for this target."
        )

        try:
            response_text = self.researcher_client.chat_completion(
                research_prompt, prompt, temperature=0.2
            )
            report = json.loads(_strip_json_fences(response_text))
            return report
        except Exception as e:
            print(f"[!] Stage 3 parse error for {analysis.url}: {e}")
            return {
                "summary": f"Exploit research failed: {e}",
                "risk_level": "Unknown",
                "vectors": [],
                "recommended_attack_order": [],
                "notes": "Stage 3 LLM response could not be parsed as JSON."
            }

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run_full_pipeline(self, url: str, raw_html: str) -> PageAnalysis:
        """
        Execute the full 3-stage pipeline for a single URL:
          1. Clean HTML (Model 1)
          2. Extract attack surface intelligence (Model 2)
          3. Research exploits per keyword/finding (Model 3)
        Returns a fully populated PageAnalysis.
        """
        print(f"  [1/3] Cleaning HTML for {url}...")
        cleaned = self.clean_page(raw_html)

        print(f"  [2/3] Extracting attack surface intelligence...")
        analysis = self.analyze_page_deep(url, cleaned)

        print(f"  [3/3] Researching exploits for {len(analysis.keyword_fingerprints)} fingerprint(s)...")
        exploit_report = self.research_exploits(analysis)
        analysis.exploit_report = exploit_report

        return analysis
