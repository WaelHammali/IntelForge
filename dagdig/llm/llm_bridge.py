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

# Stage 2, Stage 3, and Synthesis prompts are loaded from files at runtime
_WEB_PARSE_PROMPT: str = ""
_EXPLOIT_RESEARCH_PROMPT: str = ""
_ANALYST_SYNTHESIS_PROMPT: str = ""


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


def _get_analyst_synthesis_prompt() -> str:
    global _ANALYST_SYNTHESIS_PROMPT
    if not _ANALYST_SYNTHESIS_PROMPT:
        _ANALYST_SYNTHESIS_PROMPT = _load_prompt("analyst_synthesis.txt")
    return _ANALYST_SYNTHESIS_PROMPT


def _strip_json_fences(text: str) -> str:
    """Remove potential markdown ```json ... ``` and DeepSeek <think>...</think> wrappers from LLM output."""
    text = text.strip()
    # Strip DeepSeek R1 reasoning chain <think>...</think> blocks
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE).strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    match = re.search(r'(\{[\s\S]*\}|\[[\s\S]*\])', text)
    if match:
        return match.group(0).strip()
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

        # Stage 3: uses GROQ_API_KEY_3 / GROQ_MODEL_3 (defaults to deepseek-r1-distill-llama-70b)
        api_key_3 = (
            os.environ.get('GROQ_API_KEY_3')
            or os.environ.get('GROQ_API_KEY_2')
            or os.environ.get('GROQ_API_KEY')
        )
        model_3 = os.environ.get(
            'GROQ_MODEL_3',
            'deepseek-r1-distill-llama-70b'
        )
        self.researcher_client = researcher_client or GroqClient(
            api_key=api_key_3,
            model=model_3
        )

    # ── Stage 2: Initial Attack Surface & Suspicious Items Extraction ─────────

    def analyze_page_deep(self, url: str, cleaned_content: str) -> PageAnalysis:
        """
        Stage 2 (Part 1) — Run attack-surface intelligence extraction and extract
        suspicious items/keywords that raise doubt for penetration testing.
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
                pages = [data]

            if pages:
                p = pages[0]
                suspicious = p.get('suspicious_items', [])
                if not suspicious and p.get('keyword_fingerprints'):
                    suspicious = list(p.get('keyword_fingerprints'))

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
                    suspicious_items=suspicious,
                    llm_recon_paragraph=p.get('llm_recon_paragraph', ''),
                )
        except Exception as e:
            print(f"[!] Stage 2 parse error for {url}: {e}")

        return PageAnalysis(url=url, summary="Stage 2 analysis failed.")

    # ── Stage 3: Exploit Research & Tuple Generation (DeepSeek R1) ────────────

    def research_exploits(self, analysis: PageAnalysis, nmap_summary: str = "") -> dict:
        """
        Stage 3 — Given a PageAnalysis with suspicious items, keywords, recon data, and Nmap service findings,
        query DeepSeek R1 to research vulnerabilities, CVEs, and pentest relevance.
        Returns a dictionary containing `research_tuples`, `recommended_attack_order`, etc.
        """
        items_to_research = list(dict.fromkeys(analysis.suspicious_items + analysis.keyword_fingerprints))
        if not items_to_research and not analysis.llm_recon_paragraph and not nmap_summary:
            return {"summary": "No recon items available for research.", "research_tuples": [], "vectors": []}

        research_prompt = _get_exploit_research_prompt()

        # Format context specifically emphasizing suspicious items to research
        context_parts = []
        if nmap_summary:
            context_parts.append("Nmap Discovered Ports & Service Versions:")
            context_parts.append(nmap_summary)
            context_parts.append("")

        if items_to_research:
            context_parts.append("Suspicious Items / Keywords to Investigate:")
            for item in items_to_research:
                context_parts.append(f"- {item}")
            context_parts.append("")

        if analysis.llm_recon_paragraph:
            context_parts.append(f"Analyst Recon Brief:\n{analysis.llm_recon_paragraph}")
            context_parts.append("")

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
            f"{full_context}\n\n"
            "Perform deep vulnerability and exploit research for every item and Nmap service version. "
            "Return the research_tuples and prioritized attack order."
        )

        try:
            response_text = self.researcher_client.chat_completion(
                research_prompt, prompt, temperature=0.2
            )
            report = json.loads(_strip_json_fences(response_text))
            
            # Normalize tuples / vectors for compatibility
            tuples = report.get('research_tuples') or report.get('vectors') or []
            report['research_tuples'] = tuples
            report['vectors'] = tuples
            return report
        except Exception as e:
            print(f"[!] Stage 3 parse error for {analysis.url}: {e}")
            return {
                "summary": f"Exploit research failed: {e}",
                "risk_level": "Unknown",
                "research_tuples": [],
                "vectors": [],
                "recommended_attack_order": [],
                "notes": "Stage 3 DeepSeek response could not be parsed as JSON."
            }

    # ── Stage 4: Analyst Final Report Synthesis ───────────────────────────────

    def synthesize_final_report(self, analysis: PageAnalysis, exploit_report: dict) -> PageAnalysis:
        """
        Stage 4 — The Analyst ingests the Researcher's list of tuples and findings
        to synthesize the final, comprehensive security assessment.
        """
        tuples = exploit_report.get('research_tuples', [])
        analysis.research_tuples = tuples
        analysis.exploit_report = exploit_report

        if not tuples and not exploit_report.get('summary'):
            return analysis

        synthesis_prompt = _get_analyst_synthesis_prompt()
        
        # Build synthesis prompt payload
        prompt_data = {
            "target_url": analysis.url,
            "auth_requirement": analysis.auth_requirement,
            "technologies": analysis.technologies,
            "bypass_paths": analysis.bypass_paths,
            "upload_points": analysis.upload_points,
            "injectable_params": analysis.injectable_params,
            "research_tuples_from_researcher": tuples,
            "researcher_attack_order": exploit_report.get('recommended_attack_order', []),
            "researcher_summary": exploit_report.get('summary', '')
        }

        try:
            prompt_str = f"Target Reconnaissance & Research Findings:\n{json.dumps(prompt_data, indent=2)}\n\nProduce the final synthesized report."
            response_text = self.analyzer_client.chat_completion(
                synthesis_prompt, prompt_str, temperature=0.1
            )
            synth_data = json.loads(_strip_json_fences(response_text))

            if synth_data.get('summary'):
                analysis.summary = synth_data['summary']
            if synth_data.get('synthesized_attack_surface'):
                analysis.llm_recon_paragraph = synth_data['synthesized_attack_surface']
            if synth_data.get('priority_exploit_vectors'):
                analysis.exploit_report['priority_exploit_vectors'] = synth_data['priority_exploit_vectors']
            if synth_data.get('final_verdict'):
                analysis.exploit_report['final_verdict'] = synth_data['final_verdict']

        except Exception as e:
            # Fall back gracefully to the existing summary if synthesis fails
            pass

        return analysis

    # ── Full Pipeline Execution ───────────────────────────────────────────────

    def run_full_pipeline(self, url: str, raw_html: str) -> PageAnalysis:
        """
        Execute the full 4-step collaborative recon cycle:
          1. Clean HTML (Cleaner AI)
          2. Extract attack surface & suspicious items (Analyst AI)
          3. Research vulnerabilities, CVEs, pentest relevance & generate tuples (DeepSeek Researcher AI)
          4. Synthesize research tuples into final complete report (Analyst AI)
        Returns a fully enriched PageAnalysis.
        """
        print(f"  [1/4] Cleaning HTML for {url}...")
        cleaned = self.clean_page(raw_html)

        print(f"  [2/4] Extracting attack surface & suspicious items (Analyst)...")
        analysis = self.analyze_page_deep(url, cleaned)

        item_count = len(analysis.suspicious_items) or len(analysis.keyword_fingerprints)
        print(f"  [3/4] Deep research on {item_count} item(s) (DeepSeek Researcher)...")
        exploit_report = self.research_exploits(analysis)

        print(f"  [4/4] Synthesizing final report with research tuples (Analyst)...")
        analysis = self.synthesize_final_report(analysis, exploit_report)

        return analysis
