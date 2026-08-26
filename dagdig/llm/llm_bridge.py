#!/usr/bin/env python3
"""
Dual-Groq AI Analysis Engine for DAGDIG:
Model 1 (HTML Cleaner AI) -> Model 2 (Reconnaissance Intelligence AI)
"""
import json
import re
from core.schema import PageAnalysis
from .client import GroqClient

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

INTELLIGENCE_SYSTEM_PROMPT = (
    "You are a senior web penetration testing intelligence AI.\n"
    "Analyze the provided cleaned web page contents from multiple URLs of the same target and extract key intelligence.\n"
    "You MUST respond ONLY with a valid JSON object matching the following structure:\n"
    "{\n"
    '  "overall_summary": "1-2 sentence overall summary of the target attack surface",\n'
    '  "pages": [\n'
    '    {\n'
    '      "url": "http://...",\n'
    '      "technologies": ["TechName Version", ...],\n'
    '      "auth_requirement": "Public" | "Registration Page" | "Auth Required (Login)" | "Admin Protected",\n'
    '      "downloadable_files": ["/file/path.ext", ...],\n'
    '      "summary": "1-2 sentence overview of the page purpose"\n'
    '    }\n'
    '  ]\n'
    "}\n"
    "Do NOT include markdown formatting backticks like ```json in your response. Output pure JSON."
)


class DualGroqAnalyzer:
    def __init__(self, cleaner_client: GroqClient = None, analyzer_client: GroqClient = None):
        import os

        # Model 1 (HTML Cleaner) — uses GROQ_API_KEY + GROQ_MODEL
        self.cleaner_client = cleaner_client or GroqClient(
            api_key=os.environ.get('GROQ_API_KEY'),
            model=os.environ.get('GROQ_MODEL', 'qwen/qwen3.8-27b')
        )

        # Model 2 (Intelligence Report) — uses GROQ_API_KEY_2 + GROQ_MODEL_2
        api_key_2 = os.environ.get('GROQ_API_KEY_2') or os.environ.get('GROQ_API_KEY')
        model_2 = os.environ.get('GROQ_MODEL_2', os.environ.get('GROQ_MODEL', 'qwen/qwen3.8-27b'))
        self.analyzer_client = analyzer_client or GroqClient(
            api_key=api_key_2,
            model=model_2
        )


    def clean_page(self, raw_html: str) -> str:
        """Model 1: Clean raw cURL/HTML response"""
        if not raw_html or not raw_html.strip():
            return "Empty response"

        # Truncate raw HTML if excessively long (to stay well within model context window)
        truncated_raw = raw_html[:15000]

        prompt = f"Clean and structure the following raw HTML content:\n\n{truncated_raw}"
        cleaned = self.cleaner_client.chat_completion(CLEANER_SYSTEM_PROMPT, prompt, temperature=0.1)
        return cleaned

    def analyze_multiple_pages(self, cleaned_pages: dict) -> list[PageAnalysis]:
        """Model 2: Extract security intelligence from multiple cleaned pages at once (chunked to avoid 413 errors)"""
        results = []
        
        # Convert dict to list of items to chunk them
        items = list(cleaned_pages.items())
        chunk_size = 3  # Send max 3 pages at a time to stay under 8000 TPM limit per request
        
        for i in range(0, len(items), chunk_size):
            chunk = dict(items[i:i + chunk_size])
            prompt = "Target URLs and Cleaned Content:\n\n"
            for url, content in chunk.items():
                # Further truncate each page to ensure we definitely stay under limits
                prompt += f"--- URL: {url} ---\n{content[:4000]}\n\n"

            try:
                response_text = self.analyzer_client.chat_completion(INTELLIGENCE_SYSTEM_PROMPT, prompt, temperature=0.1)
                
                # Strip potential code block fences if present
                cleaned_json_str = re.sub(r'^```(?:json)?\s*', '', response_text.strip())
                cleaned_json_str = re.sub(r'\s*```$', '', cleaned_json_str)

                data = json.loads(cleaned_json_str)
                
                for page_data in data.get('pages', []):
                    url = page_data.get('url', '')
                    if url:
                        results.append(PageAnalysis(
                            url=url,
                            auth_requirement=page_data.get('auth_requirement', 'Public'),
                            downloadable_files=page_data.get('downloadable_files', []),
                            technologies=page_data.get('technologies', []),
                            summary=page_data.get('summary', '')
                        ))
            except Exception as e:
                print(f"[!] Analysis parsing error on chunk: {e}")
                
        return results

    def process_url(self, url: str, raw_html: str) -> PageAnalysis:
        """Run the full Dual-Groq pipeline: Model 1 -> Model 2"""
        cleaned = self.clean_page(raw_html)
        analysis = self.analyze_page(url, cleaned)
        return analysis
