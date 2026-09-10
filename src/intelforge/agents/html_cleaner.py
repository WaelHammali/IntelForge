"""Stage 1 — condense raw HTML into structured, security-relevant text."""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel

from intelforge.agents.llm import complete
from intelforge.agents.prompts import load_prompt

_MAX_HTML_CHARS = 15_000


class HtmlCleaner:
    def __init__(self, model: BaseChatModel) -> None:
        self.model = model
        self.system = load_prompt("html_clean")

    def clean(self, raw_html: str) -> str:
        if not raw_html or not raw_html.strip():
            return "Empty response"
        user = (
            f"Clean and structure the following raw HTML content:\n\n{raw_html[:_MAX_HTML_CHARS]}"
        )
        return complete(self.model, self.system, user).strip()
