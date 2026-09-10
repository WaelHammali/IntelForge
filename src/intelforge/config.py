"""Runtime configuration.

All values come from environment variables (prefix ``INTELFORGE_``) or a
local ``.env`` file. Import :data:`settings` for the process-wide instance.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_NMAP_PROFILES: dict[str, str] = {
    "tcp_full": "-sS -sV -sC -p- --min-rate 1000 -T4",
    "udp_top": "-sU -sV --top-ports 200 --min-rate 500 -T4",
    "tcp_light": "-sS --top-ports 1000 --min-rate 5000 -T5",
    "udp_light": "-sU --top-ports 100 --min-rate 2000 -T5",
}

# Legacy GROQ_MODEL* -> role mapping, applied only when the modern setting is untouched.
_LEGACY_MODEL_ENV = {
    "llm_cleaner": "GROQ_MODEL",
    "llm_analyst": "GROQ_MODEL_2",
    "llm_researcher": "GROQ_MODEL_3",
}
_DEFAULT_MODELS = {
    "llm_cleaner": "groq:llama-3.1-8b-instant",
    "llm_analyst": "groq:llama-3.3-70b-versatile",
    "llm_researcher": "groq:deepseek-r1-distill-llama-70b",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INTELFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM roles (LangChain "provider:model" strings) ──────────────────────
    llm_cleaner: str = _DEFAULT_MODELS["llm_cleaner"]
    llm_analyst: str = _DEFAULT_MODELS["llm_analyst"]
    llm_researcher: str = _DEFAULT_MODELS["llm_researcher"]
    llm_base_url: str | None = None
    llm_temperature: float = 0.1

    # ── Tools ──────────────────────────────────────────────────────────────
    finalrecon_path: Path = Path("/home/themangahacker/FinalRecon/finalrecon.py")
    request_timeout: int = 10
    fuzz_threads: int = 20
    scan_timeout: int = 600
    nmap_profiles: dict[str, str] = Field(default_factory=lambda: dict(_DEFAULT_NMAP_PROFILES))

    # ── Paths ──────────────────────────────────────────────────────────────
    data_dir: Path = Path("data")
    wordlist_dir: Path = Path("wordlists")

    @model_validator(mode="after")
    def _apply_legacy_groq_env(self) -> Settings:
        """Map GROQ_MODEL / _2 / _3 onto unset roles (prefixing ``groq:``)."""
        for field, env_name in _LEGACY_MODEL_ENV.items():
            legacy = os.environ.get(env_name)
            if legacy and getattr(self, field) == _DEFAULT_MODELS[field]:
                value = legacy if ":" in legacy else f"groq:{legacy}"
                object.__setattr__(self, field, value)
        return self

    def role_model(self, role: str) -> str:
        return {
            "cleaner": self.llm_cleaner,
            "analyst": self.llm_analyst,
            "researcher": self.llm_researcher,
        }[role]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
