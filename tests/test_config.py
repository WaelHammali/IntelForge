from __future__ import annotations

import pytest

from intelforge.config import Settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("GROQ_MODEL", "GROQ_MODEL_2", "GROQ_MODEL_3"):
        monkeypatch.delenv(var, raising=False)
    for var in ("INTELFORGE_LLM_CLEANER", "INTELFORGE_LLM_ANALYST", "INTELFORGE_LLM_RESEARCHER"):
        monkeypatch.delenv(var, raising=False)


def test_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.llm_analyst.startswith("groq:")
    assert set(s.nmap_profiles) == {"tcp_full", "udp_top", "tcp_light", "udp_light"}


def test_legacy_groq_model_is_mapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_MODEL_3", "deepseek-custom")
    s = Settings(_env_file=None)
    assert s.llm_researcher == "groq:deepseek-custom"


def test_legacy_ignored_when_modern_var_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_MODEL_3", "deepseek-custom")
    monkeypatch.setenv("INTELFORGE_LLM_RESEARCHER", "openai:gpt-4o-mini")
    s = Settings(_env_file=None)
    assert s.llm_researcher == "openai:gpt-4o-mini"


def test_role_model_lookup() -> None:
    s = Settings(_env_file=None, llm_analyst="groq:x")
    assert s.role_model("analyst") == "groq:x"


def test_researcher_runs_hotter_than_the_cleaners() -> None:
    s = Settings(_env_file=None)
    assert s.role_temperature("researcher") > s.role_temperature("cleaner")
    assert s.role_temperature("analyst") == s.llm_temperature
