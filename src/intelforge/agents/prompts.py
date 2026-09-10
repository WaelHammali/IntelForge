"""Load system-prompt templates shipped as package data."""

from __future__ import annotations

from functools import cache
from importlib.resources import files


@cache
def load_prompt(name: str) -> str:
    """Return the text of ``src/intelforge/prompts/<name>.txt``."""
    resource = files("intelforge.prompts") / f"{name}.txt"
    return resource.read_text(encoding="utf-8").strip()
