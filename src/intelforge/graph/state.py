"""Typed state threaded through the LangGraph pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from intelforge.domain.models import PageAnalysis
from intelforge.domain.state import TargetState


@dataclass(slots=True)
class ScanOptions:
    """Toggles that select which parts of the pipeline run."""

    skip_nmap: bool = False
    skip_web: bool = False
    skip_osint: bool = False
    skip_llm: bool = False
    skip_recon: bool = False
    direct_urls: list[str] = field(default_factory=list)


class GraphState(TypedDict, total=False):
    """The single object every node reads from and writes to.

    ``target`` holds the shared :class:`TargetState` accumulator; nodes
    mutate ``target.data`` and persist it. The remaining keys carry
    intermediate results between nodes.
    """

    target: TargetState
    options: ScanOptions
    raw_pages: dict[str, str]
    cleaned_pages: dict[str, str]
    analyses: list[PageAnalysis]
    report_path: str | None
