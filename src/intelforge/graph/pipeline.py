"""Assemble the recon → clean → analyse → research → report pipeline."""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import RetryPolicy

from intelforge.graph import nodes
from intelforge.graph.state import GraphState, ScanOptions

_LLM_RETRY = RetryPolicy(max_attempts=3, initial_interval=2.0, backoff_factor=2.0)


def _after_commands(gstate: GraphState) -> str:
    return "report" if gstate["options"].skip_llm else "fetch_pages"


def build_graph() -> CompiledStateGraph:
    graph = StateGraph(GraphState)

    graph.add_node("recon", nodes.recon)
    graph.add_node("clean_commands", nodes.clean_commands, retry_policy=_LLM_RETRY)
    graph.add_node("fetch_pages", nodes.fetch_pages)
    graph.add_node("clean_html", nodes.clean_html, retry_policy=_LLM_RETRY)
    graph.add_node("analyst", nodes.analyst, retry_policy=_LLM_RETRY)
    graph.add_node("research", nodes.research, retry_policy=_LLM_RETRY)
    graph.add_node("report", nodes.report)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "clean_commands")
    graph.add_conditional_edges(
        "clean_commands", _after_commands, {"fetch_pages": "fetch_pages", "report": "report"}
    )
    graph.add_edge("fetch_pages", "clean_html")
    graph.add_edge("clean_html", "analyst")
    graph.add_edge("analyst", "research")
    graph.add_edge("research", "report")
    graph.add_edge("report", END)

    return graph.compile()


@lru_cache(maxsize=1)
def get_graph() -> CompiledStateGraph:
    return build_graph()


def run(target_state: object, options: ScanOptions) -> GraphState:
    """Execute the full pipeline against a prepared :class:`TargetState`."""
    return get_graph().invoke({"target": target_state, "options": options})  # type: ignore[return-value]


def mermaid() -> str:
    return get_graph().get_graph().draw_mermaid()
