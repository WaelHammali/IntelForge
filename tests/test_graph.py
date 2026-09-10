from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from intelforge.domain.models import Port
from intelforge.domain.state import TargetState
from intelforge.graph import build_graph, mermaid
from intelforge.graph import nodes as graph_nodes
from intelforge.graph.state import ScanOptions


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, FakeListChatModel]:
    models = {
        "cleaner": FakeListChatModel(responses=['{"clean_output": "22/tcp open ssh"}']),
        "analyst": FakeListChatModel(
            responses=[
                '{"pages": [{"url": "http://10.10.10.5/", "technologies": ["nginx"],'
                ' "suspicious_items": ["nginx 1.18"], "summary": "home"}]}',
                '{"summary": "final", "access_map": {"bypass_candidates": ["/admin"]}}',
            ]
        ),
        "researcher": FakeListChatModel(
            responses=['{"risk_level": "High", "research_tuples": [{"keyword": "nginx 1.18"}]}']
        ),
    }
    monkeypatch.setattr(graph_nodes, "_maybe_model", lambda role: models[role])
    return models


def test_graph_compiles_and_renders() -> None:
    build_graph()
    assert "recon --> clean_commands" in mermaid()


def test_page_urls_do_not_double_scheme(tmp_path: Path) -> None:
    state = TargetState(data_dir=tmp_path / "data")
    state.set_target("http://10.10.10.5")
    state.data.directories = ["admin", "/uploads"]
    state.data.subdomains = ["dev.box.htb"]

    urls = graph_nodes._page_urls({"target": state, "options": ScanOptions()})

    assert "http://10.10.10.5" in urls
    assert "http://10.10.10.5/admin" in urls
    assert "http://10.10.10.5/uploads" in urls
    assert "http://dev.box.htb" in urls
    assert all(u.count("://") == 1 for u in urls)


def test_skip_recon_and_llm_reaches_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    state = TargetState(data_dir=tmp_path / "data")
    state.set_target("10.10.10.5")

    result = build_graph().invoke(
        {"target": state, "options": ScanOptions(skip_recon=True, skip_llm=True)}
    )

    assert result["report_path"].endswith(".json")
    assert Path(result["report_path"]).exists()


def test_full_pipeline_with_fakes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fakes: dict[str, Any]
) -> None:
    monkeypatch.chdir(tmp_path)
    state = TargetState(data_dir=tmp_path / "data")
    state.set_target("10.10.10.5")

    def fake_recon(gstate: dict[str, Any]) -> dict[str, Any]:
        st = gstate["target"]
        st.data.add_port(Port(number=22, protocol="tcp", service="ssh"))
        st.record_command("nmap_tcp_full", ["nmap", "10.10.10.5"], "Full TCP scan", "22/tcp open")
        st.save()
        return {}

    monkeypatch.setattr(graph_nodes, "recon", fake_recon)

    class _Resp:
        text = "<html><h1>home</h1></html>"

    class _Session:
        def get(self, *a: object, **k: object) -> _Resp:
            return _Resp()

    monkeypatch.setattr(graph_nodes, "new_session", lambda: _Session())

    result = build_graph().invoke({"target": state, "options": ScanOptions(skip_web=True)})

    assert state.data.command_results  # command cleaner ran
    assert state.data.command_results[0].clean_output == "22/tcp open ssh"
    assert state.data.page_analyses  # analyst + research ran
    analysis = state.data.page_analyses[0]
    assert analysis.summary == "final"
    assert "/admin" in analysis.bypass_paths
    assert result["report_path"]
