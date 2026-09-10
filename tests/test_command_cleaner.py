from __future__ import annotations

from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeListChatModel

from intelforge.agents.command_cleaner import CommandCleaner, naive_strip
from intelforge.domain.state import TargetState


def test_naive_strip_removes_ansi_and_blank_runs() -> None:
    out = naive_strip("\x1b[1;32mBanner\x1b[0m\n\n\n\nport 22 open\n\n\n")
    assert "\x1b" not in out
    assert "port 22 open" in out
    assert "\n\n\n" not in out


def _queue(state: TargetState, name: str, raw: str, tmp_path: Path) -> None:
    ref = str(tmp_path / f"{name}.txt")
    Path(ref).write_text(raw)
    state.pending_commands.append(
        {"name": name, "command": f"{name} 10.10.10.5", "purpose": name, "raw_ref": ref}
    )


def test_single_command_uses_llm(state: TargetState, tmp_path: Path) -> None:
    _queue(state, "nmap_tcp_full", "Starting Nmap\n22/tcp open ssh\nNmap done", tmp_path)
    model = FakeListChatModel(responses=['{"clean_output": "22/tcp open ssh"}'])

    rows = CommandCleaner(model).run(state)

    assert rows == 1
    assert state.data.command_results[0].clean_output == "22/tcp open ssh"
    assert state.pending_commands == []


def test_finalrecon_is_fanned_into_sections(state: TargetState, tmp_path: Path) -> None:
    _queue(state, "finalrecon", "headers...\nwhois...", tmp_path)
    model = FakeListChatModel(
        responses=[
            '{"sections": ['
            '{"section": "Headers", "clean_output": "Server: nginx"},'
            '{"section": "WHOIS", "clean_output": "registrar: X"}]}'
        ]
    )

    rows = CommandCleaner(model).run(state)

    assert rows == 2
    purposes = {cr.purpose for cr in state.data.command_results}
    assert purposes == {"finalrecon · Headers", "finalrecon · WHOIS"}


def test_falls_back_to_naive_without_model(state: TargetState, tmp_path: Path) -> None:
    _queue(state, "nmap_tcp_light", "\x1b[0mbanner\n\n\nfound port 80", tmp_path)

    rows = CommandCleaner(None).run(state)

    assert rows == 1
    assert "found port 80" in state.data.command_results[0].clean_output
