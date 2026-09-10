from __future__ import annotations

from pathlib import Path

from intelforge.domain.models import CommandResult, Port, Service
from intelforge.domain.state import TargetState


def test_set_target_persists(tmp_path: Path) -> None:
    st = TargetState(data_dir=tmp_path / "data")
    st.set_target("example.com")
    assert (tmp_path / "data" / "state.json").exists()
    assert TargetState(data_dir=tmp_path / "data").data.target == "example.com"


def test_record_command_writes_raw_and_queues(state: TargetState) -> None:
    ref = state.record_command("tcp_full", ["nmap", "-sS", "x"], "Full TCP scan", "<xml/>")
    assert Path(ref).read_text() == "<xml/>"
    assert state.pending_commands == [
        {
            "name": "tcp_full",
            "command": "nmap -sS x",
            "purpose": "Full TCP scan",
            "raw_ref": ref,
        }
    ]


def test_get_nmap_summary(state: TargetState) -> None:
    state.data.add_port(Port(number=80, protocol="tcp", service="http", version="2.4.41"))
    state.data.add_service(Service(name="openssh", version="7.6p1"))
    summary = state.get_nmap_summary()
    assert "tcp/80: http 2.4.41" in summary
    assert "- openssh 7.6p1" in summary


def test_get_command_table(state: TargetState) -> None:
    state.data.add_command_result(
        CommandResult(command="nmap -sS x", purpose="Full TCP", clean_output="80/tcp open http")
    )
    table = state.get_command_table()
    assert "### Full TCP" in table
    assert "$ nmap -sS x" in table
    assert "80/tcp open http" in table


def test_export_to_relative_path(state: TargetState, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out = state.export("out/report.json")
    assert out.exists()
    assert out.read_text().strip().startswith("{")
