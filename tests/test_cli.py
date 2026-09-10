from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from intelforge import __version__
from intelforge.cli import cli


def test_help_lists_commands() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for name in ("scan", "osint", "webanalyze", "show", "graph"):
        assert name in result.output


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert __version__ in result.output


def test_graph_command_emits_mermaid() -> None:
    result = CliRunner().invoke(cli, ["graph"])
    assert result.exit_code == 0
    assert "recon --> clean_commands" in result.output


def test_set_and_export_roundtrip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("intelforge.config.settings.data_dir", tmp_path / "data")
    runner = CliRunner()
    assert runner.invoke(cli, ["set", "target", "example.com"]).exit_code == 0
    result = runner.invoke(cli, ["export", "out.json"])
    assert result.exit_code == 0
    assert (tmp_path / "out.json").exists()
