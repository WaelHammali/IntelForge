from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from intelforge import __version__
from intelforge.cli import _repl_dispatch, cli


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


def test_scan_rejects_injection_target(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("intelforge.config.settings.data_dir", tmp_path / "data")
    result = CliRunner().invoke(cli, ["scan", "10.10.10.5 --script=http-vuln"])
    assert result.exit_code != 0
    assert "invalid target" in result.output
    assert "Traceback" not in result.output


def test_set_unknown_field_exits_nonzero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("intelforge.config.settings.data_dir", tmp_path / "data")
    result = CliRunner().invoke(cli, ["set", "not_a_field", "x"])
    assert result.exit_code != 0
    assert "unknown state field" in result.output


@pytest.fixture
def _repl_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("intelforge.config.settings.data_dir", tmp_path / "data")


def test_repl_use_updates_current_target(_repl_env: None) -> None:
    assert _repl_dispatch("use", ["example.com"], "") == "example.com"


def test_repl_unknown_command_keeps_current(_repl_env: None) -> None:
    assert _repl_dispatch("frobnicate", [], "prev.com") == "prev.com"


def test_repl_bad_target_raises_clickexception(_repl_env: None) -> None:
    import click

    with pytest.raises(click.ClickException):
        _repl_dispatch("use", ["--bad"], "")
