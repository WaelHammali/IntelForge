"""Shared helper for running an external recon tool as a subprocess."""

from __future__ import annotations

import subprocess

from intelforge.console.theme import status, warn
from intelforge.domain.state import TargetState


def run_command(
    state: TargetState,
    name: str,
    argv: list[str],
    purpose: str,
    timeout: int,
    combine_stderr: bool = True,
) -> str:
    """Run ``argv``, record it on ``state`` and return its captured output.

    The raw output is always persisted (and queued for the command-cleaner)
    even on timeout, so partial results are never lost.
    """
    status(f"{purpose} — running: {' '.join(argv)}")
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = result.stdout or ""
        if combine_stderr and result.stderr:
            output = f"{output}\n{result.stderr}"
    except subprocess.TimeoutExpired as exc:
        warn(f"{name} timed out after {timeout}s")
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
    except FileNotFoundError:
        warn(f"{name}: executable '{argv[0]}' not found on PATH")
        return ""

    state.record_command(name, argv, purpose, output)
    return output
