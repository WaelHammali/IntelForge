"""Structured JSON export of a completed run."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from intelforge.config import settings
from intelforge.domain.state import TargetState


def write_report(state: TargetState, out_dir: Path | None = None) -> Path:
    """Write ``<data_dir>/report_<host>_<timestamp>.json`` and return the path."""
    target = state.data.target or "unknown"
    host = urlparse(target if "://" in target else f"http://{target}").hostname or target
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    directory = out_dir or settings.data_dir
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"report_{host}_{stamp}.json"

    payload = state.data.model_copy(update={}).model_dump()
    payload["analyzed_at"] = datetime.now(UTC).isoformat()
    path.write_text(_dump(payload))
    return path


def _dump(payload: dict) -> str:
    import json

    return json.dumps(payload, indent=2, ensure_ascii=False)
