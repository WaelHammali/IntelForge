"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from intelforge.domain.state import TargetState


@pytest.fixture
def state(tmp_path: Path) -> TargetState:
    """A fresh TargetState rooted in a temp directory."""
    st = TargetState(data_dir=tmp_path / "data")
    st.set_target("10.10.10.5")
    return st


@pytest.fixture
def fake_chat() -> Iterator[type]:
    """Factory for a LangChain fake chat model returning canned responses."""
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    yield FakeListChatModel
