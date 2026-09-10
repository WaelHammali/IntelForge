from __future__ import annotations

import pytest

from intelforge.tools.http import ensure_url, new_session


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "http://example.com"),
        ("10.0.0.1", "http://10.0.0.1"),
        ("https://example.com/x", "https://example.com/x"),
        ("http://example.com", "http://example.com"),
    ],
)
def test_ensure_url(value: str, expected: str) -> None:
    assert ensure_url(value) == expected


def test_new_session_disables_verify_and_sets_ua() -> None:
    session = new_session()
    assert session.verify is False
    assert session.headers["User-Agent"].startswith("IntelForge/")
