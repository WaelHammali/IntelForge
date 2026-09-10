from __future__ import annotations

import pytest

from intelforge.domain.target import validate_target


@pytest.mark.parametrize(
    ("value", "host", "is_ip", "has_url"),
    [
        ("10.10.11.20", "10.10.11.20", True, False),
        ("::1", "::1", True, False),
        ("example.com", "example.com", False, False),
        ("target", "target", False, False),  # single-label CTF host
        ("a-b.sub_1.example.co.uk", "a-b.sub_1.example.co.uk", False, False),
        ("http://10.10.11.20/app", "10.10.11.20", True, True),
        ("https://shop.example.com/login?next=/x", "shop.example.com", False, True),
    ],
)
def test_valid_targets(value: str, host: str, is_ip: bool, has_url: bool) -> None:
    t = validate_target(value)
    assert t.raw == value
    assert t.host == host
    assert t.is_ip is is_ip
    assert (t.url is not None) is has_url


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "-oX",  # nmap argument injection
        "--script=http-vuln",
        "10.10.11.20 -sV",  # embedded flag
        "target; rm -rf /",  # shell metacharacters
        "ftp://example.com",  # unsupported scheme
        "http://",  # no host
        "http:// space.com",
        "not a host",
    ],
)
def test_invalid_targets_raise(value: str) -> None:
    with pytest.raises(ValueError):
        validate_target(value)
