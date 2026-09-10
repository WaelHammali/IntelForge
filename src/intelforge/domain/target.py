"""Validation and classification of a user-supplied scan target.

Every target string entering the pipeline (CLI argument, interactive console,
``set target``) is passed through :func:`validate_target` before it reaches a
subprocess. This rejects argument-injection attempts (a value such as
``-oX`` or ``--script=...`` that Nmap would read as an option) and anything
that is not a plausible IP address, hostname, or ``http(s)`` URL.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# RFC 1123 host names, plus underscores which show up on lab / CTF networks.
# Total length <= 253, each label 1-63 chars, no leading/trailing hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """A validated target, ready to hand to the recon tools.

    ``raw``  — exactly what the user typed (whitespace-trimmed), kept for display.
    ``host`` — bare hostname or IP literal; safe to place in an ``nmap`` / ``dig``
               argv because it is known to match a strict pattern.
    ``url``  — the full URL when the user supplied one, otherwise ``None``.
    ``is_ip``— ``host`` is an IPv4/IPv6 literal (web fuzzing is skipped for these).
    """

    raw: str
    host: str
    url: str | None
    is_ip: bool


def is_ip_literal(value: str) -> bool:
    """True when ``value`` parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_target(value: str) -> ScanTarget:
    """Validate and classify ``value``; raise :class:`ValueError` if unusable."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("target is empty")
    if raw.startswith("-"):
        raise ValueError(f"invalid target {raw!r}: must not start with '-'")

    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"invalid target {raw!r}: only http/https URLs are supported")
        host = parsed.hostname or ""
        if not host or not (is_ip_literal(host) or _HOSTNAME_RE.match(host)):
            raise ValueError(f"invalid target {raw!r}: URL host is missing or malformed")
        return ScanTarget(raw=raw, host=host, url=raw, is_ip=is_ip_literal(host))

    if is_ip_literal(raw):
        return ScanTarget(raw=raw, host=raw, url=None, is_ip=True)

    if _HOSTNAME_RE.match(raw):
        return ScanTarget(raw=raw, host=raw, url=None, is_ip=False)

    raise ValueError(f"invalid target {raw!r}: not an IP address, hostname, or http(s) URL")
