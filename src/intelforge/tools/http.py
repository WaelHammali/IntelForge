"""Shared HTTP client for the web-facing recon steps.

Penetration-test targets routinely serve self-signed, expired, or hostname-
mismatched certificates, so TLS verification is deliberately disabled for
every request IntelForge makes. The corresponding ``urllib3`` warning is
silenced once here, at import time, instead of printing on every call.
"""

from __future__ import annotations

import requests
import urllib3

from intelforge import __version__

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = f"IntelForge/{__version__} (+https://github.com/WaelHammali/IntelForge)"


def new_session() -> requests.Session:
    """A ``requests`` session with a stable UA and TLS verification off."""
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = USER_AGENT
    return session


def ensure_url(target: str, *, scheme: str = "http") -> str:
    """Return ``target`` as a URL, prepending ``scheme://`` when it has none."""
    return target if "://" in target else f"{scheme}://{target}"
