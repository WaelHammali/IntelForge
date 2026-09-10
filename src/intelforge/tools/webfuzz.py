"""Lightweight web fuzzer: directories (HTTP), subdomains (DNS), vhosts (Host header)."""

from __future__ import annotations

import concurrent.futures
import subprocess
from urllib.parse import urlparse

import requests

from intelforge.config import Settings, settings
from intelforge.console.theme import good, status
from intelforge.domain.state import TargetState
from intelforge.tools.http import ensure_url, new_session

_FALLBACKS: dict[str, list[str]] = {
    "directories": [
        "admin",
        "api",
        "assets",
        "css",
        "js",
        "images",
        "uploads",
        "config",
        "backup",
        "test",
        "dev",
        ".git",
        "robots.txt",
    ],
    "subdomains": ["www", "mail", "ftp", "webmail", "blog", "dev", "admin", "forum", "vpn"],
    "vhosts": ["www", "dev", "test", "staging", "admin", "api", "app"],
}
_WORDLIST_HINTS: dict[str, list[str]] = {
    "directories": ["common.txt", "directory-list-2.3-medium.txt", "directories.txt"],
    "subdomains": ["subdomains-top1million-5000.txt", "subdomains.txt"],
    "vhosts": ["vhosts.txt", "vhosts-common.txt"],
}
_INTERESTING_STATUS = (200, 301, 302, 403)


class WebFuzzer:
    def __init__(self, state: TargetState, config: Settings = settings) -> None:
        self.state = state
        self.config = config
        self.session = new_session()

    # ── wordlists ──────────────────────────────────────────────────────────
    def _wordlist(self, kind: str) -> list[str]:
        wl_dir = self.config.wordlist_dir
        if wl_dir.is_dir():
            for hint in _WORDLIST_HINTS.get(kind, []):
                for match in wl_dir.rglob(hint):
                    lines = match.read_text(encoding="utf-8", errors="ignore").splitlines()
                    words = [w.strip() for w in lines if w.strip() and not w.startswith("#")]
                    if words:
                        return words
        return _FALLBACKS.get(kind, [])

    @staticmethod
    def _host(target: str) -> str:
        return urlparse(target).netloc if "://" in target else target

    def _base_url(self, target: str) -> str:
        return ensure_url(target)

    # ── fuzzers ────────────────────────────────────────────────────────────
    def fuzz_directories(self, target: str) -> list[str]:
        status("Fuzzing directories")
        base = self._base_url(target)
        words = self._wordlist("directories")

        def check(word: str) -> str | None:
            try:
                resp = self.session.get(
                    f"{base}/{word}", allow_redirects=False, timeout=self.config.request_timeout
                )
            except requests.RequestException:
                return None
            return word if resp.status_code in _INTERESTING_STATUS else None

        found: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.fuzz_threads) as pool:
            for result in pool.map(check, words):
                if result:
                    found.append(result)
                    self.state.data.add_directory(result)
                    good(f"directory: /{result}")
        self.state.save()
        return found

    def fuzz_subdomains(self, target: str) -> list[str]:
        status("Fuzzing subdomains")
        host = self._host(target)
        found: list[str] = []
        for sub in self._wordlist("subdomains"):
            fqdn = f"{sub}.{host}"
            try:
                res = subprocess.run(
                    ["dig", "+short", fqdn], capture_output=True, text=True, timeout=3, check=False
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if res.stdout.strip():
                found.append(fqdn)
                self.state.data.add_subdomain(fqdn)
                good(f"subdomain: {fqdn}")
        self.state.save()
        return found

    def fuzz_vhosts(self, target: str) -> list[str]:
        status("Fuzzing virtual hosts")
        host = self._host(target)
        base = self._base_url(target)
        found: list[str] = []
        for vhost in self._wordlist("vhosts"):
            fqdn = f"{vhost}.{host}"
            try:
                resp = self.session.get(
                    base,
                    headers={"Host": fqdn},
                    allow_redirects=False,
                    timeout=self.config.request_timeout,
                )
            except requests.RequestException:
                continue
            if resp.status_code in _INTERESTING_STATUS:
                found.append(fqdn)
                self.state.data.add_vhost(fqdn)
                good(f"vhost: {fqdn}")
        self.state.save()
        return found

    def run_all(self, target: str) -> None:
        self.fuzz_directories(target)
        self.fuzz_subdomains(target)
        self.fuzz_vhosts(target)
