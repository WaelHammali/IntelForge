"""FinalRecon wrapper: passive OSINT harvesting into the target state."""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

from intelforge.config import Settings, settings
from intelforge.console.theme import error, warn
from intelforge.domain.state import TargetState
from intelforge.tools.base import run_command

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_IP_RE = re.compile(r"IP Address\s*:\s*(\d+\.\d+\.\d+\.\d+)")
_SERVER_RE = re.compile(r"Server\s*:\s*([^\n]+)", re.IGNORECASE)

_DUMP_FOLDER = "osint_dump"


class FinalReconScanner:
    def __init__(self, state: TargetState, config: Settings = settings) -> None:
        self.state = state
        self.config = config

    def run(self, target: str) -> None:
        script = self.config.finalrecon_path
        if not script.exists():
            error(f"FinalRecon not found at {script}")
            return

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        dump_root = Path(tempfile.mkdtemp(prefix="intelforge_fr_"))
        argv = [
            sys.executable, str(script), "--url", url,
            "--headers", "--sslinfo", "--whois", "--dns", "--sub", "--dir", "--wayback",
            "-nb", "-cd", str(dump_root), "-of", _DUMP_FOLDER,
        ]
        try:
            output = run_command(
                self.state,
                name="finalrecon",
                argv=argv,
                purpose="FinalRecon OSINT (headers, sslinfo, whois, dns, sub, dir, wayback)",
                timeout=self.config.scan_timeout,
            )
            self._parse_stdout(output)
            dump_dir = dump_root / _DUMP_FOLDER
            if dump_dir.is_dir():
                self._parse_dump(dump_dir)
            self.state.save()
        finally:
            shutil.rmtree(dump_root, ignore_errors=True)

    # ── parsing ────────────────────────────────────────────────────────────
    def _parse_stdout(self, text: str) -> None:
        data = self.state.data
        if (m := _IP_RE.search(text)) and not data.ip_address:
            data.ip_address = m.group(1)
        if m := _SERVER_RE.search(text):
            tech = f"Server: {m.group(1).strip()}"
            if tech not in data.technologies:
                data.technologies.append(tech)
        for email in _EMAIL_RE.findall(text):
            data.add_email(email)

    def _parse_dump(self, dump_dir: Path) -> None:
        data = self.state.data
        for path in dump_dir.iterdir():
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                warn(f"Could not read FinalRecon dump {path.name}: {exc}")
                continue
            fname = path.name.lower()
            for line in content.splitlines():
                item = line.strip()
                if not item:
                    continue
                if "sub" in fname and "." in item:
                    data.add_subdomain(item)
                elif "dir" in fname:
                    data.add_directory(item.lstrip("/"))
                elif ("wayback" in fname or "links" in fname) and item.startswith("http"):
                    data.add_endpoint(item)
            for email in _EMAIL_RE.findall(content):
                data.add_email(email)
