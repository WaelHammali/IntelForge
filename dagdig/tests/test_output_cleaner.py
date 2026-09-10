#!/usr/bin/env python3
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from core.schema import CommandResult, TargetData
from core.state import StateManager
from llm.client import GroqClient
from llm.output_cleaner import CommandOutputCleaner, _naive_strip


class TestCommandResultSchema(unittest.TestCase):
    def test_roundtrip(self):
        td = TargetData(target="10.10.10.5")
        td.add_command_result(CommandResult(
            command="nmap -sS 10.10.10.5", purpose="Full TCP scan",
            clean_output="22/tcp open ssh OpenSSH 7.6", raw_ref="data/raw/x.txt",
        ))
        restored = TargetData.from_dict(td.to_dict())
        self.assertEqual(len(restored.command_results), 1)
        self.assertEqual(restored.command_results[0].purpose, "Full TCP scan")

    def test_upsert_by_command_and_purpose(self):
        td = TargetData()
        td.add_command_result(CommandResult(command="c", purpose="p", clean_output="v1"))
        td.add_command_result(CommandResult(command="c", purpose="p", clean_output="v2"))
        self.assertEqual(len(td.command_results), 1)
        self.assertEqual(td.command_results[0].clean_output, "v2")


class TestNaiveStrip(unittest.TestCase):
    def test_drops_ansi_and_blank_runs(self):
        raw = "\x1b[1;32mBanner\x1b[0m\n\n\n\nport 22 open\n\n\n"
        out = _naive_strip(raw)
        self.assertNotIn("\x1b", out)
        self.assertIn("port 22 open", out)
        self.assertNotIn("\n\n\n", out)


class TestCommandOutputCleaner(unittest.TestCase):
    def _state(self):
        tmp = tempfile.mkdtemp()
        os.chdir(tmp)
        s = StateManager(state_file=os.path.join(tmp, "state.json"))
        s.data.target = "10.10.10.5"
        return s, tmp

    def test_single_command_llm_path(self):
        s, tmp = self._state()
        raw_path = os.path.join(tmp, "raw.txt")
        open(raw_path, "w").write("Starting Nmap\n22/tcp open ssh\nNmap done")
        s.pending_commands = [{
            "name": "tcp_full", "command": "nmap -sS 10.10.10.5",
            "purpose": "Full TCP scan", "raw_ref": raw_path,
        }]

        client = MagicMock(spec=GroqClient)
        client.is_configured.return_value = True
        client.chat_completion.return_value = '{"clean_output": "22/tcp open ssh"}'

        rows = CommandOutputCleaner(client=client).run(s)
        self.assertEqual(rows, 1)
        self.assertEqual(s.data.command_results[0].clean_output, "22/tcp open ssh")
        self.assertEqual(s.pending_commands, [])

    def test_finalrecon_fans_into_sections(self):
        s, tmp = self._state()
        raw_path = os.path.join(tmp, "fr.txt")
        open(raw_path, "w").write("headers...\nwhois...\ndns...")
        s.pending_commands = [{
            "name": "osint_finalrecon", "command": "finalrecon --url http://10.10.10.5",
            "purpose": "FinalRecon OSINT", "raw_ref": raw_path,
        }]

        client = MagicMock(spec=GroqClient)
        client.is_configured.return_value = True
        client.chat_completion.return_value = (
            '{"sections": ['
            '{"section": "Headers", "clean_output": "Server: nginx"},'
            '{"section": "WHOIS", "clean_output": "registrar: X"}'
            ']}'
        )

        rows = CommandOutputCleaner(client=client).run(s)
        self.assertEqual(rows, 2)
        purposes = {cr.purpose for cr in s.data.command_results}
        self.assertIn("FinalRecon OSINT · Headers", purposes)
        self.assertIn("FinalRecon OSINT · WHOIS", purposes)

    def test_falls_back_to_naive_when_unconfigured(self):
        s, tmp = self._state()
        raw_path = os.path.join(tmp, "raw.txt")
        open(raw_path, "w").write("\x1b[0mbanner\n\n\nfound port 80")
        s.pending_commands = [{
            "name": "tcp_light", "command": "nmap 10.10.10.5",
            "purpose": "Fast TCP scan", "raw_ref": raw_path,
        }]

        client = MagicMock(spec=GroqClient)
        client.is_configured.return_value = False

        rows = CommandOutputCleaner(client=client).run(s)
        self.assertEqual(rows, 1)
        client.chat_completion.assert_not_called()
        self.assertIn("found port 80", s.data.command_results[0].clean_output)


if __name__ == "__main__":
    unittest.main()
