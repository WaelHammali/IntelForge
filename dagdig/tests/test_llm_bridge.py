#!/usr/bin/env python3
import unittest
from unittest.mock import MagicMock
from core.schema import PageAnalysis, TargetData
from core.state import StateManager
from llm.client import GroqClient
from llm.llm_bridge import DualGroqAnalyzer

class TestDualGroqBridge(unittest.TestCase):
    def test_schema_page_analysis(self):
        pa = PageAnalysis(
            url="http://example.com/login",
            auth_requirement="Auth Required (Login)",
            downloadable_files=["/files/doc.pdf"],
            technologies=["WordPress 6.2", "PHP 8.1"],
            summary="User login page requiring authentication."
        )
        td = TargetData(target="example.com", page_analyses=[pa])
        td_dict = td.to_dict()
        self.assertIn("page_analyses", td_dict)
        self.assertEqual(len(td_dict["page_analyses"]), 1)

        reconstructed = TargetData.from_dict(td_dict)
        self.assertEqual(len(reconstructed.page_analyses), 1)
        self.assertEqual(reconstructed.page_analyses[0].url, "http://example.com/login")
        self.assertEqual(reconstructed.page_analyses[0].auth_requirement, "Auth Required (Login)")

    def test_dual_groq_analyzer_pipeline(self):
        mock_client = MagicMock(spec=GroqClient)
        mock_client.chat_completion.side_effect = [
            "Cleaned Page Title: Login\nForm action: /do-login, input: username, password",
            '{"technologies": ["Apache 2.4", "PHP 8.0"], "auth_requirement": "Auth Required (Login)", "downloadable_files": ["/download.zip"], "summary": "Login page"}'
        ]

        analyzer = DualGroqAnalyzer(mock_client)
        raw_html = "<html><body><h1>Login</h1><form action='/do-login'><input name='username'/></form></body></html>"
        analysis = analyzer.process_url("http://example.com/login", raw_html)

        self.assertEqual(analysis.url, "http://example.com/login")
        self.assertEqual(analysis.auth_requirement, "Auth Required (Login)")
        self.assertIn("Apache 2.4", analysis.technologies)
        self.assertIn("/download.zip", analysis.downloadable_files)

if __name__ == "__main__":
    unittest.main()
