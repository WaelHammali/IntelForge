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
        mock_cleaner = MagicMock(spec=GroqClient)
        mock_analyzer = MagicMock(spec=GroqClient)
        mock_cleaner.chat_completion.return_value = "Cleaned Page Title: Login\nForm action: /do-login, input: username, password"
        mock_analyzer.chat_completion.return_value = '{"pages": [{"url": "http://example.com/login", "technologies": ["Apache 2.4", "PHP 8.0"], "auth_requirement": "Auth Required (Login)", "downloadable_files": ["/download.zip"], "summary": "Login page"}]}'

        analyzer = DualGroqAnalyzer(cleaner_client=mock_cleaner, analyzer_client=mock_analyzer)
        raw_html = "<html><body><h1>Login</h1><form action='/do-login'><input name='username'/></form></body></html>"
        analysis = analyzer.process_url("http://example.com/login", raw_html)

        self.assertEqual(analysis.url, "http://example.com/login")
        self.assertEqual(analysis.auth_requirement, "Auth Required (Login)")
        self.assertIn("Apache 2.4", analysis.technologies)
        self.assertIn("/download.zip", analysis.downloadable_files)

    def test_triple_groq_analyzer_deepseek_stage3(self):
        from llm.llm_bridge import TripleGroqAnalyzer
        mock_cleaner = MagicMock(spec=GroqClient)
        mock_analyzer = MagicMock(spec=GroqClient)
        mock_researcher = MagicMock(spec=GroqClient)

        # DeepSeek R1 outputs <think> reasoning blocks followed by JSON
        mock_researcher.chat_completion.return_value = """
        <think>
        Analyzing target keywords and CVEs...
        Identified vulnerability: SQLi on id parameter.
        </think>
        ```json
        {
            "summary": "DeepSeek Exploit Research Analysis",
            "risk_level": "Critical",
            "vectors": [
                {
                    "title": "SQL Injection on id",
                    "cve_id": "CVE-2023-XXXX",
                    "severity": "Critical",
                    "component": "PHP 8.0",
                    "attack_type": "SQLi",
                    "description": "Exploit id query param",
                    "tools_recommended": ["sqlmap"],
                    "poc_or_method": "sqlmap -u http://example.com/login?id=1 --dbs"
                }
            ],
            "recommended_attack_order": ["1. Exploit SQLi via sqlmap"],
            "notes": "Verified via DeepSeek R1 reasoning"
        }
        ```
        """

        analyzer = TripleGroqAnalyzer(
            cleaner_client=mock_cleaner,
            analyzer_client=mock_analyzer,
            researcher_client=mock_researcher
        )

        pa = PageAnalysis(
            url="http://example.com/login",
            llm_recon_paragraph="Target uses PHP 8.0 with injectable param id.",
            keyword_fingerprints=["PHP 8.0", "SQLi"]
        )

        report = analyzer.research_exploits(pa)
        self.assertEqual(report.get("risk_level"), "Critical")
        self.assertEqual(len(report.get("vectors", [])), 1)
        self.assertEqual(report["vectors"][0]["cve_id"], "CVE-2023-XXXX")

if __name__ == "__main__":
    unittest.main()
