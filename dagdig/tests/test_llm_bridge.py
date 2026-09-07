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

        # DeepSeek R1 outputs <think> reasoning blocks followed by JSON with research_tuples
        mock_researcher.chat_completion.return_value = """
        <think>
        Analyzing target keywords and CVEs...
        Identified vulnerability: SQLi on id parameter.
        </think>
        ```json
        {
            "summary": "DeepSeek Exploit Research Analysis",
            "risk_level": "Critical",
            "research_tuples": [
                {
                    "keyword": "id parameter",
                    "cve": "CVE-2023-XXXX",
                    "vulnerability_name": "SQL Injection on id",
                    "pentest_relevance": "Direct database manipulation via id parameter",
                    "attack_type": "SQLi",
                    "affected_versions": "all",
                    "exploit_method": "sqlmap database dump",
                    "tool": "sqlmap",
                    "example_payload": "sqlmap -u http://example.com/login?id=1 --dbs",
                    "severity": "Critical"
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
            keyword_fingerprints=["PHP 8.0"],
            suspicious_items=["id parameter"]
        )

        report = analyzer.research_exploits(pa)
        self.assertEqual(report.get("risk_level"), "Critical")
        self.assertEqual(len(report.get("research_tuples", [])), 1)
        self.assertEqual(report["research_tuples"][0]["cve"], "CVE-2023-XXXX")
        self.assertEqual(report["research_tuples"][0]["pentest_relevance"], "Direct database manipulation via id parameter")

    def test_full_collaborative_pipeline_run(self):
        from llm.llm_bridge import TripleGroqAnalyzer
        mock_cleaner = MagicMock(spec=GroqClient)
        mock_analyzer = MagicMock(spec=GroqClient)
        mock_researcher = MagicMock(spec=GroqClient)

        # 1. Cleaner output
        mock_cleaner.chat_completion.return_value = "Page Title: Dashboard\nForms: /upload"

        # 2. Analyst initial output (returns suspicious_items)
        mock_analyzer.chat_completion.side_effect = [
            # First call: analyze_page_deep
            """{
                "pages": [{
                    "url": "http://example.com/admin",
                    "auth_requirement": "Public",
                    "technologies": ["Werkzeug 2.0.1"],
                    "summary": "Admin dashboard with upload",
                    "suspicious_items": ["Werkzeug 2.0.1 debug console", "avatar upload without validation"],
                    "keyword_fingerprints": ["Werkzeug 2.0.1"],
                    "llm_recon_paragraph": "Admin panel exposed with Werkzeug 2.0.1 and file upload."
                }]
            }""",
            # Second call: synthesize_final_report
            """{
                "summary": "Critical Vulnerability: Werkzeug PIN exploit & Webshell upload confirmed.",
                "synthesized_attack_surface": "Target exposes Werkzeug debug console allowing RCE via PIN exploit.",
                "priority_exploit_vectors": [{
                    "keyword": "Werkzeug 2.0.1 debug console",
                    "actionable_exploit": "PIN bypass for interactive python RCE",
                    "severity": "Critical"
                }],
                "final_verdict": "Vulnerable to immediate RCE"
            }"""
        ]

        # 3. Researcher DeepSeek output (returns research_tuples)
        mock_researcher.chat_completion.return_value = """{
            "summary": "Critical vulnerabilities identified",
            "risk_level": "Critical",
            "research_tuples": [{
                "keyword": "Werkzeug 2.0.1 debug console",
                "cve": "CVE-2021-XXXX",
                "vulnerability_name": "Werkzeug Debugger RCE",
                "pentest_relevance": "Allows remote code execution if debug PIN is cracked or bypassed",
                "attack_type": "RCE",
                "affected_versions": "2.0.1",
                "exploit_method": "Access /console and execute os.system()",
                "tool": "curl / python",
                "example_payload": "import os; os.system('id')",
                "severity": "Critical"
            }],
            "recommended_attack_order": ["1. Exploit Werkzeug PIN console for RCE"]
        }"""

        analyzer = TripleGroqAnalyzer(
            cleaner_client=mock_cleaner,
            analyzer_client=mock_analyzer,
            researcher_client=mock_researcher
        )

        result = analyzer.run_full_pipeline("http://example.com/admin", "<html>raw</html>")

        self.assertEqual(result.url, "http://example.com/admin")
        self.assertIn("Werkzeug 2.0.1", result.technologies)
        self.assertEqual(len(result.suspicious_items), 2)
        self.assertEqual(len(result.research_tuples), 1)
        self.assertEqual(result.research_tuples[0]["attack_type"], "RCE")
        self.assertIn("Werkzeug PIN exploit", result.summary)

if __name__ == "__main__":
    unittest.main()
