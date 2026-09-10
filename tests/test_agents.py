from __future__ import annotations

from langchain_core.language_models.fake_chat_models import FakeListChatModel

from intelforge.agents.analyst import Analyst
from intelforge.agents.html_cleaner import HtmlCleaner
from intelforge.agents.researcher import Researcher
from intelforge.domain.models import PageAnalysis


def test_html_cleaner_returns_text() -> None:
    model = FakeListChatModel(responses=["Title: Login\nForm action: /do-login"])
    assert "Login" in HtmlCleaner(model).clean("<html>...</html>")


def test_analyst_extract_surface() -> None:
    model = FakeListChatModel(
        responses=[
            '{"pages": [{"url": "http://x/login", "auth_requirement": "Auth Required (Login)",'
            ' "technologies": ["Apache 2.4", "PHP 8.0"], "downloadable_files": ["/d.zip"],'
            ' "suspicious_items": ["id parameter"], "summary": "login"}]}'
        ]
    )
    pages = Analyst(model).extract_surface({"http://x/login": "cleaned"})
    assert len(pages) == 1
    assert pages[0].auth_requirement == "Auth Required (Login)"
    assert "id parameter" in pages[0].suspicious_items


def test_researcher_normalises_tuples_and_reads_think_blocks() -> None:
    model = FakeListChatModel(
        responses=[
            "<think>reasoning...</think>\n```json\n"
            '{"risk_level": "Critical", "research_tuples": [{"keyword": "id", "cve": "CVE-1"}]}\n```'
        ]
    )
    pa = PageAnalysis(url="http://x/", suspicious_items=["id parameter"])
    report = Researcher(model).research(pa, nmap_summary="tcp/80: http 2.4.41")
    assert report["risk_level"] == "Critical"
    assert report["research_tuples"] == report["vectors"]
    assert report["research_tuples"][0]["cve"] == "CVE-1"


def test_researcher_short_circuits_without_input() -> None:
    model = FakeListChatModel(responses=["{}"])
    report = Researcher(model).research(PageAnalysis(url="http://x/"))
    assert report["research_tuples"] == []


def test_analyst_synthesis_merges_access_map() -> None:
    model = FakeListChatModel(
        responses=[
            '{"summary": "final", "synthesized_attack_surface": "surface",'
            ' "access_map": {"register_required": ["/dashboard"], "bypass_candidates": ["/admin"]}}'
        ]
    )
    pa = PageAnalysis(url="http://x/")
    report = {"research_tuples": [{"keyword": "k"}], "summary": "r"}
    out = Analyst(model).synthesize(pa, report, command_summary="### scan\n80 open")
    assert out.summary == "final"
    assert "/dashboard" in out.auth_pages
    assert "/admin" in out.bypass_paths
    assert out.exploit_report["access_map"]["bypass_candidates"] == ["/admin"]
