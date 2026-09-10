from __future__ import annotations

from intelforge.domain.models import CommandResult, PageAnalysis, Port, Service, TargetData


def test_port_dedup_by_identity() -> None:
    data = TargetData()
    data.add_port(Port(number=22, protocol="tcp", service="ssh"))
    data.add_port(Port(number=22, protocol="tcp", service="ssh"))
    data.add_port(Port(number=22, protocol="udp", service="ssh"))
    assert len(data.open_ports) == 2
    assert set(data.protocols) == {"tcp", "udp"}


def test_service_and_string_adders_dedup() -> None:
    data = TargetData()
    data.add_service(Service(name="openssh", version="7.6"))
    data.add_service(Service(name="openssh", version="7.6"))
    data.add_subdomain("a.example.com")
    data.add_subdomain("a.example.com")
    data.add_email("Admin@Example.com")
    data.add_email("admin@example.com")
    assert len(data.services) == 1
    assert data.subdomains == ["a.example.com"]
    assert data.emails == ["Admin@Example.com"]


def test_command_result_upsert_by_command_and_purpose() -> None:
    data = TargetData()
    data.add_command_result(CommandResult(command="c", purpose="p", clean_output="v1"))
    data.add_command_result(CommandResult(command="c", purpose="p", clean_output="v2"))
    assert len(data.command_results) == 1
    assert data.command_results[0].clean_output == "v2"


def test_page_analysis_upsert_merges_technologies() -> None:
    data = TargetData()
    data.upsert_page_analysis(PageAnalysis(url="http://x/", technologies=["nginx"]))
    data.upsert_page_analysis(PageAnalysis(url="http://x/", technologies=["php"]))
    assert len(data.page_analyses) == 1
    assert data.page_analyses[0].technologies == ["php"]
    assert set(data.technologies) == {"nginx", "php"}


def test_json_roundtrip_preserves_shape() -> None:
    data = TargetData(target="t", ip_address="1.2.3.4")
    data.add_port(Port(number=80, protocol="tcp", service="http", version="Apache 2.4.41"))
    data.add_command_result(CommandResult(command="nmap", purpose="scan", clean_output="80 open"))
    restored = TargetData.model_validate_json(data.model_dump_json())
    assert restored == data
    assert restored.open_ports[0].version == "Apache 2.4.41"
