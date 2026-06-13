"""Analyzer bronze fact emission tests."""

from pathlib import Path

from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.path_validation import PathValidationAnalyzer
from mcts.analyzers.permissions import PermissionAnalyzer
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcts.core.config import ScanConfig
from mcts.discovery.static import StaticDiscovery
from mcts.mcp.models import MCPServerInfo, MCPTool


def test_prompt_injection_emits_bronze_facts(example_server_path: Path) -> None:
    server = StaticDiscovery(ScanConfig(target=example_server_path)).discover()
    findings = PromptInjectionAnalyzer().analyze(server)
    assert findings
    assert all((f.evidence or {}).get("facts") for f in findings)


def test_data_leakage_emits_bronze_facts(example_server_path: Path) -> None:
    server = StaticDiscovery(ScanConfig(target=example_server_path)).discover()
    findings = DataLeakageAnalyzer().analyze(server)
    assert findings
    assert all((f.evidence or {}).get("facts") for f in findings)


def test_path_validation_emits_bronze_facts() -> None:
    server = MCPServerInfo(
        tools=[
            MCPTool(
                name="read_file",
                description="Read a file",
                handler_snippet="def read_file(path):\n    return open(path).read()",
            )
        ],
        source_files={},
    )
    findings = PathValidationAnalyzer().analyze(server)
    assert findings
    facts = findings[0].evidence.get("facts") or []
    assert facts[0]["rule_id"] == "RULE_PATH_NO_CANONICALIZATION"


def test_tool_abuse_emits_bronze_facts() -> None:
    server = MCPServerInfo(tools=[MCPTool(name="read_file", description="Read any file from disk")])
    findings = ToolAbuseAnalyzer().analyze(server)
    assert findings
    facts = findings[0].evidence.get("facts") or []
    assert facts[0]["rule_id"] == "RULE_TOOL_TRAVERSAL"


def test_permissions_emits_bronze_facts() -> None:
    server = MCPServerInfo(tools=[MCPTool(name="wipe_db", description="Delete all records permanently")])
    findings = PermissionAnalyzer().analyze(server)
    destructive = [f for f in findings if "destructive" in f.id]
    assert destructive
    facts = destructive[0].evidence.get("facts") or []
    assert facts[0]["rule_id"] == "RULE_PERM_DESTRUCTIVE"
