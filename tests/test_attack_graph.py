"""Tests for attack graph generation."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import build_attack_graph
from mcts.scoring.graph import canonical_attack_graph

VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")


def test_attack_graph_uses_capability_edges(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    graph = build_attack_graph(report)

    assert graph["edges"]
    labels = {edge["label"] for edge in graph["edges"]}
    assert any("exfil" in label or "exec" in label or "chain" in label for label in labels)

    # No synthetic "related" fallback edges
    assert not any(edge["label"] == "related" for edge in graph["edges"])


def test_attack_graph_empty_when_no_chains() -> None:
    from mcts.mcp.models import MCPServerInfo, MCPTool
    from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

    report = ScanReport(
        version="0.0.0",
        target="test",
        scanned_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        server=MCPServerInfo(
            tools=[
                MCPTool(name="safe_list", description="List items only"),
            ]
        ),
        findings=[],
        summary=ScanSummary(),
        score=RiskScore(
            overall=100,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(critical=0, high=0, medium=0, low=0, scorable_total=0, excluded_non_scorable=0),
        ),
        attack_graph={"nodes": [], "edges": []},
    )
    graph = build_attack_graph(report)
    assert graph.get("edges", []) == []


def test_attack_graph_paths_schema_on_vulnerable() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    graph = canonical_attack_graph(report)
    paths = graph.get("paths") or []
    assert paths
    for path in paths:
        assert "hop_count" in path
        assert isinstance(path["hop_count"], int)
        assert path["hop_count"] >= 1
        tools = path.get("tools_on_path") or path.get("nodes")
        assert tools
        assert len(tools) >= 2


def test_scanner_graph_matches_build_attack_graph() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert report.attack_graph.get("paths") == build_attack_graph(report).get("paths")


def test_g0_semantic_path_has_multi_hop_on_vulnerable() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    paths = canonical_attack_graph(report).get("paths") or []
    assert any(path.get("hop_count", 0) >= 2 for path in paths)


def test_pentest_attack_paths_populated_on_vulnerable() -> None:
    from mcts.pentest.runner import run_pentest

    report = run_pentest(ScanConfig(target=VULNERABLE, scoring_mode="v2"), run_fuzz=False)
    attack_phase = next(phase for phase in report.phases if phase.name == "attack_chains")
    assert attack_phase.findings > 0
