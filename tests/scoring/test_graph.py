"""Tests for canonical attack graph path building."""

from datetime import UTC, datetime

from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis, Severity
from mcts.scoring.graph import build_paths, canonical_attack_graph


def test_build_paths_rejects_disconnected_tools() -> None:
    finding = Finding(
        id="chain-read-exfil",
        analyzer="attack_chains",
        title="Read exfil",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={
            "read_tools": ["read_a"],
            "exfil_tools": ["exfil_z"],
            "path": ["read_a", "exfil_z"],
        },
    )
    graph = {"nodes": [], "edges": []}
    assert build_paths(graph, [finding]) == []


def test_canonical_graph_builds_paths_when_edges_only() -> None:
    report = ScanReport(
        version="0.0.0",
        target="test",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(
            tools=[
                MCPTool(name="read_file", description="read"),
                MCPTool(name="send_webhook", description="exfil"),
            ]
        ),
        findings=[
            Finding(
                id="chain-read-exfil",
                analyzer="attack_chains",
                title="Read exfil",
                description="d",
                severity=Severity.CRITICAL,
                recommendation="fix",
                evidence={
                    "read_tools": ["read_file"],
                    "exfil_tools": ["send_webhook"],
                    "path": ["read_file", "send_webhook"],
                },
            )
        ],
        summary=ScanSummary(critical=1, total=1),
        score=RiskScore(
            overall=0,
            risk_index=100,
            raw_risk=100,
            penalty=100,
            basis=ScoreBasis(critical=1, high=0, medium=0, low=0, scorable_total=1, excluded_non_scorable=0),
        ),
        attack_graph={
            "nodes": [
                {"id": "read_file", "label": "read_file", "type": "tool"},
                {"id": "send_webhook", "label": "send_webhook", "type": "tool"},
            ],
            "edges": [{"from": "read_file", "to": "send_webhook", "label": "exfil"}],
        },
    )
    graph = canonical_attack_graph(report)
    assert graph.get("paths")
    assert graph["paths"][0]["hop_count"] == 1
