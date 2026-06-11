"""Unit tests for factor classifiers."""

from mcts.mcp.models import MCPTool
from mcts.reporting.models import Finding, Severity
from mcts.scoring.factors import (
    ScoringContext,
    build_factor_vector,
    classify_business_impact,
    compute_blast_radius,
)
from mcts.scoring.weights import load_weights


def test_blast_radius_zero_tools() -> None:
    finding = Finding(
        id="1",
        analyzer="prompt_injection",
        title="PI",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
    )
    assert compute_blast_radius(finding, []) == 0.0


def test_behavioral_static_gets_non_default_factors() -> None:
    weights = load_weights("manual_v1")
    finding = Finding(
        id="bs-1",
        analyzer="behavioral_static",
        title="Behavior",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
        tool="read_file",
    )
    ctx = ScoringContext(
        findings=[finding],
        tools=[MCPTool(name="read_file", description="read")],
        attack_graph={},
        scan_scope="repository",
        weights=weights,
        corpus_stats=None,
        chain_factors={},
    )
    vector = build_factor_vector(finding, ctx)
    assert vector.exploitability >= 0.30
    assert vector.reachability >= 0.35


def test_permission_analyzer_exploitability_040() -> None:
    from mcts.analyzers.permissions import PermissionAnalyzer
    from mcts.mcp.models import MCPServerInfo, MCPTool
    from mcts.scoring.factors import classify_exploitability

    weights = load_weights("manual_v1")
    server = MCPServerInfo(tools=[MCPTool(name="admin_tool", description="Execute shell commands")])
    finding = PermissionAnalyzer().analyze(server)[0]
    assert classify_exploitability(finding, weights) == 0.40


def test_ciafc_hints_raise_business_impact() -> None:
    weights = load_weights("manual_v1")
    low = Finding(
        id="1",
        analyzer="command_execution",
        title="t",
        description="d",
        severity=Severity.LOW,
        recommendation="fix",
        evidence={"ciafc_hints": ["confidentiality"]},
    )
    high = Finding(
        id="2",
        analyzer="command_execution",
        title="t",
        description="d",
        severity=Severity.LOW,
        recommendation="fix",
        evidence={"ciafc_hints": ["confidentiality", "integrity", "availability"]},
    )
    assert classify_business_impact(low, weights) == weights.classifiers["business_impact"]["medium"]
    assert classify_business_impact(high, weights) == weights.classifiers["business_impact"]["high"]
