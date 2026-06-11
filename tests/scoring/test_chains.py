"""Unit tests for chain factor resolution."""

from unittest.mock import patch

from mcts.reporting.models import Finding, Severity
from mcts.scoring.chains import hop_factor_for, resolve_chain_factors
from mcts.scoring.engine_v2 import finding_risk
from mcts.scoring.factors import ScoringContext
from mcts.scoring.models import RiskFactorVector
from mcts.scoring.weights import load_weights


def _tool_finding(analyzer: str, tool: str, severity: Severity) -> Finding:
    return Finding(
        id=f"{analyzer}-{tool}",
        analyzer=analyzer,
        title="test",
        description="d",
        severity=severity,
        recommendation="fix",
        tool=tool,
    )


def test_hop_factor_mapping() -> None:
    assert hop_factor_for(1) == 1.0
    assert hop_factor_for(2) == 1.15
    assert hop_factor_for(3) == 1.35
    assert hop_factor_for(4) == 1.50


def test_chain_factor_applies_to_tool_findings_not_meta() -> None:
    findings = [_tool_finding("prompt_injection", "read_file", Severity.HIGH)]
    graph = {"paths": [{"hop_count": 2, "tools_on_path": ["read_file", "send_webhook"]}]}
    factors = resolve_chain_factors(findings, graph)
    assert factors[findings[0].id] == 1.15


def test_chain_factor_skips_low_severity() -> None:
    findings = [_tool_finding("prompt_injection", "read_file", Severity.LOW)]
    graph = {"paths": [{"hop_count": 2, "tools_on_path": ["read_file", "send_webhook"]}]}
    factors = resolve_chain_factors(findings, graph)
    assert findings[0].id not in factors


def test_chain_factor_over_amplification_bound_uses_max_not_product() -> None:
    """Multiple paths must not compound — capped at hop_factor_for(4) == 1.50."""
    findings = [_tool_finding("prompt_injection", "read_file", Severity.HIGH)]
    graph = {
        "paths": [
            {"hop_count": 2, "tools_on_path": ["read_file", "send_webhook"]},
            {"hop_count": 4, "tools_on_path": ["read_file", "run_cmd", "get_env", "send_webhook"]},
            {"hop_count": 3, "tools_on_path": ["read_file", "run_cmd", "send_webhook"]},
        ]
    }
    factors = resolve_chain_factors(findings, graph)
    assert factors[findings[0].id] == 1.50
    assert factors[findings[0].id] <= hop_factor_for(4)


def test_chain_factor_changes_absolute_risk_with_mock_context() -> None:
    finding = _tool_finding("prompt_injection", "read_file", Severity.HIGH)
    weights = load_weights("manual_v1")
    vector = RiskFactorVector(exploitability=0.30, reachability=0.35, exposure=0.45)
    base_ctx = ScoringContext(
        findings=[finding],
        tools=[],
        attack_graph={},
        scan_scope="repository",
        weights=weights,
        chain_factors={},
    )
    chain_ctx = ScoringContext(
        findings=[finding],
        tools=[],
        attack_graph={"paths": [{"hop_count": 2, "tools_on_path": ["read_file", "send_webhook"]}]},
        scan_scope="repository",
        weights=weights,
        chain_factors={finding.id: 1.15},
    )
    with patch("mcts.scoring.engine_v2.build_factor_vector", return_value=vector):
        base_risk = finding_risk(finding, base_ctx)
        chain_risk = finding_risk(finding, chain_ctx)
    assert chain_risk > base_risk
