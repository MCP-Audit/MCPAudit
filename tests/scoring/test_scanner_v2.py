"""Integration tests for v2 scoring in the scanner pipeline."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import build_attack_graph, build_dashboard_payload
from mcts.scoring.graph import canonical_attack_graph
from mcts.scoring.pipeline_trace import EVENTS, clear

VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")
PROMPT_ONLY = Path("examples/prompt-only-server/server.py")
BASELINE = Path("examples/baseline-mcp-server/server.py")


def test_legacy_unchanged_when_scoring_legacy() -> None:
    report = Scanner(ScanConfig(target=BASELINE, scoring_mode="legacy")).run()
    assert report.score_v2 is None


def test_v2_mode_still_populates_legacy_score() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert report.score.overall is not None
    assert report.score_v2 is not None


def test_paths_present_when_chains_enabled_on_vulnerable() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="both")).run()
    assert "attack_chains" in report.analyzers_executed
    graph = canonical_attack_graph(report)
    assert graph.get("paths")


def test_attack_chains_meta_present_but_excluded_from_v2_basis() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert any(f.analyzer == "attack_chains" for f in report.findings)
    assert report.score_v2 is not None
    assert report.score_v2.basis.excluded_non_scorable >= 5
    assert report.score_v2.basis.scorable_count == (
        len(report.findings) - report.score_v2.basis.excluded_non_scorable
    )


def test_zero_tool_server_does_not_crash() -> None:
    Scanner(ScanConfig(target=PROMPT_ONLY, scoring_mode="v2")).run()


def test_scanner_graph_matches_canonical() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert report.attack_graph.get("paths") == canonical_attack_graph(report).get("paths")


def test_top_contributors_includes_attack_chain_row() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert report.score_v2 is not None
    assert any(c.type == "attack_chain" for c in report.score_v2.top_contributors)


def test_attack_graph_before_score_v2() -> None:
    """Invariant I2 — graph + scope before v1/v2 scoring."""
    clear()
    Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert EVENTS.index("graph") < EVENTS.index("scope") < EVENTS.index("v1") < EVENTS.index("v2")


def test_v1_verify_still_runs() -> None:
    from mcts.scoring.engine import RiskScoringEngine

    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert RiskScoringEngine.verify(report.findings, report.score)


def test_filtered_scan_graph_matches_dashboard_payload() -> None:
    """Invariant I3 — chains-off + prompt-only surface: scanner graph = dashboard graph."""
    report = Scanner(
        ScanConfig(
            target=VULNERABLE,
            scoring_mode="both",
            enable_attack_chains=False,
            surfaces=["prompt"],
            surface_scoped_analyzers=True,
        )
    ).run()
    scanner_paths = report.attack_graph.get("paths")
    assert scanner_paths == canonical_attack_graph(report).get("paths")
    assert scanner_paths == build_attack_graph(report).get("paths")
    payload = build_dashboard_payload(report)
    assert payload["attack_graph"].get("paths") == scanner_paths


def test_compliance_excluded_from_v2_basis() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert report.score_v2 is not None
    compliance_rows = sum(1 for f in report.findings if f.analyzer == "compliance")
    chain_rows = sum(1 for f in report.findings if f.analyzer == "attack_chains")
    assert report.score_v2.basis.excluded_non_scorable >= compliance_rows + chain_rows
