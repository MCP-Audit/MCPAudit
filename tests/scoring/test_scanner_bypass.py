"""Tests for v2 analyzer bypass rules."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner

VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")


def test_attack_chains_runs_when_analyzers_whitelist_excludes_it() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2", analyzers=["prompt_injection"])).run()
    assert "attack_chains" in report.analyzers_executed


def test_attack_chains_runs_when_surfaces_prompt_only() -> None:
    report = Scanner(
        ScanConfig(
            target=VULNERABLE,
            scoring_mode="v2",
            surfaces=["prompt"],
            surface_scoped_analyzers=True,
        )
    ).run()
    assert "attack_chains" in report.analyzers_executed
