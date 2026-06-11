"""Corpus ordering gate G2."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner

BASELINE = Path("examples/baseline-mcp-server/server.py")
MEDIUM = Path("examples/medium-risk-mcp-server/server.py")
VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")


def test_corpus_ordering_absolute_risk() -> None:
    base = Scanner(ScanConfig(target=BASELINE, scoring_mode="v2")).run()
    med = Scanner(ScanConfig(target=MEDIUM, scoring_mode="v2")).run()
    vuln = Scanner(ScanConfig(target=VULNERABLE, scoring_mode="v2")).run()
    assert base.score_v2 is not None
    assert med.score_v2 is not None
    assert vuln.score_v2 is not None
    assert vuln.score_v2.absolute_risk > med.score_v2.absolute_risk > base.score_v2.absolute_risk
    assert vuln.score_v2.risk_level in {"high", "critical"}
