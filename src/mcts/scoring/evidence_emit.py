"""Backward-compatible entry for graph/scope-dependent v2 evidence enrichment."""

from __future__ import annotations

from typing import Any

from mcts.reporting.models import Finding
from mcts.scoring.evidence_tags import (
    enrich_graph_dependent_evidence,
    has_non_default_v2_evidence,
    has_v2_evidence,
)

__all__ = ["enrich_scoring_evidence", "has_v2_evidence", "has_non_default_v2_evidence"]


def enrich_scoring_evidence(
    findings: list[Finding],
    *,
    attack_graph: dict[str, Any] | None = None,
    scan_scope: str = "repository",
) -> list[Finding]:
    """Apply scan-scope and attack-graph evidence tags after analyzers run."""
    return enrich_graph_dependent_evidence(
        findings,
        attack_graph=attack_graph,
        scan_scope=scan_scope,
    )
