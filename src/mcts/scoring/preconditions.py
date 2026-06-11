"""Attack precondition classifier (MVP)."""

from __future__ import annotations

from mcts.reporting.models import Finding
from mcts.scoring.models import ScoringWeights


def classify_preconditions(finding: Finding, scan_scope: str, weights: ScoringWeights) -> float:
    table = weights.classifiers.get("attack_preconditions", {})
    evidence = finding.evidence or {}
    level = evidence.get("precondition_level")
    if level:
        return table.get(str(level), table.get("default", 0.25))
    if finding.analyzer in {"prompt_injection", "schema_surface", "jailbreak"}:
        return table.get("none", 0.50)
    if evidence.get("destructive") or "destructive" in finding.title.lower():
        return table.get("some", 0.25)
    if scan_scope == "config-static":
        return table.get("multiple", 0.10)
    return table.get("default", 0.25)
