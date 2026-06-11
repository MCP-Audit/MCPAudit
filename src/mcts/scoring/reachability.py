"""Reachability factor classifier (MVP)."""

from __future__ import annotations

from mcts.reporting.models import Finding
from mcts.scoring.models import ScoringWeights

_ANALYZER_DEFAULTS: dict[str, str] = {
    "behavioral_static": "default",
    "prompt_injection": "network_exposed",
    "command_execution": "network_exposed",
    "tool_abuse": "default",
    "discovery_meta": "default",
    "static_discovery": "default",
}


def classify_reachability(finding: Finding, scan_scope: str, weights: ScoringWeights) -> float:
    table = weights.classifiers.get("reachability", {})
    evidence = finding.evidence or {}
    tag = str(evidence.get("reachability_tag") or _ANALYZER_DEFAULTS.get(finding.analyzer, "default"))
    if scan_scope == "live" and tag == "default":
        tag = "network_exposed"
    return table.get(tag, table.get("default", 0.35))
