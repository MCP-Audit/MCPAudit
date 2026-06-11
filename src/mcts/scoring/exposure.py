"""Exposure factor classifier (MVP)."""

from __future__ import annotations

from mcts.reporting.models import Finding
from mcts.scoring.models import ScoringWeights


def classify_exposure(finding: Finding, weights: ScoringWeights) -> float:
    table = weights.classifiers.get("exposure", {})
    evidence = finding.evidence or {}
    tag = evidence.get("exposure_tag")
    if tag:
        return table.get(str(tag), table.get("default", 0.20))
    if finding.analyzer in {"prompt_injection", "schema_surface", "data_leakage"}:
        return table.get("public_endpoint", table.get("default", 0.20))
    return table.get("default", 0.20)


def apply_reachability_exposure_dedup(
    reachability: float, exposure: float, evidence: dict
) -> float:
    """Keep higher of reachability/exposure when tags overlap."""
    tags = set(evidence.get("risk_tags") or [])
    if "reachability_tag" in tags and "exposure_tag" in tags:
        return min(exposure, max(0.0, exposure - reachability * 0.5))
    return exposure
