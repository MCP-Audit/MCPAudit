"""Risk scoring package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcts.scoring.engine import RiskScoringEngine
    from mcts.scoring.engine_v2 import RiskScoringEngineV2
    from mcts.scoring.graph import canonical_attack_graph

__all__ = ["RiskScoringEngine", "RiskScoringEngineV2", "canonical_attack_graph"]


def __getattr__(name: str):
    if name == "RiskScoringEngine":
        from mcts.scoring.engine import RiskScoringEngine

        return RiskScoringEngine
    if name == "RiskScoringEngineV2":
        from mcts.scoring.engine_v2 import RiskScoringEngineV2

        return RiskScoringEngineV2
    if name == "canonical_attack_graph":
        from mcts.scoring.graph import canonical_attack_graph

        return canonical_attack_graph
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
