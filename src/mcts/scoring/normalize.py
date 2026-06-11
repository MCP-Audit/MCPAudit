"""Percentile security score from absolute risk."""

from __future__ import annotations

from mcts.scoring.models import CorpusStats


def percentile_rank(value: int, distribution: list[int]) -> int:
    if not distribution:
        return 50
    below = sum(1 for x in distribution if x < value)
    return min(100, round(100 * below / len(distribution)))


def security_score_from_absolute(
    absolute_risk: int, stats: CorpusStats
) -> tuple[int, int]:
    percentile = percentile_rank(absolute_risk, stats.distribution)
    return max(0, min(100, 100 - percentile)), percentile
