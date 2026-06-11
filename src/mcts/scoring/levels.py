"""Risk level bands from absolute_risk."""

from __future__ import annotations

from mcts.scoring.models import CorpusStats

DEFAULT_BANDS = {
    "low": (0, 99),
    "medium": (100, 249),
    "high": (250, 499),
    "critical": (500, 999_999),
}


def risk_level_from_absolute(absolute_risk: int, stats: CorpusStats | None = None) -> str:
    bands = DEFAULT_BANDS
    if stats and stats.risk_bands:
        bands = {k: (v[0], v[1]) for k, v in stats.risk_bands.items()}
    for level in ("critical", "high", "medium", "low"):
        low, high = bands.get(level, DEFAULT_BANDS[level])
        if low <= absolute_risk <= high:
            return level
    return "critical"
