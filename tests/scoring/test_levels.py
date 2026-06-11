"""Risk level band tests."""

from mcts.scoring.levels import risk_level_from_absolute


def test_risk_level_bands() -> None:
    assert risk_level_from_absolute(0) == "low"
    assert risk_level_from_absolute(150) == "medium"
    assert risk_level_from_absolute(300) == "high"
    assert risk_level_from_absolute(600) == "critical"
