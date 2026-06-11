"""Corpus runner shared with calibration scripts."""

from mcts.scoring.corpus_runner import (
    build_package_stats_from_metrics,
    load_corpus_entries,
    scan_corpus_metrics,
)
from mcts.scoring.models import FACTOR_DIMENSIONS


def test_corpus_has_at_least_ten_servers() -> None:
    entries = [entry for entry in load_corpus_entries() if not entry.get("skip")]
    assert len(entries) >= 10


def test_scan_corpus_absolute_risks_returns_all_servers() -> None:
    entries = [entry for entry in load_corpus_entries() if not entry.get("skip")]
    risks = scan_corpus_metrics(scoring_mode="v2").risks
    assert set(risks) == {entry["server_id"] for entry in entries}


def test_build_package_stats_recomputes_dimension_p95() -> None:
    metrics = scan_corpus_metrics(scoring_mode="v2")
    stats = build_package_stats_from_metrics(metrics, version="test-corpus")
    assert stats["dimension_p95"]
    for dim in FACTOR_DIMENSIONS:
        assert dim in stats["dimension_p95"]
        assert stats["dimension_p95"][dim] >= 1
