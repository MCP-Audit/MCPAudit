"""Spearman correlation helper tests for calibration script."""

from __future__ import annotations

import json

from mcts.scoring.corpus_runner import EXPERT_RANKINGS_PATH, scan_corpus_absolute_risks, spearman_rho


def test_spearman_perfect_positive() -> None:
    assert spearman_rho([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0


def test_spearman_perfect_negative() -> None:
    assert spearman_rho([1, 2, 3, 4], [40, 30, 20, 10]) == -1.0


def test_spearman_ties() -> None:
    rho = spearman_rho([1, 1, 2, 3], [5, 6, 7, 8])
    assert -1.0 <= rho <= 1.0


def test_corpus_spearman_meets_pilot_threshold() -> None:
    risks = scan_corpus_absolute_risks(scoring_mode="v2")
    expert = json.loads(EXPERT_RANKINGS_PATH.read_text(encoding="utf-8"))
    ids = [row["server_id"] for row in expert["rankings"] if row["server_id"] in risks]
    model_vals = [float(risks[sid]) for sid in ids]
    expert_vals = [float(row["expert_score"]) for row in expert["rankings"] if row["server_id"] in risks]
    rho = spearman_rho(model_vals, expert_vals)
    assert rho >= 0.80
