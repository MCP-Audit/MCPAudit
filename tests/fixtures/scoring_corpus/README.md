# Scoring calibration corpus (dev/CI only — not shipped in wheel)

Provisional expert ordering for G2 pilot tests. Replace with formal expert review before GA.

Shared loader: `mcts.scoring.corpus_runner` (used by `scripts/run_scoring_corpus.py`,
`scripts/calibrate_scoring_weights.py`, and `tests/scoring/`). Technique regression harness
(`mcts.testing.regression_harness`) remains separate — it validates detector accuracy, not
risk-score ordering.
