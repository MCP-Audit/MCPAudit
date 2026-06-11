#!/usr/bin/env python3
"""Refresh packaged corpus stats and print Spearman correlation vs expert rankings."""

from __future__ import annotations

import argparse
import json

from mcts.scoring.corpus_runner import (
    EXPERT_RANKINGS_PATH,
    PACKAGE_STATS_PATH,
    build_package_stats_from_metrics,
    scan_corpus_metrics,
    spearman_rho,
)
from mcts.scoring.weights import PACKAGE_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate v2 scoring corpus stats")
    parser.add_argument("--scoring", default="v2", choices=["v2", "both"])
    parser.add_argument("--write-package-stats", action="store_true")
    parser.add_argument("--min-rho", type=float, default=0.0, help="Exit 1 if Spearman rho below threshold")
    parser.add_argument(
        "--stats-version",
        default="corpus-2026-06",
        help="Version label written into packaged corpus stats JSON",
    )
    parser.add_argument(
        "--write-learned-weights",
        action="store_true",
        help="Copy manual_v1 weights to weights_learned.yaml (offline calibration placeholder)",
    )
    args = parser.parse_args()

    metrics = scan_corpus_metrics(scoring_mode=args.scoring)
    risks = metrics.risks
    for server_id, absolute_risk in risks.items():
        print(f"{server_id}: absolute_risk={absolute_risk}")

    if args.write_package_stats and risks:
        stats = build_package_stats_from_metrics(metrics, version=args.stats_version)
        PACKAGE_STATS_PATH.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {PACKAGE_STATS_PATH}")

    if args.write_learned_weights:
        manual = PACKAGE_DIR / "weights_v1.yaml"
        learned = PACKAGE_DIR / "weights_learned.yaml"
        text = manual.read_text(encoding="utf-8").replace("version: manual_v1", "version: learned_v1", 1)
        learned.write_text(text, encoding="utf-8")
        print(f"Wrote {learned}")

    if EXPERT_RANKINGS_PATH.exists():
        expert = json.loads(EXPERT_RANKINGS_PATH.read_text(encoding="utf-8"))
        ids = [row["server_id"] for row in expert["rankings"] if row["server_id"] in risks]
        model_vals = [float(risks[sid]) for sid in ids]
        expert_vals = [
            float(row.get("expert_score") or max(0, 100 - (int(row["rank"]) - 1) * 15))
            for row in expert["rankings"]
            if row["server_id"] in risks
        ]
        rho = spearman_rho(model_vals, expert_vals)
        print(f"Spearman rho={rho:.3f} (n={len(ids)})")
        if rho < args.min_rho:
            raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
