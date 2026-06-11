#!/usr/bin/env python3
"""Batch-scan scoring corpus servers and optionally refresh packaged stats."""

from __future__ import annotations

import argparse
import json

from mcts.scoring.corpus_runner import (
    PACKAGE_STATS_PATH,
    build_package_stats_from_metrics,
    scan_corpus_metrics,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run v2 scoring across corpus servers")
    parser.add_argument("--scoring", default="v2", choices=["v2", "both"])
    parser.add_argument(
        "--write-package-stats",
        action="store_true",
        help="Write distribution snapshot to packaged corpus stats JSON",
    )
    parser.add_argument(
        "--stats-version",
        default="corpus-2026-06",
        help="Version label written into packaged corpus stats JSON",
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
