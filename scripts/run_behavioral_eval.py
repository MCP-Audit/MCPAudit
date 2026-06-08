#!/usr/bin/env python3
"""Run the behavioral SAST evaluation corpus and print metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcts.sast.eval import run_behavioral_eval


def main() -> int:
    parser = argparse.ArgumentParser(description="Run behavioral SAST eval corpus")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="Path to cases.json (default: eval/behavioral/cases.json)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    report = run_behavioral_eval(args.corpus)
    if args.json:
        payload = {
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "recall": round(report.recall, 4),
            "results": [
                {
                    "case_id": row.case_id,
                    "passed": row.passed,
                    "reason": row.reason,
                    "findings": row.findings,
                }
                for row in report.results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Behavioral SAST eval: {report.passed}/{report.total} passed")
        print(f"Malicious-case recall: {report.recall:.1%}")
        for row in report.results:
            status = "PASS" if row.passed else "FAIL"
            print(f"  [{status}] {row.case_id}: {row.reason}")
            if not row.passed and row.findings:
                print(f"         findings: {', '.join(row.findings)}")

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
