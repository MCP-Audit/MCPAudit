"""Load packaged corpus statistics for percentile scoring."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.scoring.models import CorpusStats

PACKAGE_DIR = Path(__file__).resolve().parent


def load_corpus_stats(path: Path | None = None) -> CorpusStats | None:
    if path is not None:
        data = json.loads(path.read_text(encoding="utf-8"))
        return CorpusStats.from_json_dict(data)
    default = PACKAGE_DIR / "data" / "scoring_v2_corpus_stats.json"
    if not default.exists():
        return None
    data = json.loads(default.read_text(encoding="utf-8"))
    return CorpusStats.from_json_dict(data)
