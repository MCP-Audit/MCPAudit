"""Asset value resolver (MVP)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcts.reporting.models import Finding
from mcts.scoring.models import ScoringWeights


@dataclass
class AssetRegistry:
    overrides: dict[str, float] = field(default_factory=dict)


def load_assets(path: Path | None) -> AssetRegistry | None:
    if path is None or not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    overrides = {str(k): float(v) for k, v in (data.get("overrides") or {}).items()}
    return AssetRegistry(overrides=overrides)


def resolve_asset_value(
    finding: Finding,
    weights: ScoringWeights,
    assets: AssetRegistry | None = None,
) -> float:
    table = weights.classifiers.get("asset_value", {})
    if assets and finding.tool and finding.tool in assets.overrides:
        return assets.overrides[finding.tool]
    return table.get("default", 0.25)
