"""Load scoring weights from packaged YAML."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from mcts.scoring.models import ScoringWeights

PACKAGE_DIR = Path(__file__).resolve().parent


def load_weights(profile: str = "manual_v1") -> ScoringWeights:
    if profile == "manual_v1":
        path = PACKAGE_DIR / "weights_v1.yaml"
    elif profile in {"weights_learned", "learned_v1"}:
        path = PACKAGE_DIR / "weights_learned.yaml"
    elif profile.startswith("learned"):
        path = PACKAGE_DIR / f"{profile}.yaml"
    else:
        raise ValueError(f"Unknown weights profile: {profile}")
    if not path.exists():
        raise FileNotFoundError(f"Weights file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ScoringWeights.from_yaml_dict(data)


def weights_hash(weights: ScoringWeights) -> str:
    """SHA256 prefix of canonical YAML representation."""
    payload: dict[str, Any] = {
        "version": weights.version,
        "severity": weights.severity,
        "classifiers": weights.classifiers,
    }
    canonical = yaml.dump(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
