"""Scoring v2 data models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

FACTOR_DIMENSIONS = (
    "exploitability",
    "reachability",
    "exposure",
    "blast_radius",
    "business_impact",
    "asset_value",
    "attack_preconditions",
    "threat_maturity",
)

ADDITIVE_FACTORS = FACTOR_DIMENSIONS


class RiskFactorVector(BaseModel):
    exploitability: float = Field(ge=0, le=1, default=0.0)
    reachability: float = Field(ge=0, le=1, default=0.0)
    exposure: float = Field(ge=0, le=1, default=0.0)
    blast_radius: float = Field(ge=0, le=1, default=0.0)
    business_impact: float = Field(ge=0, le=1, default=0.0)
    asset_value: float = Field(ge=0, le=1, default=0.0)
    attack_preconditions: float = Field(ge=0, le=1, default=0.0)
    threat_maturity: float = Field(ge=0, le=1, default=0.0)
    evidence_tags: list[str] = Field(default_factory=list)


class ScoreV2Basis(BaseModel):
    scorable_count: int = Field(ge=0)
    excluded_non_scorable: int = Field(ge=0)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    weights_hash: str = ""
    weights_profile: str = "manual_v1"


class TopContributor(BaseModel):
    type: Literal["finding", "attack_chain"] = "finding"
    finding_id: str | None = None
    risk_contribution: int | None = None
    confidence: int | None = None
    chain_factor: float | None = None
    factors: dict[str, float] | None = None
    path_id: str | None = None
    hop_count: int | None = None
    nodes: list[str] | None = None
    in_chain_findings: list[str] | None = None
    chain_factor_display: float | None = None


class RiskScoreV2(BaseModel):
    absolute_risk: int = Field(ge=0)
    risk_range: tuple[int, int] = (0, 0)
    risk_range_confidence: str = "medium"
    risk_level: str = "low"
    security_score: int | None = Field(default=None, ge=0, le=100)
    risk_percentile: int | None = Field(default=None, ge=0, le=100)
    legacy_overall: int = Field(ge=0, le=100)
    confidence_score: int = Field(ge=0, le=100, default=60)
    weights_profile: str = "manual_v1"
    benchmark_corpus_version: str | None = None
    chain_factor_mode: str = "paths_v1"
    dimension_scores: dict[str, int] = Field(default_factory=dict)
    top_contributors: list[TopContributor] = Field(default_factory=list)
    basis: ScoreV2Basis


class ScoringWeights(BaseModel):
    version: str
    severity: dict[str, int]
    classifiers: dict[str, dict[str, float]]

    @classmethod
    def from_yaml_dict(cls, data: dict[str, Any]) -> ScoringWeights:
        return cls(
            version=str(data.get("version", "manual_v1")),
            severity={k: int(v) for k, v in data.get("severity", {}).items()},
            classifiers={
                axis: {k: float(v) for k, v in table.items()}
                for axis, table in data.get("classifiers", {}).items()
            },
        )


class CorpusStats(BaseModel):
    version: str = "placeholder"
    p25: int = 100
    p50: int = 280
    p75: int = 450
    p90: int = 620
    p95: int = 750
    distribution: list[int] = Field(default_factory=list)
    dimension_p95: dict[str, float] = Field(default_factory=dict)
    risk_bands: dict[str, list[int]] = Field(default_factory=dict)

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> CorpusStats:
        return cls.model_validate(data)
