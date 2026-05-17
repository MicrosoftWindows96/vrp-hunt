"""Asset confidence and freshness scoring."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.models import Asset, AssetKind


def default_source_confidence_weights() -> dict[str, float]:
    return {
        "seed": 0.95,
        "httpx": 0.9,
        "katana": 0.85,
        "censys": 0.8,
        "chaos": 0.8,
        "securitytrails": 0.8,
        "shodan": 0.8,
        "subfinder": 0.75,
        "alienvault": 0.7,
        "certspotter": 0.7,
        "crtsh": 0.7,
        "github": 0.65,
        "fofa": 0.65,
        "wayback": 0.65,
        "urlscan": 0.65,
        "anubis": 0.6,
        "hackertarget": 0.6,
        "nuclei": 0.6,
        "cli": 0.5,
    }


def default_kind_confidence() -> dict[AssetKind, float]:
    return {
        "host": 0.75,
        "url": 0.85,
        "endpoint": 0.85,
        "parameter": 0.8,
        "javascript": 0.75,
        "technology": 0.65,
        "mobile_component": 0.7,
        "note": 0.4,
    }


class AssetScoringProfile(StrictModel):
    default_source_confidence: float = Field(default=0.5, ge=0, le=1)
    source_confidence: dict[str, float] = Field(default_factory=default_source_confidence_weights)
    kind_confidence: dict[AssetKind, float] = Field(default_factory=default_kind_confidence)
    status_code_boost: float = Field(default=0.05, ge=0, le=0.2)
    parent_boost: float = Field(default=0.03, ge=0, le=0.2)
    metadata_boost: float = Field(default=0.02, ge=0, le=0.2)
    multi_source_boost: float = Field(default=0.05, ge=0, le=0.2)

    @field_validator("source_confidence")
    @classmethod
    def source_weights_must_be_bounded(cls, value: dict[str, float]) -> dict[str, float]:
        for key, weight in value.items():
            if not key.strip():
                raise ValueError("source confidence keys cannot be blank")
            if weight < 0 or weight > 1:
                raise ValueError("source confidence weights must be between 0 and 1")
        return {key.strip().lower(): weight for key, weight in value.items()}

    @field_validator("kind_confidence")
    @classmethod
    def kind_weights_must_be_bounded(cls, value: dict[AssetKind, float]) -> dict[AssetKind, float]:
        if any(weight < 0 or weight > 1 for weight in value.values()):
            raise ValueError("kind confidence weights must be between 0 and 1")
        return value


class AssetScore(StrictModel):
    asset: Asset
    confidence: float = Field(ge=0, le=1)
    freshness: float = Field(ge=0, le=1)
    priority: float = Field(ge=0, le=1)
    age_days: float = Field(ge=0)
    reasons: list[str] = Field(default_factory=list)
    attributed_sources: list[str] = Field(default_factory=list)


class AssetScoreReport(StrictModel):
    generated_at: datetime
    total_assets: int = Field(ge=0)
    scores: list[AssetScore] = Field(default_factory=list)


def score_assets(
    assets: list[Asset],
    *,
    profile: AssetScoringProfile | None = None,
    now: datetime | None = None,
) -> AssetScoreReport:
    scoring_profile = profile or AssetScoringProfile()
    generated_at = now or datetime.now(UTC)
    scores = [
        score_asset(asset, profile=scoring_profile, now=generated_at)
        for asset in assets
    ]
    scores.sort(key=lambda score: (score.priority, score.confidence, score.freshness), reverse=True)
    return AssetScoreReport(
        generated_at=generated_at,
        total_assets=len(assets),
        scores=scores,
    )


def score_asset(
    asset: Asset,
    *,
    profile: AssetScoringProfile | None = None,
    now: datetime | None = None,
) -> AssetScore:
    scoring_profile = profile or AssetScoringProfile()
    generated_at = now or datetime.now(UTC)
    age_days = _age_days(asset, generated_at)
    freshness = _freshness_score(age_days)
    confidence, reasons, attributed_sources = _confidence_score(asset, scoring_profile)
    priority = _clamp((confidence * 0.7) + (freshness * 0.3))
    reasons.append(f"freshness={freshness:.2f} from age_days={age_days:.2f}")
    return AssetScore(
        asset=asset,
        confidence=confidence,
        freshness=freshness,
        priority=priority,
        age_days=age_days,
        reasons=reasons,
        attributed_sources=attributed_sources,
    )


def _confidence_score(asset: Asset, profile: AssetScoringProfile) -> tuple[float, list[str], list[str]]:
    attributed_sources = _attributed_sources(asset)
    weighted_sources = [
        (source, profile.source_confidence.get(source, profile.default_source_confidence))
        for source in attributed_sources
    ]
    best_source, source_weight = max(weighted_sources, key=lambda item: item[1])
    kind_weight = profile.kind_confidence[asset.kind]
    confidence = (source_weight + kind_weight) / 2
    reasons = [
        f"source={best_source} weight={source_weight:.2f}",
        f"kind={asset.kind} weight={kind_weight:.2f}",
    ]
    if len(attributed_sources) > 1:
        confidence += profile.multi_source_boost
        reasons.append(
            f"multi_source_boost={profile.multi_source_boost:.2f} from {','.join(attributed_sources)}"
        )
    if asset.parent:
        confidence += profile.parent_boost
        reasons.append(f"parent_boost={profile.parent_boost:.2f}")
    if asset.metadata:
        confidence += profile.metadata_boost
        reasons.append(f"metadata_boost={profile.metadata_boost:.2f}")
    if _has_status_code(asset):
        confidence += profile.status_code_boost
        reasons.append(f"status_code_boost={profile.status_code_boost:.2f}")
    return _clamp(confidence), reasons, attributed_sources


def _attributed_sources(asset: Asset) -> list[str]:
    sources: list[str] = []
    seen: set[str] = set()
    for value in [asset.source, *_metadata_source_values(asset)]:
        normalized = value.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            sources.append(normalized)
    return sources


def _metadata_source_values(asset: Asset) -> list[str]:
    values: list[str] = []
    for key in ("sources", "source", "providers", "discovery_sources"):
        raw_value = asset.metadata.get(key)
        if raw_value:
            values.extend(raw_value.replace(";", ",").split(","))
    return values


def _age_days(asset: Asset, now: datetime) -> float:
    last_seen = asset.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    effective_now = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    return max((effective_now - last_seen).total_seconds() / 86_400, 0.0)


def _freshness_score(age_days: float) -> float:
    if age_days <= 1:
        return 1.0
    if age_days <= 7:
        return 0.85
    if age_days <= 30:
        return 0.65
    if age_days <= 90:
        return 0.35
    return 0.15


def _has_status_code(asset: Asset) -> bool:
    return any(key.lower() in {"status", "status_code", "http_status"} for key in asset.metadata)


def _clamp(value: float) -> float:
    return min(max(value, 0.0), 1.0)
