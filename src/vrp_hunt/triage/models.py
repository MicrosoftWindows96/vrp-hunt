"""Models for reward scoring and triage."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset

DomainTier = Literal["T0", "T1", "T2", "T3a", "T3b"]
RewardCategory = Literal["S0", "S1", "S2a", "S2b", "S2c", "C0", "C1a", "C1b", "C1c"]
QualityLevel = Literal["low", "good", "exceptional"]


class RewardInput(StrictModel):
    domain_tier: DomainTier
    category: RewardCategory
    quality: QualityLevel = "good"
    downgrade_steps: int = Field(default=0, ge=0)
    novelty_bonus: Decimal = Decimal("0")
    time_limited_bonus: bool = False

    @field_validator("novelty_bonus")
    @classmethod
    def novelty_bonus_cannot_be_negative(cls, value: Decimal) -> Decimal:
        if value < 0:
            raise ValueError("novelty_bonus cannot be negative")
        return value


class RewardEstimate(StrictModel):
    input: RewardInput
    adjusted_category: RewardCategory
    base_amount: Decimal
    quality_multiplier: Decimal
    time_limited_multiplier: Decimal
    novelty_bonus: Decimal
    amount: Decimal
    explanation: str


class BugHypothesis(StrictModel):
    bug_class: str = Field(min_length=1)
    category: RewardCategory
    confidence: Decimal = Field(default=Decimal("1.0"), ge=0, le=1)
    quality: QualityLevel = "good"
    downgrade_steps: int = Field(default=0, ge=0)
    novelty_bonus: Decimal = Decimal("0")
    time_limited_bonus: bool = False


class TriageCandidate(StrictModel):
    asset: Asset
    hypothesis: BugHypothesis
    reward: RewardEstimate
    expected_value: Decimal
    rank_reason: str
