"""Bug bounty program registry data contracts."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import Field, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel, TargetKind
from vrp_hunt.guardrails.normalization import (
    NormalizationError,
    normalize_host,
    normalize_mobile_app,
    normalize_url,
)
from vrp_hunt.guardrails.rate_limits import RateLimitPolicy

ScopeEntryKind = Literal[
    "domain",
    "host_suffix",
    "exact_host",
    "exact_url",
    "mobile_app",
    "mobile_publisher",
]
ProgramScopeDecisionValue = Literal["IN_SCOPE", "OUT_OF_SCOPE", "UNKNOWN"]
ProgramRegistryChangeKind = Literal["added", "removed", "changed"]
ProgramRegistryEntryType = Literal["program", "scope", "exclusion"]


class SafeHarborPolicy(StrictModel):
    summary: str = Field(min_length=1, max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)
    researcher_requirements: list[str] = Field(default_factory=list)

    @field_validator("researcher_requirements")
    @classmethod
    def requirements_must_not_be_blank(cls, value: list[str]) -> list[str]:
        return _stripped_unique(value, "researcher requirements")


class RewardTier(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    label: str = Field(min_length=1, max_length=256)
    min_usd: float = Field(ge=0)
    max_usd: float = Field(ge=0)
    notes: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def max_must_not_be_less_than_min(self) -> "RewardTier":
        if self.max_usd < self.min_usd:
            raise ValueError("reward max_usd must be >= min_usd")
        return self


class ProgramScopeEntry(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    kind: ScopeEntryKind
    value: str = Field(min_length=1, max_length=4096)
    reward_eligible: bool = True
    notes: str = Field(default="", max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("scope value cannot be blank")
        return stripped

    @model_validator(mode="after")
    def value_must_match_kind(self) -> "ProgramScopeEntry":
        try:
            if self.kind in {"domain", "host_suffix", "exact_host"}:
                normalize_host(_host_pattern(self.value))
            elif self.kind == "exact_url":
                normalize_url(self.value)
            elif self.kind == "mobile_app":
                normalize_mobile_app(self.value)
            elif self.kind == "mobile_publisher" and not self.value.strip():
                raise ValueError("mobile publisher cannot be blank")
        except NormalizationError as exc:
            raise ValueError(f"invalid {self.kind} scope value") from exc
        return self


class ProgramExclusion(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    kind: ScopeEntryKind
    value: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("exclusion value cannot be blank")
        return stripped

    @model_validator(mode="after")
    def value_must_match_kind(self) -> "ProgramExclusion":
        try:
            if self.kind in {"domain", "host_suffix", "exact_host"}:
                normalize_host(_host_pattern(self.value))
            elif self.kind == "exact_url":
                normalize_url(self.value)
            elif self.kind == "mobile_app":
                normalize_mobile_app(self.value)
            elif self.kind == "mobile_publisher" and not self.value.strip():
                raise ValueError("mobile publisher cannot be blank")
        except NormalizationError as exc:
            raise ValueError(f"invalid {self.kind} exclusion value") from exc
        return self


class ProgramProfile(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=1, max_length=256)
    platform: str = Field(min_length=1, max_length=128)
    policy_url: str = Field(min_length=1, max_length=1000)
    captured_date: date
    safe_harbor: SafeHarborPolicy
    rate_limit: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    scope: list[ProgramScopeEntry] = Field(min_length=1)
    exclusions: list[ProgramExclusion] = Field(default_factory=list)
    reward_tiers: list[RewardTier] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("captured_date", mode="before")
    @classmethod
    def parse_captured_date(cls, value: object) -> object:
        if isinstance(value, str):
            return date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def entry_ids_must_be_unique(self) -> "ProgramProfile":
        scope_ids = [entry.id for entry in self.scope]
        exclusion_ids = [entry.id for entry in self.exclusions]
        reward_ids = [entry.id for entry in self.reward_tiers]
        _ensure_unique(scope_ids, "scope ids")
        _ensure_unique(exclusion_ids, "exclusion ids")
        _ensure_unique(reward_ids, "reward tier ids")
        return self


class ProgramRegistry(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    programs: list[ProgramProfile] = Field(min_length=1)

    @model_validator(mode="after")
    def program_ids_must_be_unique(self) -> "ProgramRegistry":
        _ensure_unique([program.id for program in self.programs], "program ids")
        return self


class ProgramScopeDecision(StrictModel):
    decision: ProgramScopeDecisionValue
    target_kind: TargetKind
    target: str = Field(min_length=1)
    normalized_target: str | None = None
    program_id: str | None = None
    program_name: str | None = None
    matched_entry_id: str | None = None
    reward_eligible: bool = False
    safe_harbor_summary: str | None = None
    rate_limit: RateLimitPolicy | None = None
    reason: str = Field(min_length=1)
    source_reference: str | None = None


class ProgramRegistryChange(StrictModel):
    change: ProgramRegistryChangeKind
    entry_type: ProgramRegistryEntryType
    program_id: str = Field(min_length=1)
    program_name: str | None = None
    entry_id: str | None = None
    kind: ScopeEntryKind | None = None
    value: str | None = None
    reward_eligible: bool | None = None
    source_reference: str | None = None
    fresh_target: bool = False
    old: dict[str, object] | None = None
    new: dict[str, object] | None = None


class ProgramRegistryDiff(StrictModel):
    old_version: str = Field(min_length=1)
    new_version: str = Field(min_length=1)
    changes: list[ProgramRegistryChange] = Field(default_factory=list)
    fresh_targets: list[ProgramRegistryChange] = Field(default_factory=list)


def _host_pattern(value: str) -> str:
    return value.strip().removeprefix("*.").rstrip(".")


def _ensure_unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _stripped_unique(values: list[str], label: str) -> list[str]:
    stripped = [value.strip() for value in values]
    if any(not value for value in stripped):
        raise ValueError(f"{label} cannot contain blanks")
    _ensure_unique(stripped, label)
    return stripped
