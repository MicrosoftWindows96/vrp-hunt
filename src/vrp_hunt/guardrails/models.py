"""Strict data contracts for guardrail decisions."""

from __future__ import annotations

from datetime import date
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    """Base model that refuses schema drift."""

    model_config = ConfigDict(extra="forbid", validate_default=True, strict=True)


TargetKind = Literal["url", "host", "mobile_app"]
DecisionValue = Literal["ALLOW", "DENY"]
MatchKind = Literal[
    "registrable_domain",
    "acquisition_domain",
    "host_suffix",
    "mobile_publisher",
    "action",
    "sandbox_without_sensitive_impact",
    "blogspot_owner_js",
    "user_enumeration_without_rate_limit_bypass",
]


class TargetCandidate(StrictModel):
    """A proposed target/action pair that must pass before traffic is sent."""

    kind: TargetKind
    raw_target: str = Field(min_length=1, max_length=2048)
    intended_action: str = Field(min_length=1, max_length=128)
    researcher_owned_account: bool = False
    will_access_third_party_data: bool = True
    legal_acknowledged: bool = False
    sensitive_data_impact: bool = False
    rate_limit_bypass_evidence: bool = False
    owner_supplied_javascript: bool = False
    acquisition_date: date | None = None
    context: dict[str, str] = Field(default_factory=dict)

    @field_validator("intended_action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        return value.strip().lower().replace("-", "_").replace(" ", "_")


class Rule(StrictModel):
    """One allow or hard-deny rule from the structured VRP ruleset."""

    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    match_kind: MatchKind
    pattern: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=500)
    source_reference: str = Field(min_length=1, max_length=500)

    @field_validator("pattern")
    @classmethod
    def normalize_pattern(cls, value: str) -> str:
        return value.strip()


class EthicsRequirements(StrictModel):
    require_researcher_owned_account: bool = True
    require_no_third_party_data: bool = True
    require_legal_acknowledgement: bool = True


class AcquisitionPolicy(StrictModel):
    blackout_days: int = Field(gt=0)
    domains: list[str] = Field(min_length=1)

    @field_validator("domains")
    @classmethod
    def lowercase_domains(cls, value: list[str]) -> list[str]:
        return [domain.lower().strip() for domain in value]


class RateLimitDefaults(StrictModel):
    global_max_rps: float = Field(gt=0)
    per_host_max_rps: float = Field(gt=0)
    burst_size: int = Field(gt=0)
    retry_budget: int = Field(ge=0)
    backoff_base_seconds: float = Field(gt=0)
    backoff_cap_seconds: float = Field(gt=0)
    retry_strategy: Literal["full_jitter"] = "full_jitter"
    require_single_flight: bool = True
    honor_robots_txt: bool = True
    honor_retry_after: bool = True
    user_agent_contact: str = Field(min_length=1)

    @model_validator(mode="after")
    def cap_must_not_be_less_than_base(self) -> "RateLimitDefaults":
        if self.backoff_cap_seconds < self.backoff_base_seconds:
            raise ValueError("backoff cap must be >= base")
        return self


class Ruleset(StrictModel):
    version: str = Field(min_length=1)
    captured_date: date
    source_digest_path: str = Field(min_length=1)
    digest_hash: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    allow_rules: list[Rule] = Field(min_length=1)
    deny_rules: list[Rule] = Field(min_length=1)
    ethics: EthicsRequirements
    acquisition: AcquisitionPolicy
    rate_limit_defaults: RateLimitDefaults

    @model_validator(mode="after")
    def rule_ids_must_be_unique(self) -> "Ruleset":
        ids = [rule.id for rule in self.allow_rules + self.deny_rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


class GateDecision(StrictModel):
    decision: DecisionValue
    rule_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    normalized_target: str | None = None
    digest_hash: str = Field(min_length=64, max_length=64)
    ruleset_version: str = Field(min_length=1)
    audit_id: str = Field(default_factory=lambda: uuid4().hex, min_length=1)
    source_reference: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"
