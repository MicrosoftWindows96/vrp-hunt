"""Typed rate-limit and politeness contract for later traffic-sending units."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from vrp_hunt.guardrails.models import RateLimitDefaults, StrictModel


class RateLimitPolicy(StrictModel):
    global_max_rps: float = Field(default=0.5, gt=0)
    per_host_max_rps: float = Field(default=0.2, gt=0)
    burst_size: int = Field(default=1, gt=0)
    retry_budget: int = Field(default=3, ge=0)
    backoff_base_seconds: float = Field(default=1.0, gt=0)
    backoff_cap_seconds: float = Field(default=60.0, gt=0)
    retry_strategy: Literal["full_jitter"] = "full_jitter"
    require_single_flight: bool = True
    honor_robots_txt: bool = True
    honor_retry_after: bool = True
    user_agent_contact: str = Field(default="set-contact-before-live-traffic", min_length=1)

    @model_validator(mode="after")
    def cap_must_not_be_less_than_base(self) -> "RateLimitPolicy":
        if self.backoff_cap_seconds < self.backoff_base_seconds:
            raise ValueError("backoff cap must be >= base")
        return self

    @classmethod
    def from_defaults(cls, defaults: RateLimitDefaults) -> "RateLimitPolicy":
        return cls(**defaults.model_dump())

    def to_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")
