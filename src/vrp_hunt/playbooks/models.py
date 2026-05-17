"""Models for manual testing playbooks and finding artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset
from vrp_hunt.triage.models import RewardCategory

BugClass = Literal["xss", "csrf", "idor", "xsleak", "oauth", "server_side"]
FindingStatus = Literal["draft", "needs_review", "ready_for_report", "invalid"]
EvidenceKind = Literal["http", "screenshot", "video", "note", "burp", "har", "tool_versions"]


class PlaybookStep(StrictModel):
    title: str = Field(min_length=1)
    instruction: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    stop_if: list[str] = Field(default_factory=list)


class Playbook(StrictModel):
    bug_class: BugClass
    title: str = Field(min_length=1)
    reward_category: RewardCategory
    preconditions: list[str] = Field(min_length=1)
    account_setup: list[str] = Field(min_length=1)
    burp_workflow: list[str] = Field(min_length=1)
    steps: list[PlaybookStep] = Field(min_length=1)
    evidence_to_capture: list[str] = Field(min_length=1)
    non_qualifying_pitfalls: list[str] = Field(min_length=1)
    stop_conditions: list[str] = Field(min_length=1)


class EvidenceItem(StrictModel):
    kind: EvidenceKind
    description: str = Field(min_length=1)
    path_or_ref: str = Field(min_length=1)
    redacted: bool = True


class FindingArtifact(StrictModel):
    finding_id: str = Field(default_factory=lambda: uuid4().hex)
    title: str = Field(min_length=1)
    bug_class: BugClass
    reward_category: RewardCategory
    status: FindingStatus = "draft"
    target: str = Field(min_length=1)
    affected_assets: list[Asset] = Field(default_factory=list)
    preconditions: list[str] = Field(min_length=1)
    impact: str = Field(min_length=1)
    reproduction_steps: list[str] = Field(min_length=1)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    own_account_only: bool = True
    third_party_data_touched: bool = False
    notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("reproduction_steps")
    @classmethod
    def no_empty_steps(cls, value: list[str]) -> list[str]:
        if any(not step.strip() for step in value):
            raise ValueError("reproduction steps cannot be blank")
        return value

    @model_validator(mode="after")
    def enforce_ethics_boundary(self) -> "FindingArtifact":
        if not self.own_account_only:
            raise ValueError("finding must be limited to owned test accounts")
        if self.third_party_data_touched:
            raise ValueError("finding must not touch third-party data")
        return self
