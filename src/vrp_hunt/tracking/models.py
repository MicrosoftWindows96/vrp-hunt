"""Submission tracking models."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Literal
from uuid import uuid4

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.reporting.models import ReportDraft
from vrp_hunt.triage.models import RewardEstimate

SubmissionStatus = Literal[
    "submitted",
    "triaged",
    "rewarded",
    "appealed",
    "closed",
    "duplicate",
    "not_eligible",
]


class StatusEvent(StrictModel):
    status: SubmissionStatus
    changed_at: date
    note: str | None = None


class SubmissionRecord(StrictModel):
    submission_id: str = Field(default_factory=lambda: uuid4().hex, min_length=1)
    report: ReportDraft
    status: SubmissionStatus = "submitted"
    submitted_at: date
    estimated_reward: RewardEstimate | None = None
    actual_reward: Decimal | None = None
    dedupe_notes: str | None = None
    first_reporter_notes: str | None = None
    leaderboard_profile_public: bool = False
    leaderboard_credit_requested: bool = False
    status_history: list[StatusEvent] = Field(default_factory=list)


class SubmissionLog(StrictModel):
    records: list[SubmissionRecord] = Field(default_factory=list)


class RewardReconciliation(StrictModel):
    submission_id: str = Field(min_length=1)
    estimated_amount: Decimal
    actual_amount: Decimal
    delta: Decimal
    gap_flag: bool
    estimate: RewardEstimate
    explanation: str = Field(min_length=1)


class AppealWindow(StrictModel):
    decision_date: date
    current_date: date
    deadline: date
    days_remaining: int
    expired: bool
    warning_due: bool


class AppealDraft(StrictModel):
    submission_id: str = Field(min_length=1)
    deadline: date
    eligible: bool
    new_information: list[str] = Field(min_length=1)
    rules_references: list[str] = Field(min_length=1)
    impact_argument: str = Field(min_length=1)
    draft_text: str = Field(min_length=1)
