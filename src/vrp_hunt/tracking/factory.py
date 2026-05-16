"""Submission factory helpers."""

from __future__ import annotations

from datetime import date

from vrp_hunt.reporting.models import ReportDraft
from vrp_hunt.tracking.models import StatusEvent, SubmissionRecord
from vrp_hunt.triage import RewardInput, estimate_reward


def create_submission(
    report: ReportDraft,
    *,
    reward_input: RewardInput,
    submitted_at: date | None = None,
    dedupe_notes: str | None = None,
    first_reporter_notes: str | None = None,
    leaderboard_profile_public: bool = False,
    leaderboard_credit_requested: bool = False,
) -> SubmissionRecord:
    submission_date = submitted_at or date.today()
    return SubmissionRecord(
        report=report,
        submitted_at=submission_date,
        estimated_reward=estimate_reward(reward_input),
        dedupe_notes=dedupe_notes,
        first_reporter_notes=first_reporter_notes,
        leaderboard_profile_public=leaderboard_profile_public,
        leaderboard_credit_requested=leaderboard_credit_requested,
        status_history=[
            StatusEvent(
                status="submitted",
                changed_at=submission_date,
                note="Initial VRP submission recorded.",
            )
        ],
    )
