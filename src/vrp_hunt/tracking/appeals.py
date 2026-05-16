"""Appeal deadline and draft helpers."""

from __future__ import annotations

from calendar import monthrange
from datetime import date

from vrp_hunt.tracking.models import AppealDraft, AppealWindow, SubmissionRecord


def appeal_deadline(decision_date: date) -> date:
    year = decision_date.year
    month = decision_date.month + 1
    if month == 13:
        year += 1
        month = 1
    last_day = monthrange(year, month)[1]
    return date(year, month, min(decision_date.day, last_day))


def appeal_window_status(
    *,
    decision_date: date,
    current_date: date,
    warning_days: int = 7,
) -> AppealWindow:
    deadline = appeal_deadline(decision_date)
    days_remaining = (deadline - current_date).days
    return AppealWindow(
        decision_date=decision_date,
        current_date=current_date,
        deadline=deadline,
        days_remaining=days_remaining,
        expired=days_remaining < 0,
        warning_due=0 <= days_remaining <= warning_days,
    )


def draft_appeal(
    record: SubmissionRecord,
    *,
    decision_date: date,
    current_date: date,
    new_information: list[str],
    rules_references: list[str],
    impact_argument: str,
) -> AppealDraft:
    window = appeal_window_status(decision_date=decision_date, current_date=current_date)
    if window.expired:
        raise ValueError("appeal window has expired")
    if not new_information:
        raise ValueError("appeal requires new information")
    if not rules_references:
        raise ValueError("appeal requires rules or program references")

    draft_text = "\n".join(
        [
            f"Appeal for submission {record.submission_id}",
            "",
            "New information:",
            *_bullets(new_information),
            "",
            "Rules and impact references:",
            *_bullets(rules_references),
            "",
            "Impact argument:",
            impact_argument,
        ]
    )
    return AppealDraft(
        submission_id=record.submission_id,
        deadline=window.deadline,
        eligible=True,
        new_information=new_information,
        rules_references=rules_references,
        impact_argument=impact_argument,
        draft_text=draft_text,
    )


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]
