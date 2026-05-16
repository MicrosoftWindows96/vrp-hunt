from datetime import date
from decimal import Decimal

import pytest

from tests.reporting.test_linter import complete_report
from vrp_hunt.tracking import (
    appeal_deadline,
    appeal_window_status,
    create_submission,
    draft_appeal,
    reconcile_reward,
)
from vrp_hunt.triage import RewardInput


def test_reconciliation_reuses_reward_calculator() -> None:
    record = create_submission(
        complete_report(),
        reward_input=RewardInput(domain_tier="T2", category="S2b"),
        submitted_at=date(2026, 5, 16),
    )

    reconciliation = reconcile_reward(
        record,
        reward_input=RewardInput(domain_tier="T2", category="S2b"),
        actual_amount=Decimal("10000"),
    )

    assert reconciliation.estimated_amount == Decimal("13337")
    assert reconciliation.actual_amount == Decimal("10000")
    assert reconciliation.delta == Decimal("-3337")
    assert reconciliation.gap_flag is True


def test_appeal_deadline_uses_calendar_month_with_clamp() -> None:
    assert appeal_deadline(date(2026, 1, 31)) == date(2026, 2, 28)


def test_appeal_window_alerts_before_deadline() -> None:
    window = appeal_window_status(
        decision_date=date(2026, 5, 1),
        current_date=date(2026, 5, 25),
        warning_days=7,
    )

    assert window.deadline == date(2026, 6, 1)
    assert window.days_remaining == 7
    assert window.warning_due is True
    assert window.expired is False


def test_appeal_draft_requires_new_information() -> None:
    record = create_submission(
        complete_report(),
        reward_input=RewardInput(domain_tier="T2", category="S2b"),
        submitted_at=date(2026, 5, 16),
    )

    with pytest.raises(ValueError):
        draft_appeal(
            record,
            decision_date=date(2026, 5, 20),
            current_date=date(2026, 5, 25),
            new_information=[],
            rules_references=["Appeal within 1 month; should contain new info."],
            impact_argument="The impact maps to S2b because owned-account PII was exposed.",
        )


def test_appeal_draft_emphasizes_new_info_and_rules() -> None:
    record = create_submission(
        complete_report(),
        reward_input=RewardInput(domain_tier="T2", category="S2b"),
        submitted_at=date(2026, 5, 16),
    )

    appeal = draft_appeal(
        record,
        decision_date=date(2026, 5, 20),
        current_date=date(2026, 5, 25),
        new_information=["Google-side fix confirmed the authz bypass root cause."],
        rules_references=["Panel may reconsider on new information such as revised impact."],
        impact_argument="The new fix detail confirms cross-account access to owned test PII.",
    )

    assert appeal.eligible is True
    assert "New information" in appeal.draft_text
    assert "Panel may reconsider" in appeal.draft_text
    assert appeal.deadline == date(2026, 6, 20)
