"""Reward reconciliation against split 05 estimates."""

from __future__ import annotations

from decimal import Decimal

from vrp_hunt.tracking.models import RewardReconciliation, SubmissionRecord
from vrp_hunt.triage import RewardInput, estimate_reward


def reconcile_reward(
    record: SubmissionRecord,
    *,
    reward_input: RewardInput,
    actual_amount: Decimal,
) -> RewardReconciliation:
    estimate = estimate_reward(reward_input)
    delta = actual_amount - estimate.amount
    return RewardReconciliation(
        submission_id=record.submission_id,
        estimated_amount=estimate.amount,
        actual_amount=actual_amount,
        delta=delta,
        gap_flag=delta != Decimal("0"),
        estimate=estimate,
        explanation=(
            f"Actual reward differs from estimated {reward_input.domain_tier}/"
            f"{reward_input.category} amount by {delta}."
        ),
    )
