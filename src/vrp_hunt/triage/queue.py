"""Build deterministic testing queues from recon assets."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

from vrp_hunt.recon import Asset
from vrp_hunt.triage.models import BugHypothesis, RewardInput, TriageCandidate
from vrp_hunt.triage.rewards import classify_domain_tier, estimate_reward


def build_triage_queue(
    assets: list[Asset],
    hypotheses: list[BugHypothesis],
    *,
    global_impact_assets: set[str] | None = None,
) -> list[TriageCandidate]:
    global_impact_assets = global_impact_assets or set()
    candidates: list[TriageCandidate] = []
    for asset in assets:
        tier = classify_domain_tier(asset.value, global_impact=asset.value in global_impact_assets)
        for hypothesis in hypotheses:
            reward = estimate_reward(
                RewardInput(
                    domain_tier=tier,
                    category=hypothesis.category,
                    quality=hypothesis.quality,
                    downgrade_steps=hypothesis.downgrade_steps,
                    novelty_bonus=hypothesis.novelty_bonus,
                    time_limited_bonus=hypothesis.time_limited_bonus,
                )
            )
            expected_value = (reward.amount * hypothesis.confidence).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            ).normalize()
            candidates.append(
                TriageCandidate(
                    asset=asset,
                    hypothesis=hypothesis,
                    reward=reward,
                    expected_value=expected_value,
                    rank_reason=f"{tier}/{hypothesis.category} confidence={hypothesis.confidence}",
                )
            )
    return sorted(
        candidates,
        key=lambda candidate: (
            -candidate.expected_value,
            candidate.asset.value,
            candidate.hypothesis.bug_class,
        ),
    )
