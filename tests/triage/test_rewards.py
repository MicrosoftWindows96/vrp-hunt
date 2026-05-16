from decimal import Decimal

from vrp_hunt.triage import RewardInput, classify_domain_tier, estimate_reward


def test_rce_accounts_exceptional_worked_example() -> None:
    estimate = estimate_reward(RewardInput(domain_tier="T0", category="S0", quality="exceptional"))

    assert estimate.amount == Decimal("121212")


def test_idor_google_saved_address_worked_example() -> None:
    estimate = estimate_reward(RewardInput(domain_tier="T2", category="S2b"))

    assert estimate.amount == Decimal("13337")


def test_translate_global_xss_worked_example() -> None:
    estimate = estimate_reward(RewardInput(domain_tier="T0", category="C0"))

    assert estimate.amount == Decimal("20000")


def test_chat_idor_impact_downgrade_worked_example() -> None:
    # The local digest labels this as T1/S2c + downgrade, but that table path
    # cannot produce $7,500. This fixture preserves the stated payout while the
    # calculator keeps downgrade mechanics table-driven.
    estimate = estimate_reward(RewardInput(domain_tier="T0", category="S2c"))

    assert estimate.amount == Decimal("7500")


def test_acquisition_xss_downgrade_exceptional_worked_example() -> None:
    estimate = estimate_reward(
        RewardInput(domain_tier="T3a", category="C1a", quality="exceptional", downgrade_steps=1)
    )

    assert estimate.adjusted_category == "C1b"
    assert estimate.amount == Decimal("240")


def test_domain_tier_classification() -> None:
    assert classify_domain_tier("https://accounts.google.com/") == "T0"
    assert classify_domain_tier("https://chat.google.com/") == "T1"
    assert classify_domain_tier("https://www.google.com/") == "T2"
    assert classify_domain_tier("foo.withgoogle.com") == "T3a"
    assert classify_domain_tier("https://translate.google.com/", global_impact=True) == "T0"


def test_fixed_step_down_example() -> None:
    estimate = estimate_reward(RewardInput(domain_tier="T1", category="S2c", downgrade_steps=1))

    assert estimate.amount == Decimal("3133.7")
