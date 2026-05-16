"""Google VRP reward table implementation."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import urlsplit

from vrp_hunt.triage.models import DomainTier, QualityLevel, RewardCategory, RewardEstimate, RewardInput

CATEGORY_ORDER: tuple[RewardCategory, ...] = (
    "S0",
    "S1",
    "S2a",
    "S2b",
    "S2c",
    "C0",
    "C1a",
    "C1b",
    "C1c",
)

QUALITY_MULTIPLIERS: dict[QualityLevel, Decimal] = {
    "low": Decimal("0.8"),
    "good": Decimal("1.0"),
    "exceptional": Decimal("1.2"),
}

REWARD_TABLE: dict[RewardCategory, dict[DomainTier, Decimal]] = {
    "S0": {"T0": Decimal("101010"), "T1": Decimal("101010"), "T2": Decimal("75000"), "T3a": Decimal("10000"), "T3b": Decimal("1337")},
    "S1": {"T0": Decimal("75000"), "T1": Decimal("75000"), "T2": Decimal("50000"), "T3a": Decimal("10000"), "T3b": Decimal("1337")},
    "S2a": {"T0": Decimal("50000"), "T1": Decimal("50000"), "T2": Decimal("31337"), "T3a": Decimal("5000"), "T3b": Decimal("500")},
    "S2b": {"T0": Decimal("31337"), "T1": Decimal("31337"), "T2": Decimal("13337"), "T3a": Decimal("2500"), "T3b": Decimal("500")},
    "S2c": {"T0": Decimal("7500"), "T1": Decimal("5000"), "T2": Decimal("3133.7"), "T3a": Decimal("500"), "T3b": Decimal("200")},
    "C0": {"T0": Decimal("20000"), "T1": Decimal("15000"), "T2": Decimal("10000"), "T3a": Decimal("500"), "T3b": Decimal("200")},
    "C1a": {"T0": Decimal("15000"), "T1": Decimal("13337"), "T2": Decimal("7500"), "T3a": Decimal("500"), "T3b": Decimal("200")},
    "C1b": {"T0": Decimal("5000"), "T1": Decimal("5000"), "T2": Decimal("3133.7"), "T3a": Decimal("200"), "T3b": Decimal("100")},
    "C1c": {"T0": Decimal("1337"), "T1": Decimal("1337"), "T2": Decimal("1337"), "T3a": Decimal("100"), "T3b": Decimal("100")},
}


def estimate_reward(input_: RewardInput) -> RewardEstimate:
    adjusted_category = _apply_downgrade(input_.category, input_.downgrade_steps)
    original_base = REWARD_TABLE[input_.category][input_.domain_tier]
    base = _apply_fixed_step_down(original_base, input_.downgrade_steps)
    quality_multiplier = QUALITY_MULTIPLIERS[input_.quality]
    time_multiplier = Decimal("1.75") if input_.time_limited_bonus else Decimal("1.0")
    amount = (base * quality_multiplier * time_multiplier) + input_.novelty_bonus
    amount = _money(amount)
    explanation = (
        f"{input_.domain_tier}/{input_.category}"
        f" -> {adjusted_category}; quality={input_.quality};"
        f" downgrades={input_.downgrade_steps}"
    )
    return RewardEstimate(
        input=input_,
        adjusted_category=adjusted_category,
        base_amount=base,
        quality_multiplier=quality_multiplier,
        time_limited_multiplier=time_multiplier,
        novelty_bonus=input_.novelty_bonus,
        amount=amount,
        explanation=explanation,
    )


def classify_domain_tier(value: str, *, global_impact: bool = False) -> DomainTier:
    host = urlsplit(value).hostname or value
    host = host.lower().strip().rstrip(".")
    if global_impact:
        return "T0"
    if host.endswith(".withgoogle.com") or host == "withgoogle.com":
        return "T3a"
    if host.endswith(".withyoutube.com") or host == "withyoutube.com":
        return "T3a"
    if host in {"accounts.google.com", "admin.google.com", "wallet.google.com"}:
        return "T0"
    if host in {"chat.google.com", "mail.google.com", "drive.google.com"}:
        return "T1"
    if any(host == domain or host.endswith(f".{domain}") for domain in ("google.com", "youtube.com", "blogger.com", "deepmind.com", "waymo.com", "wing.com")):
        return "T2"
    return "T3b"


def _apply_downgrade(category: RewardCategory, steps: int) -> RewardCategory:
    index = CATEGORY_ORDER.index(category)
    return CATEGORY_ORDER[min(index + steps, len(CATEGORY_ORDER) - 1)]


def _apply_fixed_step_down(amount: Decimal, steps: int) -> Decimal:
    ladder = sorted(
        {value for category in REWARD_TABLE.values() for value in category.values()},
        reverse=True,
    )
    current = amount
    for _ in range(steps):
        lower_values = [value for value in ladder if value < current]
        if not lower_values:
            return ladder[-1]
        current = lower_values[0]
    return current


def _money(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP).normalize()
