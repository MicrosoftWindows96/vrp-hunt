import pytest
from pydantic import ValidationError

from vrp_hunt.guardrails import RateLimitPolicy


def test_default_rate_limit_policy_validates() -> None:
    policy = RateLimitPolicy()
    data = policy.to_dict()
    assert data["require_single_flight"] is True
    assert data["honor_robots_txt"] is True
    assert data["honor_retry_after"] is True


def test_invalid_rate_limit_values_fail() -> None:
    with pytest.raises(ValidationError):
        RateLimitPolicy(global_max_rps=0)
    with pytest.raises(ValidationError):
        RateLimitPolicy(backoff_base_seconds=10, backoff_cap_seconds=1)
