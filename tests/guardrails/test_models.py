from datetime import date

import pytest
from pydantic import ValidationError

from vrp_hunt.guardrails.models import RateLimitDefaults, Rule, Ruleset, TargetCandidate


def test_candidate_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TargetCandidate(
            kind="host",
            raw_target="google.com",
            intended_action="recon",
            unexpected=True,
        )


def test_candidate_normalizes_action() -> None:
    candidate = TargetCandidate(
        kind="host",
        raw_target="google.com",
        intended_action="High Volume Scanning",
    )
    assert candidate.intended_action == "high_volume_scanning"


def test_ruleset_rejects_duplicate_rule_ids() -> None:
    rule = Rule(
        id="duplicate-rule",
        match_kind="registrable_domain",
        pattern="google.com",
        reason="reason",
        source_reference="source",
    )
    with pytest.raises(ValidationError):
        Ruleset(
            version="v",
            captured_date=date(2026, 5, 16),
            source_digest_path="digest.md",
            digest_hash="a" * 64,
            allow_rules=[rule],
            deny_rules=[rule],
            ethics={},
            acquisition={"blackout_days": 183, "domains": ["withgoogle.com"]},
            rate_limit_defaults=RateLimitDefaults(user_agent_contact="contact"),
        )
