from datetime import date

import pytest

from vrp_hunt.guardrails import GuardrailGate, TargetCandidate


@pytest.fixture
def gate() -> GuardrailGate:
    return GuardrailGate(as_of_date=date(2026, 5, 16))


def safe_candidate(**overrides: object) -> TargetCandidate:
    data = {
        "kind": "host",
        "raw_target": "google.com",
        "intended_action": "recon",
        "researcher_owned_account": True,
        "will_access_third_party_data": False,
        "legal_acknowledged": True,
    }
    data.update(overrides)
    return TargetCandidate(**data)


def test_default_no_match_denies(gate: GuardrailGate) -> None:
    decision = gate.decide(safe_candidate(raw_target="example.com"))
    assert decision.decision == "DENY"
    assert decision.rule_id == "deny-default"


def test_allowed_google_host_allows(gate: GuardrailGate) -> None:
    decision = gate.decide(safe_candidate(raw_target="mail.google.com"))
    assert decision.decision == "ALLOW"
    assert decision.rule_id == "allow-google-domain"


def test_unknown_action_denies(gate: GuardrailGate) -> None:
    decision = gate.decide(safe_candidate(intended_action="mystery_action"))
    assert decision.decision == "DENY"
    assert decision.rule_id == "deny-unsupported-action"


@pytest.mark.parametrize(
    ("action", "rule_id"),
    [
        ("url_redirector", "deny-url-redirector"),
        ("logout_csrf", "deny-logout-csrf"),
        ("version_banner_only", "deny-version-banner-only"),
        ("sms_quota_bypass", "deny-sms-quota-bypass"),
        ("dos", "deny-dos"),
        ("account_automation", "deny-account-automation"),
    ],
)
def test_action_deny_rules_override_allow(gate: GuardrailGate, action: str, rule_id: str) -> None:
    decision = gate.decide(safe_candidate(intended_action=action))
    assert decision.decision == "DENY"
    assert decision.rule_id == rule_id


def test_user_enumeration_requires_rate_limit_bypass_evidence(gate: GuardrailGate) -> None:
    denied = gate.decide(safe_candidate(intended_action="user_enumeration"))
    assert denied.rule_id == "deny-user-enumeration-without-rate-limit-bypass"

    allowed = gate.decide(
        safe_candidate(intended_action="user_enumeration", rate_limit_bypass_evidence=True)
    )
    assert allowed.decision == "ALLOW"


def test_acquisition_blackout(gate: GuardrailGate) -> None:
    denied = gate.decide(
        safe_candidate(raw_target="foo.withgoogle.com", acquisition_date=date(2026, 1, 1))
    )
    assert denied.rule_id == "deny-acquisition-blackout"

    allowed = gate.decide(
        safe_candidate(raw_target="foo.withgoogle.com", acquisition_date=date(2025, 1, 1))
    )
    assert allowed.rule_id == "allow-withgoogle-acquisition-domain"


def test_mobile_requires_known_publisher(gate: GuardrailGate) -> None:
    denied = gate.decide(
        TargetCandidate(
            kind="mobile_app",
            raw_target="com.google.SomeApp",
            intended_action="recon",
            researcher_owned_account=True,
            will_access_third_party_data=False,
            legal_acknowledged=True,
            context={"publisher": "Unknown"},
        )
    )
    assert denied.decision == "DENY"

    allowed = gate.decide(
        TargetCandidate(
            kind="mobile_app",
            raw_target="com.google.SomeApp",
            intended_action="recon",
            researcher_owned_account=True,
            will_access_third_party_data=False,
            legal_acknowledged=True,
            context={"publisher": "Google LLC"},
        )
    )
    assert allowed.rule_id == "allow-google-waymo-mobile-app"
