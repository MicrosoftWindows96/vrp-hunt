from datetime import date

from hypothesis import given, settings, strategies as st

from vrp_hunt.guardrails import GuardrailGate, TargetCandidate


@given(st.text())
@settings(max_examples=100)
def test_arbitrary_hosts_do_not_raise(raw_target: str) -> None:
    gate = GuardrailGate(as_of_date=date(2026, 5, 16))
    candidate = TargetCandidate(
        kind="host",
        raw_target=raw_target or " ",
        intended_action="recon",
        researcher_owned_account=True,
        will_access_third_party_data=False,
        legal_acknowledged=True,
    )
    decision = gate.decide(candidate)
    assert decision.decision in {"ALLOW", "DENY"}
    if decision.decision == "ALLOW":
        assert decision.normalized_target is not None
        assert decision.normalized_target in {
            "google.com",
            "youtube.com",
            "blogger.com",
            "deepmind.com",
            "waymo.com",
            "wing.com",
            "withgoogle.com",
            "withyoutube.com",
        } or decision.normalized_target.endswith(
            (
                ".google.com",
                ".youtube.com",
                ".blogger.com",
                ".deepmind.com",
                ".waymo.com",
                ".wing.com",
                ".withgoogle.com",
                ".withyoutube.com",
            )
        )
