from datetime import UTC, datetime

from vrp_hunt.guardrails import GuardrailGate, TargetCandidate, audit_decision


def test_audit_record_redacts_sensitive_context() -> None:
    candidate = TargetCandidate(
        kind="host",
        raw_target="google.com",
        intended_action="recon",
        researcher_owned_account=True,
        will_access_third_party_data=False,
        legal_acknowledged=True,
        context={"Authorization": "Bearer secret", "note": "safe"},
    )
    decision = GuardrailGate().decide(candidate)
    record = audit_decision(candidate, decision, timestamp=datetime(2026, 5, 16, tzinfo=UTC))
    data = record.to_dict()

    assert data["context"]["Authorization"] == "[REDACTED]"
    assert data["context"]["note"] == "safe"
    assert data["digest_hash"] == decision.digest_hash
    assert data["ruleset_version"] == decision.ruleset_version
