from datetime import date
from pathlib import Path

import yaml

from vrp_hunt.guardrails import GuardrailGate, TargetCandidate, audit_decision


ROOT = Path(__file__).resolve().parents[2]


def test_fixture_gate_cases() -> None:
    cases = yaml.safe_load((ROOT / "tests" / "fixtures" / "gate_cases.yaml").read_text())
    gate = GuardrailGate(as_of_date=date(2026, 5, 16))

    for case in cases:
        candidate = TargetCandidate(**case["candidate"])
        decision = gate.decide(candidate)
        assert decision.decision == case["expected_decision"], case["name"]
        assert decision.rule_id == case["expected_rule_id"], case["name"]
        assert audit_decision(candidate, decision).to_dict()["rule_id"] == decision.rule_id


def test_fixture_cases_have_required_fields() -> None:
    cases = yaml.safe_load((ROOT / "tests" / "fixtures" / "gate_cases.yaml").read_text())
    for case in cases:
        assert case["name"]
        assert case["candidate"]
        assert case["expected_decision"] in {"ALLOW", "DENY"}
        assert case["expected_rule_id"]
        assert case["rationale"]
