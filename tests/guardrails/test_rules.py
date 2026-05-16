from vrp_hunt.guardrails.loader import load_ruleset
from vrp_hunt.guardrails.rules import find_rule


def test_find_rule_returns_allow_or_deny_rule() -> None:
    ruleset = load_ruleset()

    assert find_rule(ruleset, "allow-google-domain") is not None
    assert find_rule(ruleset, "deny-dos") is not None
    assert find_rule(ruleset, "missing-rule") is None
