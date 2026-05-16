"""Rule matching helpers."""

from __future__ import annotations

from vrp_hunt.guardrails.models import Rule, Ruleset


def find_rule(ruleset: Ruleset, rule_id: str) -> Rule | None:
    for rule in ruleset.deny_rules + ruleset.allow_rules:
        if rule.id == rule_id:
            return rule
    return None
