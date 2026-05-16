"""Fail-closed guardrail policy engine."""

from __future__ import annotations

from datetime import date

from vrp_hunt.guardrails.loader import RulesetLoadError, load_ruleset
from vrp_hunt.guardrails.models import GateDecision, Rule, Ruleset, TargetCandidate
from vrp_hunt.guardrails.normalization import (
    NormalizationError,
    NormalizedHost,
    host_matches_domain,
    host_matches_suffix,
    normalize_host,
    normalize_mobile_app,
    normalize_url,
)

SAFE_ACTIONS = {
    "recon",
    "passive_recon",
    "manual_testing",
    "xss_testing",
    "csrf_testing",
    "idor_testing",
    "xsleak_testing",
    "oauth_testing",
    "server_side_testing",
    "triage",
    "reporting",
    "user_enumeration",
}


class GuardrailGate:
    """Evaluate targets before traffic is sent."""

    def __init__(self, ruleset: Ruleset | None = None, *, as_of_date: date | None = None) -> None:
        self._ruleset = ruleset
        self._as_of_date = as_of_date or date.today()
        self._load_error: str | None = None
        if self._ruleset is None:
            try:
                self._ruleset = load_ruleset()
            except RulesetLoadError as exc:
                self._load_error = str(exc)

    def decide(self, candidate: TargetCandidate) -> GateDecision:
        if self._ruleset is None:
            return self._deny_static("deny-ruleset-load-error", self._load_error or "ruleset failed")

        normalized_host: NormalizedHost | None = None
        normalized_target: str | None = None
        try:
            if candidate.kind == "host":
                normalized_host = normalize_host(candidate.raw_target)
                normalized_target = normalized_host.host
            elif candidate.kind == "url":
                normalized_host = normalize_url(candidate.raw_target)
                normalized_target = normalized_host.host
            elif candidate.kind == "mobile_app":
                normalized_target = normalize_mobile_app(candidate.raw_target)
            else:
                return self._deny("deny-unknown-target-kind", "Unknown target kind.", None)
        except NormalizationError as exc:
            return self._deny("deny-invalid-target", str(exc), None)

        ethics_deny = self._ethics_denial(candidate, normalized_target)
        if ethics_deny is not None:
            return ethics_deny

        deny = self._match_deny_rules(candidate, normalized_host, normalized_target)
        if deny is not None:
            return deny

        unsupported_action = self._unsupported_action_denial(candidate, normalized_target)
        if unsupported_action is not None:
            return unsupported_action

        acquisition_deny = self._acquisition_denial(candidate, normalized_host, normalized_target)
        if acquisition_deny is not None:
            return acquisition_deny

        allow = self._match_allow_rules(candidate, normalized_host, normalized_target)
        if allow is not None:
            return allow

        return self._deny("deny-default", "No allow rule matched.", normalized_target)

    def _ethics_denial(self, candidate: TargetCandidate, target: str | None) -> GateDecision | None:
        assert self._ruleset is not None
        ethics = self._ruleset.ethics
        if ethics.require_researcher_owned_account and not candidate.researcher_owned_account:
            return self._deny(
                "deny-missing-owned-account",
                "Researcher-owned test account acknowledgement is required.",
                target,
            )
        if ethics.require_no_third_party_data and candidate.will_access_third_party_data:
            return self._deny(
                "deny-third-party-data",
                "Planned access to third-party data is prohibited.",
                target,
            )
        if ethics.require_legal_acknowledgement and not candidate.legal_acknowledged:
            return self._deny(
                "deny-missing-legal-acknowledgement",
                "Legal and sanctions acknowledgement is required.",
                target,
            )
        return None

    def _unsupported_action_denial(
        self, candidate: TargetCandidate, normalized_target: str | None
    ) -> GateDecision | None:
        assert self._ruleset is not None
        configured_deny_actions = {
            rule.pattern
            for rule in self._ruleset.deny_rules
            if rule.match_kind in {"action", "user_enumeration_without_rate_limit_bypass"}
        }
        known_actions = SAFE_ACTIONS | configured_deny_actions
        if candidate.intended_action not in known_actions:
            return self._deny(
                "deny-unsupported-action",
                "Unsupported intended action is not allowed by the guardrail policy.",
                normalized_target,
            )
        return None

    def _match_deny_rules(
        self,
        candidate: TargetCandidate,
        normalized_host: NormalizedHost | None,
        normalized_target: str | None,
    ) -> GateDecision | None:
        assert self._ruleset is not None
        for rule in self._ruleset.deny_rules:
            if self._deny_rule_matches(rule, candidate, normalized_host):
                return self._deny_from_rule(rule, normalized_target)
        return None

    def _deny_rule_matches(
        self,
        rule: Rule,
        candidate: TargetCandidate,
        normalized_host: NormalizedHost | None,
    ) -> bool:
        if rule.match_kind == "action":
            return candidate.intended_action == rule.pattern
        if rule.match_kind == "host_suffix" and normalized_host is not None:
            return host_matches_suffix(normalized_host, rule.pattern)
        if rule.match_kind == "sandbox_without_sensitive_impact" and normalized_host is not None:
            return host_matches_suffix(normalized_host, rule.pattern) and not candidate.sensitive_data_impact
        if rule.match_kind == "blogspot_owner_js" and normalized_host is not None:
            return host_matches_suffix(normalized_host, rule.pattern) and candidate.owner_supplied_javascript
        if rule.match_kind == "user_enumeration_without_rate_limit_bypass":
            return (
                candidate.intended_action == rule.pattern
                and not candidate.rate_limit_bypass_evidence
            )
        return False

    def _acquisition_denial(
        self,
        candidate: TargetCandidate,
        normalized_host: NormalizedHost | None,
        normalized_target: str | None,
    ) -> GateDecision | None:
        assert self._ruleset is not None
        if normalized_host is None:
            return None
        if not any(host_matches_domain(normalized_host, domain) for domain in self._ruleset.acquisition.domains):
            return None
        if candidate.acquisition_date is None:
            return self._deny(
                "deny-missing-acquisition-date",
                "Acquisition targets require an acquisition date.",
                normalized_target,
            )
        age_days = (self._as_of_date - candidate.acquisition_date).days
        if age_days < self._ruleset.acquisition.blackout_days:
            return self._deny(
                "deny-acquisition-blackout",
                "Acquisition target is inside the 6-month blackout window.",
                normalized_target,
            )
        return None

    def _match_allow_rules(
        self,
        candidate: TargetCandidate,
        normalized_host: NormalizedHost | None,
        normalized_target: str | None,
    ) -> GateDecision | None:
        assert self._ruleset is not None
        for rule in self._ruleset.allow_rules:
            if rule.match_kind == "registrable_domain" and normalized_host is not None:
                if host_matches_domain(normalized_host, rule.pattern):
                    return self._allow_from_rule(rule, normalized_target)
            if rule.match_kind == "acquisition_domain" and normalized_host is not None:
                if host_matches_domain(normalized_host, rule.pattern):
                    return self._allow_from_rule(rule, normalized_target)
            if rule.match_kind == "mobile_publisher" and candidate.kind == "mobile_app":
                publishers = {publisher.strip() for publisher in rule.pattern.split("|")}
                if candidate.context.get("publisher") in publishers:
                    return self._allow_from_rule(rule, normalized_target)
        return None

    def _allow_from_rule(self, rule: Rule, target: str | None) -> GateDecision:
        assert self._ruleset is not None
        return GateDecision(
            decision="ALLOW",
            rule_id=rule.id,
            reason=rule.reason,
            normalized_target=target,
            digest_hash=self._ruleset.digest_hash,
            ruleset_version=self._ruleset.version,
            source_reference=rule.source_reference,
        )

    def _deny_from_rule(self, rule: Rule, target: str | None) -> GateDecision:
        return self._deny(rule.id, rule.reason, target, source_reference=rule.source_reference)

    def _deny(
        self,
        rule_id: str,
        reason: str,
        target: str | None,
        *,
        source_reference: str | None = None,
    ) -> GateDecision:
        assert self._ruleset is not None
        return GateDecision(
            decision="DENY",
            rule_id=rule_id,
            reason=reason,
            normalized_target=target,
            digest_hash=self._ruleset.digest_hash,
            ruleset_version=self._ruleset.version,
            source_reference=source_reference,
        )

    @staticmethod
    def _deny_static(rule_id: str, reason: str) -> GateDecision:
        return GateDecision(
            decision="DENY",
            rule_id=rule_id,
            reason=reason,
            normalized_target=None,
            digest_hash="0" * 64,
            ruleset_version="unloaded",
        )
