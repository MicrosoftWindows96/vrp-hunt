"""Fail-closed guardrails for authorized VRP research."""

from vrp_hunt.guardrails.audit import AuditRecord, audit_decision
from vrp_hunt.guardrails.engine import GuardrailGate
from vrp_hunt.guardrails.loader import load_ruleset
from vrp_hunt.guardrails.models import GateDecision, TargetCandidate
from vrp_hunt.guardrails.rate_limits import RateLimitPolicy

__all__ = [
    "AuditRecord",
    "GateDecision",
    "GuardrailGate",
    "RateLimitPolicy",
    "TargetCandidate",
    "audit_decision",
    "load_ruleset",
]
