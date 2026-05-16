"""JSON-compatible audit records for gate decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from vrp_hunt.guardrails.models import GateDecision, StrictModel, TargetCandidate

SENSITIVE_KEY_PARTS = (
    "authorization",
    "body",
    "cookie",
    "credential",
    "key",
    "password",
    "screenshot",
    "secret",
    "token",
)


class AuditRecord(StrictModel):
    timestamp: datetime
    audit_id: str = Field(min_length=1)
    raw_target: str
    normalized_target: str | None
    target_kind: str
    intended_action: str
    decision: str
    rule_id: str
    reason: str
    ruleset_version: str
    digest_hash: str
    source_reference: str | None = None
    context: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def redact_context(context: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in context.items():
        lowered = key.lower()
        if any(part in lowered for part in SENSITIVE_KEY_PARTS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def audit_decision(
    candidate: TargetCandidate,
    decision: GateDecision,
    *,
    timestamp: datetime | None = None,
) -> AuditRecord:
    return AuditRecord(
        timestamp=timestamp or datetime.now(UTC),
        audit_id=decision.audit_id,
        raw_target=candidate.raw_target,
        normalized_target=decision.normalized_target,
        target_kind=candidate.kind,
        intended_action=candidate.intended_action,
        decision=decision.decision,
        rule_id=decision.rule_id,
        reason=decision.reason,
        ruleset_version=decision.ruleset_version,
        digest_hash=decision.digest_hash,
        source_reference=decision.source_reference,
        context=redact_context(candidate.context),
    )
