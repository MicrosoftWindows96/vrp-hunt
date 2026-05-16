"""Autonomous white-hat agent data contracts."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal
from uuid import uuid4

from pydantic import Field, model_validator

from vrp_hunt.guardrails.models import GateDecision, StrictModel, TargetKind
from vrp_hunt.recon import Asset
from vrp_hunt.triage import TriageCandidate
from vrp_hunt.triage.models import RewardCategory

AgentActionType = Literal[
    "analyze_assets",
    "plan_test",
    "passive_recon",
    "low_volume_probe",
    "owned_account_authz",
    "state_change_test",
    "idor_validation",
    "oauth_validation",
    "xsleak_validation",
    "xss_validation",
    "csrf_validation",
    "report_draft",
]


def default_approval_required_actions() -> set[AgentActionType]:
    return {"owned_account_authz", "state_change_test", "idor_validation", "csrf_validation"}


def default_allowed_action_types() -> set[AgentActionType]:
    return {
        "analyze_assets",
        "plan_test",
        "passive_recon",
        "low_volume_probe",
        "owned_account_authz",
        "state_change_test",
        "idor_validation",
        "oauth_validation",
        "xsleak_validation",
        "xss_validation",
        "csrf_validation",
        "report_draft",
    }


class BrainSuggestion(StrictModel):
    bug_class: str = Field(min_length=1)
    category: RewardCategory
    confidence: Decimal = Field(ge=0, le=1)
    reason: str = Field(min_length=1)


class AgentAction(StrictModel):
    action_id: str = Field(default_factory=lambda: uuid4().hex, min_length=1)
    action_type: AgentActionType
    target_kind: TargetKind
    target: str = Field(min_length=1)
    intended_action: str = Field(min_length=1)
    description: str = Field(min_length=1)
    sends_traffic: bool = False
    request_budget: int = Field(default=0, ge=0)
    requires_human_approval: bool = False
    human_approved: bool = False
    researcher_owned_account: bool = True
    will_access_third_party_data: bool = False
    legal_acknowledged: bool = True
    sensitive_data_impact: bool = False
    candidate: TriageCandidate | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def traffic_requires_budget(self) -> "AgentAction":
        if self.sends_traffic and self.request_budget == 0:
            raise ValueError("traffic-sending actions require a request budget")
        return self


class AgentPlan(StrictModel):
    actions: list[AgentAction] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AutonomyPolicy(StrictModel):
    dry_run: bool = True
    require_guardrail: bool = True
    stop_on_third_party_data: bool = True
    approval_required_actions: set[AgentActionType] = Field(
        default_factory=default_approval_required_actions
    )
    allowed_action_types: set[AgentActionType] = Field(
        default_factory=default_allowed_action_types
    )


class ActionBudget(StrictModel):
    max_actions: int = Field(default=25, ge=1)
    max_live_requests: int = Field(default=20, ge=0)
    max_hosts: int = Field(default=10, ge=1)
    max_state_changes: int = Field(default=0, ge=0)


class BudgetState(StrictModel):
    actions_run: int = Field(default=0, ge=0)
    live_requests_used: int = Field(default=0, ge=0)
    hosts_touched: set[str] = Field(default_factory=set)
    state_changes_used: int = Field(default=0, ge=0)


class ActionPolicyDecision(StrictModel):
    action_id: str = Field(min_length=1)
    allowed: bool
    reason: str = Field(min_length=1)
    gate_decision: GateDecision | None = None


class AgentObservation(StrictModel):
    action_id: str = Field(min_length=1)
    success: bool
    notes: list[str] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    request_count: int = Field(default=0, ge=0)
    third_party_data_seen: bool = False


class AgentRunResult(StrictModel):
    decisions: list[ActionPolicyDecision] = Field(default_factory=list)
    observations: list[AgentObservation] = Field(default_factory=list)
    completed_actions: int = 0
    blocked_actions: int = 0
    stopped: bool = False
    stop_reason: str = ""
