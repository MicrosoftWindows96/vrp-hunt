"""Autonomy policy evaluation."""

from __future__ import annotations

from urllib.parse import urlparse

from vrp_hunt.agent.models import (
    ActionBudget,
    ActionPolicyDecision,
    AgentAction,
    AutonomyPolicy,
    BudgetState,
)
from vrp_hunt.guardrails import GuardrailGate, TargetCandidate


def evaluate_action(
    action: AgentAction,
    *,
    policy: AutonomyPolicy,
    gate: GuardrailGate,
    budget: ActionBudget,
    state: BudgetState,
) -> ActionPolicyDecision:
    if action.action_type not in policy.allowed_action_types:
        return _blocked(action, "action type is not allowed by autonomy policy")
    if state.actions_run >= budget.max_actions:
        return _blocked(action, "action budget exhausted")
    if action.sends_traffic and policy.dry_run:
        return _blocked(action, "traffic-sending action blocked in dry-run mode")
    if action.sends_traffic and state.live_requests_used + action.request_budget > budget.max_live_requests:
        return _blocked(action, "live request budget exhausted")
    if _host_count_after(action, state) > budget.max_hosts:
        return _blocked(action, "host budget exhausted")
    if (
        action.action_type in {"state_change_test", "csrf_validation"}
        and state.state_changes_used >= budget.max_state_changes
    ):
        return _blocked(action, "state-change budget exhausted")
    if (
        action.action_type in policy.approval_required_actions
        or action.requires_human_approval
    ) and not action.human_approved:
        return _blocked(action, "human approval required before this action")

    gate_decision = None
    if policy.require_guardrail:
        gate_decision = gate.decide(
            TargetCandidate(
                kind=action.target_kind,
                raw_target=action.target,
                intended_action=action.intended_action,
                researcher_owned_account=action.researcher_owned_account,
                will_access_third_party_data=action.will_access_third_party_data,
                legal_acknowledged=action.legal_acknowledged,
                sensitive_data_impact=action.sensitive_data_impact,
                context=action.metadata,
            )
        )
        if not gate_decision.allowed:
            return ActionPolicyDecision(
                action_id=action.action_id,
                allowed=False,
                reason=f"guardrail denied action: {gate_decision.reason}",
                gate_decision=gate_decision,
            )

    return ActionPolicyDecision(
        action_id=action.action_id,
        allowed=True,
        reason="allowed",
        gate_decision=gate_decision,
    )


def apply_budget(action: AgentAction, state: BudgetState) -> BudgetState:
    host = _host_for_action(action)
    hosts = set(state.hosts_touched)
    if host:
        hosts.add(host)
    return BudgetState(
        actions_run=state.actions_run + 1,
        live_requests_used=state.live_requests_used + action.request_budget,
        hosts_touched=hosts,
        state_changes_used=(
            state.state_changes_used + 1
            if action.action_type in {"state_change_test", "csrf_validation"}
            else state.state_changes_used
        ),
    )


def _blocked(action: AgentAction, reason: str) -> ActionPolicyDecision:
    return ActionPolicyDecision(action_id=action.action_id, allowed=False, reason=reason)


def _host_count_after(action: AgentAction, state: BudgetState) -> int:
    host = _host_for_action(action)
    if not host:
        return len(state.hosts_touched)
    return len({*state.hosts_touched, host})


def _host_for_action(action: AgentAction) -> str | None:
    if action.target_kind == "host":
        return action.target.lower()
    parsed = urlparse(action.target)
    return parsed.hostname.lower() if parsed.hostname else None
