"""Approval gates for risky autonomous actions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import Field

from vrp_hunt.agent.models import AgentAction, AgentPlan, AutonomyPolicy
from vrp_hunt.agent.risk import ModuleRiskLevel, module_risk_profile
from vrp_hunt.guardrails.models import StrictModel

ApprovalMode = Literal["block", "explicit", "prompt", "approve-all"]


class ApprovalRequiredAction(StrictModel):
    index: int = Field(ge=1)
    action_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    intended_action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    description: str = Field(min_length=1)
    sends_traffic: bool
    request_budget: int = Field(ge=0)
    risk_level: ModuleRiskLevel
    reason: str = Field(min_length=1)


class ApprovalGateResult(StrictModel):
    plan: AgentPlan
    required_actions: list[ApprovalRequiredAction] = Field(default_factory=list)
    approved_action_ids: list[str] = Field(default_factory=list)
    prompt_shown: bool = False


class ApprovalGateError(ValueError):
    """Raised when requested approvals are malformed or denied."""


PromptFunc = Callable[[str], str]
RenderFunc = Callable[[str], None]


def apply_approval_gate(
    plan: AgentPlan,
    *,
    policy: AutonomyPolicy,
    mode: ApprovalMode,
    approvals: list[str] | None = None,
    prompt: PromptFunc | None = None,
    render: RenderFunc | None = None,
) -> ApprovalGateResult:
    required = approval_required_actions(plan, policy=policy)
    if not required:
        return ApprovalGateResult(plan=plan)

    approval_tokens = approvals or []
    prompt_shown = False
    if mode == "block":
        return ApprovalGateResult(plan=plan, required_actions=required)
    if mode == "approve-all":
        approved_ids = {item.action_id for item in required}
    elif mode == "explicit":
        approved_ids = _resolve_approval_tokens(approval_tokens, required)
    elif mode == "prompt":
        if prompt is None:
            raise ApprovalGateError("prompt approval mode requires a prompt function")
        if render is not None:
            render(render_approval_prompt(required))
        response = prompt("approval> ")
        prompt_shown = True
        approved_ids = _resolve_prompt_response(response, required)
    else:
        raise ApprovalGateError(f"unsupported approval mode: {mode}")

    updated_actions = [
        action.model_copy(update={"human_approved": True})
        if action.action_id in approved_ids
        else action
        for action in plan.actions
    ]
    return ApprovalGateResult(
        plan=AgentPlan(actions=updated_actions, notes=plan.notes),
        required_actions=required,
        approved_action_ids=sorted(approved_ids),
        prompt_shown=prompt_shown,
    )


def approval_required_actions(
    plan: AgentPlan,
    *,
    policy: AutonomyPolicy,
) -> list[ApprovalRequiredAction]:
    required: list[ApprovalRequiredAction] = []
    for index, action in enumerate(plan.actions, start=1):
        if not _needs_approval(action, policy):
            continue
        required.append(
            ApprovalRequiredAction(
                index=index,
                action_id=action.action_id,
                action_type=action.action_type,
                intended_action=action.intended_action,
                target=action.target,
                description=action.description,
                sends_traffic=action.sends_traffic,
                request_budget=action.request_budget,
                risk_level=module_risk_profile(
                    action.action_type,
                    sends_traffic=action.sends_traffic,
                ).risk_level,
                reason=_approval_reason(action, policy),
            )
        )
    return required


def render_approval_prompt(required: list[ApprovalRequiredAction]) -> str:
    lines = [
        "Risky actions require explicit approval before execution:",
    ]
    for item in required:
        traffic = "traffic" if item.sends_traffic else "no-traffic"
        lines.append(
            f"[{item.index}] {item.action_type} {item.intended_action} "
            f"{traffic} risk={item.risk_level} budget={item.request_budget} target={item.target}"
        )
        lines.append(f"    {item.description}")
        lines.append(f"    reason: {item.reason}")
    lines.append("Approve with one of: APPROVE ALL, APPROVE <index>, APPROVE <action_id>.")
    return "\n".join(lines)


def _needs_approval(action: AgentAction, policy: AutonomyPolicy) -> bool:
    risk = module_risk_profile(action.action_type, sends_traffic=action.sends_traffic).risk_level
    return (
        action.requires_human_approval
        or action.action_type in policy.approval_required_actions
        or risk in policy.approval_required_risk_levels
    ) and not action.human_approved


def _approval_reason(action: AgentAction, policy: AutonomyPolicy) -> str:
    reasons: list[str] = []
    if action.requires_human_approval:
        reasons.append("action marked human-approval required")
    if action.action_type in policy.approval_required_actions:
        reasons.append("action type requires approval by policy")
    risk = module_risk_profile(action.action_type, sends_traffic=action.sends_traffic).risk_level
    if risk in policy.approval_required_risk_levels:
        reasons.append(f"risk class requires approval: {risk}")
    return "; ".join(reasons)


def _resolve_prompt_response(
    response: str,
    required: list[ApprovalRequiredAction],
) -> set[str]:
    normalized = response.strip()
    parts = normalized.split(maxsplit=1)
    if len(parts) == 2 and parts[0].upper() == "APPROVE":
        token = parts[1].strip()
        if token.upper() == "ALL":
            return {item.action_id for item in required}
        return _resolve_approval_tokens([token], required)
    raise ApprovalGateError("approval prompt response must be APPROVE ALL or APPROVE <index|action_id>")


def _resolve_approval_tokens(
    tokens: list[str],
    required: list[ApprovalRequiredAction],
) -> set[str]:
    if not tokens:
        raise ApprovalGateError("explicit approval mode requires at least one --approve-action")
    if any(token.strip().lower() == "all" for token in tokens):
        return {item.action_id for item in required}

    by_id = {item.action_id: item.action_id for item in required}
    by_index = {str(item.index): item.action_id for item in required}
    approved: set[str] = set()
    unknown: list[str] = []
    for token in tokens:
        normalized = token.strip()
        action_id = by_id.get(normalized) or by_index.get(normalized)
        if action_id is None:
            unknown.append(token)
        else:
            approved.add(action_id)
    if unknown:
        raise ApprovalGateError(f"unknown approval action reference: {', '.join(unknown)}")
    return approved
