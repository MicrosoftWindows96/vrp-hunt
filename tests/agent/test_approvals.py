import pytest

from vrp_hunt.agent import (
    AgentAction,
    AgentPlan,
    ApprovalGateError,
    AutonomyPolicy,
    apply_approval_gate,
    approval_required_actions,
    render_approval_prompt,
)


def risky_plan() -> AgentPlan:
    return AgentPlan(
        actions=[
            AgentAction(
                action_type="idor_validation",
                target_kind="url",
                target="https://accounts.google.com/profile",
                intended_action="idor_testing",
                description="Prepare IDOR validation.",
                requires_human_approval=True,
            ),
            AgentAction(
                action_type="xss_validation",
                target_kind="url",
                target="https://accounts.google.com/search?q=test",
                intended_action="xss_testing",
                description="Prepare XSS validation.",
            ),
        ]
    )


def test_approval_required_actions_describe_risky_actions() -> None:
    required = approval_required_actions(risky_plan(), policy=AutonomyPolicy())

    assert len(required) == 1
    assert required[0].index == 1
    assert required[0].action_type == "idor_validation"
    assert "approval" in required[0].reason


def test_block_mode_leaves_risky_action_unapproved() -> None:
    result = apply_approval_gate(
        risky_plan(),
        policy=AutonomyPolicy(),
        mode="block",
    )

    assert result.required_actions
    assert not result.plan.actions[0].human_approved
    assert not result.approved_action_ids


def test_explicit_mode_approves_by_index() -> None:
    result = apply_approval_gate(
        risky_plan(),
        policy=AutonomyPolicy(),
        mode="explicit",
        approvals=["1"],
    )

    assert result.plan.actions[0].human_approved
    assert len(result.approved_action_ids) == 1
    assert not result.plan.actions[1].human_approved


def test_prompt_mode_requires_approve_phrase() -> None:
    rendered: list[str] = []

    result = apply_approval_gate(
        risky_plan(),
        policy=AutonomyPolicy(),
        mode="prompt",
        prompt=lambda _: "APPROVE 1",
        render=rendered.append,
    )

    assert result.prompt_shown
    assert result.plan.actions[0].human_approved
    assert "Risky actions" in rendered[0]


def test_prompt_mode_accepts_case_insensitive_approve_command() -> None:
    result = apply_approval_gate(
        risky_plan(),
        policy=AutonomyPolicy(),
        mode="prompt",
        prompt=lambda _: "approve   1",
    )

    assert result.plan.actions[0].human_approved


def test_prompt_render_lists_risk_context() -> None:
    rendered = render_approval_prompt(approval_required_actions(risky_plan(), policy=AutonomyPolicy()))

    assert "idor_validation" in rendered
    assert "target=https://accounts.google.com/profile" in rendered
    assert "APPROVE ALL" in rendered


def test_approval_gate_rejects_unknown_action_reference() -> None:
    with pytest.raises(ApprovalGateError, match="unknown"):
        apply_approval_gate(
            risky_plan(),
            policy=AutonomyPolicy(),
            mode="explicit",
            approvals=["999"],
        )
