from vrp_hunt.agent import (
    ActionBudget,
    AgentAction,
    AgentObservation,
    AutonomyPolicy,
    BudgetState,
    DryRunRunner,
    RegisteredActionRunner,
    evaluate_action,
)
from vrp_hunt.guardrails import GuardrailGate


def safe_action(**updates: object) -> AgentAction:
    data = {
        "action_type": "passive_recon",
        "target_kind": "url",
        "target": "https://accounts.google.com/",
        "intended_action": "passive_recon",
        "description": "Check cached passive metadata.",
        "sends_traffic": False,
        "request_budget": 0,
    }
    data.update(updates)
    if data["sends_traffic"] and data["request_budget"] == 0:
        data["request_budget"] = 1
    return AgentAction(**data)


def test_policy_allows_safe_non_traffic_action_after_gate() -> None:
    decision = evaluate_action(
        safe_action(),
        policy=AutonomyPolicy(dry_run=True),
        gate=GuardrailGate(),
        budget=ActionBudget(),
        state=BudgetState(),
    )

    assert decision.allowed
    assert decision.gate_decision is not None
    assert decision.gate_decision.allowed


def test_policy_blocks_live_traffic_in_dry_run() -> None:
    decision = evaluate_action(
        safe_action(sends_traffic=True),
        policy=AutonomyPolicy(dry_run=True),
        gate=GuardrailGate(),
        budget=ActionBudget(),
        state=BudgetState(),
    )

    assert not decision.allowed
    assert "dry-run" in decision.reason


def test_policy_blocks_authz_without_human_approval() -> None:
    decision = evaluate_action(
        safe_action(
            action_type="owned_account_authz",
            intended_action="idor_testing",
            sends_traffic=True,
            requires_human_approval=True,
        ),
        policy=AutonomyPolicy(dry_run=False),
        gate=GuardrailGate(),
        budget=ActionBudget(),
        state=BudgetState(),
    )

    assert not decision.allowed
    assert "approval" in decision.reason


def test_policy_blocks_budget_exhaustion() -> None:
    decision = evaluate_action(
        safe_action(),
        policy=AutonomyPolicy(dry_run=False),
        gate=GuardrailGate(),
        budget=ActionBudget(max_actions=1),
        state=BudgetState(actions_run=1),
    )

    assert not decision.allowed
    assert "budget" in decision.reason


def test_registered_runner_executes_only_registered_actions() -> None:
    action = safe_action(action_type="analyze_assets")
    runner = RegisteredActionRunner(
        {
            "analyze_assets": lambda item: AgentObservation(
                action_id=item.action_id,
                success=True,
                notes=["analyzed"],
            )
        }
    )

    observation = runner.run(action)

    assert observation.success
    assert observation.notes == ["analyzed"]


def test_dry_run_runner_never_sends_live_traffic() -> None:
    observation = DryRunRunner().run(safe_action(sends_traffic=True))

    assert observation.success
    assert observation.request_count == 0
    assert "planned only" in observation.notes[0]
