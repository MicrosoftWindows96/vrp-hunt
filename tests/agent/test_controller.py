from vrp_hunt.agent import (
    ActionBudget,
    AgentAction,
    AgentObservation,
    AgentPlan,
    AutonomyPolicy,
    AutonomousAgent,
    RegisteredActionRunner,
)
from vrp_hunt.guardrails import GuardrailGate


def test_agent_runs_allowed_actions_and_records_observations() -> None:
    action = AgentAction(
        action_type="passive_recon",
        target_kind="url",
        target="https://accounts.google.com/",
        intended_action="passive_recon",
        description="Analyze passive metadata.",
        sends_traffic=False,
    )
    runner = RegisteredActionRunner(
        {
            "passive_recon": lambda item: AgentObservation(
                action_id=item.action_id,
                success=True,
                notes=["done"],
            )
        }
    )

    result = AutonomousAgent(
        policy=AutonomyPolicy(dry_run=True),
        budget=ActionBudget(),
        gate=GuardrailGate(),
        runner=runner,
    ).run_plan(AgentPlan(actions=[action]))

    assert result.completed_actions == 1
    assert result.blocked_actions == 0
    assert result.observations[0].notes == ["done"]


def test_agent_stops_when_observation_reports_third_party_data() -> None:
    first = AgentAction(
        action_type="passive_recon",
        target_kind="url",
        target="https://accounts.google.com/",
        intended_action="passive_recon",
        description="Analyze passive metadata.",
        sends_traffic=False,
    )
    second = first.model_copy(update={"description": "Should not run"})
    runner = RegisteredActionRunner(
        {
            "passive_recon": lambda item: AgentObservation(
                action_id=item.action_id,
                success=False,
                third_party_data_seen=True,
                notes=["stop"],
            )
        }
    )

    result = AutonomousAgent(
        policy=AutonomyPolicy(dry_run=True),
        budget=ActionBudget(),
        gate=GuardrailGate(),
        runner=runner,
    ).run_plan(AgentPlan(actions=[first, second]))

    assert result.completed_actions == 1
    assert result.stopped
    assert "third-party data" in result.stop_reason
