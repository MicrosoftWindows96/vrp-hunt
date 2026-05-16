"""Autonomous agent controller."""

from __future__ import annotations

from vrp_hunt.agent.executor import ActionRunner, DryRunRunner
from vrp_hunt.agent.models import (
    ActionBudget,
    AgentPlan,
    AgentRunResult,
    AutonomyPolicy,
    BudgetState,
)
from vrp_hunt.agent.policy import apply_budget, evaluate_action
from vrp_hunt.guardrails import GuardrailGate


class AutonomousAgent:
    def __init__(
        self,
        *,
        policy: AutonomyPolicy | None = None,
        budget: ActionBudget | None = None,
        gate: GuardrailGate | None = None,
        runner: ActionRunner | None = None,
    ) -> None:
        self.policy = policy or AutonomyPolicy()
        self.budget = budget or ActionBudget()
        self.gate = gate or GuardrailGate()
        self.runner = runner or DryRunRunner()

    def run_plan(self, plan: AgentPlan) -> AgentRunResult:
        state = BudgetState()
        result = AgentRunResult()

        for action in plan.actions:
            decision = evaluate_action(
                action,
                policy=self.policy,
                gate=self.gate,
                budget=self.budget,
                state=state,
            )
            result.decisions.append(decision)
            if not decision.allowed:
                result.blocked_actions += 1
                continue

            observation = self.runner.run(action)
            result.observations.append(observation)
            result.completed_actions += 1
            state = apply_budget(action, state)

            if self.policy.stop_on_third_party_data and observation.third_party_data_seen:
                result.stopped = True
                result.stop_reason = "third-party data observed; stopping autonomous run"
                break

        return result
