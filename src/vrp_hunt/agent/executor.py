"""Action runners for autonomous plans."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol

from vrp_hunt.agent.models import AgentAction, AgentActionType, AgentObservation


class ActionRunner(Protocol):
    def run(self, action: AgentAction) -> AgentObservation:
        """Execute one already-approved action."""
        ...


class DryRunRunner:
    def run(self, action: AgentAction) -> AgentObservation:
        return AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=[f"planned only: {action.description}"],
            request_count=0,
        )


class RegisteredActionRunner:
    def __init__(
        self,
        handlers: Mapping[AgentActionType, Callable[[AgentAction], AgentObservation]],
    ) -> None:
        self._handlers = dict(handlers)

    def run(self, action: AgentAction) -> AgentObservation:
        handler = self._handlers.get(action.action_type)
        if handler is None:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=[f"no registered handler for {action.action_type}"],
            )
        return handler(action)
