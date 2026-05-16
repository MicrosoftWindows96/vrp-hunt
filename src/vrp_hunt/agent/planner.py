"""AI-pluggable planning for autonomous VRP workflows."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Protocol

from vrp_hunt.agent.models import AgentAction, AgentActionType, AgentPlan, BrainSuggestion
from vrp_hunt.guardrails.models import TargetKind
from vrp_hunt.recon import Asset
from vrp_hunt.triage import BugHypothesis, TriageCandidate, build_triage_queue


class AgentBrain(Protocol):
    def suggest(self, assets: list[Asset]) -> list[BrainSuggestion]:
        """Return structured vulnerability hypotheses for the supplied assets."""
        ...


class StructuredModelClient(Protocol):
    def suggest_hypotheses(self, assets: list[Asset]) -> list[dict[str, Any]]:
        """Return JSON-like structured suggestions from a model provider."""
        ...


class StaticModelClient:
    """Test/demo client for the same structured contract real model clients use."""

    def __init__(self, suggestions: list[dict[str, Any]]) -> None:
        self._suggestions = suggestions

    def suggest_hypotheses(self, assets: list[Asset]) -> list[dict[str, Any]]:
        return self._suggestions


class ModelBrain:
    """Validate structured AI model output into local planning contracts."""

    def __init__(self, client: StructuredModelClient) -> None:
        self._client = client

    def suggest(self, assets: list[Asset]) -> list[BrainSuggestion]:
        return [
            BrainSuggestion(
                bug_class=str(item["bug_class"]),
                category=item["category"],
                confidence=Decimal(str(item["confidence"])),
                reason=str(item["reason"]),
            )
            for item in self._client.suggest_hypotheses(assets)
        ]


class HeuristicBrain:
    """Safe deterministic fallback when no model provider is wired in."""

    def suggest(self, assets: list[Asset]) -> list[BrainSuggestion]:
        suggestions: list[BrainSuggestion] = []
        seen: set[tuple[str, str]] = set()
        for asset in assets:
            text = f"{asset.kind} {asset.value} {asset.parent or ''}".lower()
            for suggestion in _suggestions_for_text(text):
                key = (suggestion.bug_class, suggestion.category)
                if key in seen:
                    continue
                seen.add(key)
                suggestions.append(suggestion)
        if not suggestions:
            suggestions.append(
                BrainSuggestion(
                    bug_class="idor",
                    category="S2b",
                    confidence=Decimal("0.25"),
                    reason="Default authz review for owned-account reachable assets.",
                )
            )
        return suggestions


def build_agent_plan(
    assets: list[Asset],
    *,
    brain: AgentBrain,
    max_actions: int = 10,
) -> AgentPlan:
    suggestions = brain.suggest(assets)
    hypotheses = [
        BugHypothesis(
            bug_class=suggestion.bug_class,
            category=suggestion.category,
            confidence=suggestion.confidence,
        )
        for suggestion in suggestions
    ]
    candidates = build_triage_queue(assets, hypotheses)
    actions = [
        _action_from_candidate(candidate)
        for candidate in candidates[:max_actions]
        if _target_for_asset(candidate.asset) is not None
    ]
    return AgentPlan(actions=actions, notes=[suggestion.reason for suggestion in suggestions])


def build_offline_analysis_plan(
    assets: list[Asset],
    *,
    brain: AgentBrain,
    max_actions: int = 10,
) -> AgentPlan:
    suggestions = brain.suggest(assets)
    actions: list[AgentAction] = []
    for asset in assets[:max_actions]:
        target = _target_for_asset(asset)
        if target is None:
            continue
        actions.append(
            AgentAction(
                action_type="analyze_assets",
                target_kind=_target_kind_for_asset(asset),
                target=target,
                intended_action="triage",
                description=f"Analyze offline asset context for {target}.",
                sends_traffic=False,
                metadata={"asset_kind": asset.kind, "asset_source": asset.source},
            )
        )
    for suggestion in suggestions[: max(0, max_actions - len(actions))]:
        target_asset = assets[0] if assets else None
        if target_asset is None:
            break
        target = _target_for_asset(target_asset)
        if target is None:
            continue
        actions.append(
            AgentAction(
                action_type="plan_test",
                target_kind=_target_kind_for_asset(target_asset),
                target=target,
                intended_action="manual_testing",
                description=f"Plan {suggestion.bug_class} validation using existing playbooks.",
                sends_traffic=False,
                metadata={
                    "bug_class": suggestion.bug_class,
                    "category": suggestion.category,
                    "confidence": str(suggestion.confidence),
                    "reason": suggestion.reason,
                },
            )
        )
    return AgentPlan(actions=actions, notes=[suggestion.reason for suggestion in suggestions])


def _suggestions_for_text(text: str) -> list[BrainSuggestion]:
    suggestions: list[BrainSuggestion] = []
    if any(token in text for token in ("oauth", "redirect_uri", "consent", "scope", "openid")):
        suggestions.append(
            BrainSuggestion(
                bug_class="oauth",
                category="C1b",
                confidence=Decimal("0.65"),
                reason="OAuth or consent-flow indicators are present.",
            )
        )
    if any(token in text for token in ("profile", "account", "user", "object", "record", "api/")):
        suggestions.append(
            BrainSuggestion(
                bug_class="idor",
                category="S2b",
                confidence=Decimal("0.55"),
                reason="Object ownership or account-bound API indicators are present.",
            )
        )
    if any(token in text for token in ("callback", "postmessage", "frame", "cors", "cross-origin")):
        suggestions.append(
            BrainSuggestion(
                bug_class="xsleak",
                category="C1b",
                confidence=Decimal("0.45"),
                reason="Cross-origin observable behavior indicators are present.",
            )
        )
    if any(token in text for token in ("q=", "query", "search", "render", "html")):
        suggestions.append(
            BrainSuggestion(
                bug_class="xss",
                category="C1b",
                confidence=Decimal("0.35"),
                reason="Rendered input indicators are present.",
            )
        )
    if any(token in text for token in ("delete", "update", "settings", "csrf")):
        suggestions.append(
            BrainSuggestion(
                bug_class="csrf",
                category="C1b",
                confidence=Decimal("0.30"),
                reason="State-changing workflow indicators are present.",
            )
        )
    return suggestions


def _action_from_candidate(candidate: TriageCandidate) -> AgentAction:
    target = _target_for_asset(candidate.asset)
    assert target is not None
    action_type = _action_type_for_bug_class(candidate.hypothesis.bug_class)
    return AgentAction(
        action_type=action_type,
        target_kind=_target_kind_for_asset(candidate.asset),
        target=target,
        intended_action=_intended_action_for_bug_class(candidate.hypothesis.bug_class),
        description=f"Evaluate {candidate.hypothesis.bug_class} hypothesis on {target}.",
        sends_traffic=_action_sends_traffic(action_type),
        request_budget=_request_budget_for_action_type(action_type),
        requires_human_approval=_requires_approval_for_action_type(action_type),
        candidate=candidate,
    )


def _target_for_asset(asset: Asset) -> str | None:
    if asset.kind == "host":
        return asset.value
    if asset.kind in {"url", "endpoint", "javascript"} and asset.value.startswith("http"):
        return asset.value
    if asset.parent and asset.parent.startswith("http"):
        return asset.parent
    return None


def _target_kind_for_asset(asset: Asset) -> TargetKind:
    if asset.kind == "host":
        return "host"
    return "url"


def _action_type_for_bug_class(bug_class: str) -> AgentActionType:
    normalized = bug_class.lower()
    if normalized in {"idor", "authz", "authorization"}:
        return "idor_validation"
    if normalized == "csrf":
        return "csrf_validation"
    if normalized == "oauth":
        return "oauth_validation"
    if normalized == "xsleak":
        return "xsleak_validation"
    if normalized == "xss":
        return "xss_validation"
    return "low_volume_probe"


def _action_sends_traffic(action_type: AgentActionType) -> bool:
    return action_type == "low_volume_probe"


def _request_budget_for_action_type(action_type: AgentActionType) -> int:
    return 3 if _action_sends_traffic(action_type) else 0


def _requires_approval_for_action_type(action_type: AgentActionType) -> bool:
    return action_type in {
        "owned_account_authz",
        "state_change_test",
        "idor_validation",
        "csrf_validation",
    }


def _intended_action_for_bug_class(bug_class: str) -> str:
    normalized = bug_class.lower()
    if normalized in {"idor", "authz", "authorization"}:
        return "idor_testing"
    if normalized == "csrf":
        return "csrf_testing"
    if normalized == "oauth":
        return "oauth_testing"
    if normalized == "xsleak":
        return "xsleak_testing"
    if normalized == "xss":
        return "xss_testing"
    return "manual_testing"
