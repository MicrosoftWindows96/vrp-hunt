from decimal import Decimal

from vrp_hunt.agent import HeuristicBrain, ModelBrain, StaticModelClient, build_agent_plan
from vrp_hunt.recon import Asset


def test_heuristic_brain_suggests_oauth_and_idor_hypotheses() -> None:
    assets = [
        Asset(kind="url", value="https://accounts.google.com/o/oauth2/v2/auth", source="test"),
        Asset(kind="endpoint", value="https://accounts.google.com/api/profile/123", source="test"),
    ]

    suggestions = HeuristicBrain().suggest(assets)

    assert any(item.bug_class == "oauth" for item in suggestions)
    assert any(item.bug_class == "idor" for item in suggestions)


def test_model_brain_accepts_structured_ai_suggestions() -> None:
    client = StaticModelClient(
        [
            {
                "bug_class": "xsleak",
                "category": "C1b",
                "confidence": "0.42",
                "reason": "Cross-origin observable behavior likely.",
            }
        ]
    )

    suggestions = ModelBrain(client).suggest(
        [Asset(kind="url", value="https://mail.google.com/u/0/", source="test")]
    )

    assert suggestions[0].bug_class == "xsleak"
    assert suggestions[0].confidence == Decimal("0.42")
    assert suggestions[0].reason == "Cross-origin observable behavior likely."


def test_build_agent_plan_turns_top_candidates_into_actions() -> None:
    assets = [Asset(kind="url", value="https://accounts.google.com/profile", source="test")]

    plan = build_agent_plan(assets, brain=HeuristicBrain(), max_actions=3)

    assert plan.actions
    assert all(action.researcher_owned_account for action in plan.actions)
    assert all(not action.will_access_third_party_data for action in plan.actions)
    assert any(action.intended_action == "idor_testing" for action in plan.actions)


def test_build_agent_plan_uses_named_safe_validation_actions() -> None:
    assets = [
        Asset(
            kind="url",
            value="https://accounts.google.com/profile?callback=cb&q=test&delete=true",
            source="test",
        )
    ]

    plan = build_agent_plan(assets, brain=HeuristicBrain(), max_actions=10)
    action_types = {action.action_type for action in plan.actions}

    assert {
        "idor_validation",
        "xsleak_validation",
        "xss_validation",
        "csrf_validation",
    }.issubset(action_types)
    assert all(
        not action.sends_traffic
        for action in plan.actions
        if action.action_type.endswith("_validation")
    )
