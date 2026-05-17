from vrp_hunt.agent import AgentAction, AgentPlan, AutonomyPolicy, approval_required_actions, module_risk_profile


def test_module_risk_profiles_classify_known_actions() -> None:
    assert module_risk_profile("passive_recon").risk_level == "passive"
    assert module_risk_profile("low_volume_probe").risk_level == "safe"
    assert module_risk_profile("idor_validation").risk_level == "active"
    assert module_risk_profile("state_change_test").risk_level == "aggressive"


def test_approval_gate_can_require_actions_by_risk_class() -> None:
    action = AgentAction(
        action_type="xss_validation",
        target_kind="url",
        target="https://www.google.com/search?q=test",
        intended_action="xss_validation",
        description="Review saved reflection evidence.",
    )

    required = approval_required_actions(
        AgentPlan(actions=[action]),
        policy=AutonomyPolicy(approval_required_risk_levels={"active"}),
    )

    assert len(required) == 1
    assert required[0].risk_level == "active"
    assert "risk class" in required[0].reason
