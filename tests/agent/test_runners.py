from vrp_hunt.agent import AgentAction, build_safe_offline_runner, build_safe_validation_runner


def test_safe_offline_runner_executes_offline_analysis() -> None:
    action = AgentAction(
        action_type="analyze_assets",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="triage",
        description="Analyze asset offline.",
        metadata={"asset_kind": "url"},
    )

    observation = build_safe_offline_runner().run(action)

    assert observation.success
    assert observation.assets[0].kind == "note"
    assert observation.request_count == 0


def test_safe_offline_runner_refuses_traffic_action() -> None:
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="manual_testing",
        description="Would send traffic.",
        sends_traffic=True,
        request_budget=1,
    )

    observation = build_safe_offline_runner().run(action)

    assert not observation.success
    assert "refuses traffic" in observation.notes[0]


def test_safe_validation_runner_has_named_non_traffic_handlers() -> None:
    cases = [
        ("idor_validation", "idor_testing", "IDOR", "owned test accounts"),
        ("oauth_validation", "oauth_testing", "OAuth", "tokens"),
        ("xsleak_validation", "xsleak_testing", "XSLeak", "high-volume"),
        ("xss_validation", "xss_testing", "XSS", "benign marker"),
        ("csrf_validation", "csrf_testing", "CSRF", "single-action"),
    ]
    runner = build_safe_validation_runner()

    for action_type, intended_action, title_fragment, note_fragment in cases:
        action = AgentAction(
            action_type=action_type,
            target_kind="url",
            target="https://accounts.google.com/profile",
            intended_action=intended_action,
            description=f"Prepare {intended_action}.",
        )

        observation = runner.run(action)

        assert observation.success
        assert observation.request_count == 0
        assert title_fragment in observation.notes[0]
        assert any(note_fragment in note for note in observation.notes)


def test_safe_validation_runner_forces_legacy_traffic_actions_to_preparation_only() -> None:
    action = AgentAction(
        action_type="owned_account_authz",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="idor_testing",
        description="Legacy authz validation action.",
        sends_traffic=True,
        request_budget=3,
        requires_human_approval=True,
        human_approved=True,
    )

    observation = build_safe_validation_runner().run(action)

    assert observation.success
    assert observation.request_count == 0
    assert "no validation traffic" in observation.notes[2]
