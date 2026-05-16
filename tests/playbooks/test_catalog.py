from vrp_hunt.playbooks import default_playbooks, get_playbook


def test_every_playbook_has_required_safety_sections() -> None:
    playbooks = default_playbooks()

    assert {playbook.bug_class for playbook in playbooks} == {
        "xss",
        "csrf",
        "idor",
        "xsleak",
        "oauth",
        "server_side",
    }
    for playbook in playbooks:
        combined = " ".join(
            [
                *playbook.account_setup,
                *playbook.non_qualifying_pitfalls,
                *playbook.stop_conditions,
            ]
        ).lower()
        assert "owned" in combined
        assert playbook.non_qualifying_pitfalls
        assert playbook.stop_conditions


def test_specific_non_qualifying_pitfalls_present() -> None:
    assert "sandbox" in " ".join(get_playbook("xss").non_qualifying_pitfalls).lower()
    assert "logout csrf" in " ".join(get_playbook("csrf").non_qualifying_pitfalls).lower()
    assert "non-owned data" in " ".join(get_playbook("idor").stop_conditions).lower()
