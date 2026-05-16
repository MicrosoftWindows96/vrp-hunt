def test_package_imports() -> None:
    import vrp_hunt
    import vrp_hunt.guardrails

    assert vrp_hunt.__version__
    assert vrp_hunt.guardrails.GuardrailGate


def test_expected_project_paths_exist() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for relative in ("config", "docs", "src/vrp_hunt/guardrails", "tests/fixtures"):
        assert (root / relative).exists()
