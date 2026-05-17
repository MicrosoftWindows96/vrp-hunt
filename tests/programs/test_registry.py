from pathlib import Path

import pytest

from vrp_hunt.programs import (
    ProgramRegistryLoadError,
    ProgramScopeEntry,
    diff_program_registries,
    load_program_registry,
    match_program_scope,
)


def test_load_default_program_registry() -> None:
    registry = load_program_registry()

    assert registry.version == "program-registry-2026-05-16"
    assert registry.programs[0].id == "google-alphabet-vrp"
    assert any(entry.id == "google-web" for entry in registry.programs[0].scope)


def test_program_registry_matches_domain_scope() -> None:
    decision = match_program_scope(load_program_registry(), target="https://accounts.google.com/")

    assert decision.decision == "IN_SCOPE"
    assert decision.program_id == "google-alphabet-vrp"
    assert decision.matched_entry_id == "google-web"
    assert decision.reward_eligible
    assert decision.rate_limit is not None


def test_program_registry_exclusions_override_scope() -> None:
    decision = match_program_scope(load_program_registry(), target="foo.appspot.com")

    assert decision.decision == "OUT_OF_SCOPE"
    assert decision.matched_entry_id == "appspot-customer-app"
    assert "Appspot customer apps" in decision.reason


def test_program_registry_matches_mobile_publisher() -> None:
    decision = match_program_scope(
        load_program_registry(),
        target="com.google.android.apps.maps",
        target_kind="mobile_app",
        publisher="Google LLC",
    )

    assert decision.decision == "IN_SCOPE"
    assert decision.matched_entry_id == "google-mobile-publisher"


def test_program_registry_rejects_malformed_yaml(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text("version: [", encoding="utf-8")

    with pytest.raises(ProgramRegistryLoadError):
        load_program_registry(registry_path)


def test_program_registry_rejects_unknown_fields(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        """
version: "test"
programs:
  - id: "test-program"
    name: "Test Program"
    platform: "Test"
    policy_url: "https://example.com"
    captured_date: 2026-05-16
    safe_harbor:
      summary: "Test safely."
      source_reference: "test"
    scope:
      - id: "example"
        kind: "domain"
        value: "example.com"
        source_reference: "test"
    unexpected: true
""",
        encoding="utf-8",
    )

    with pytest.raises(ProgramRegistryLoadError):
        load_program_registry(registry_path)


def test_program_registry_diff_surfaces_fresh_scope_targets() -> None:
    old_registry = load_program_registry()
    old_program = old_registry.programs[0]
    fresh_entry = ProgramScopeEntry(
        id="fresh-google-host",
        kind="exact_host",
        value="fresh.google.com",
        reward_eligible=True,
        notes="Fresh scoped host.",
        source_reference="test",
    )
    new_program = old_program.model_copy(update={"scope": [*old_program.scope, fresh_entry]})
    new_registry = old_registry.model_copy(
        update={"version": "program-registry-2026-05-17", "programs": [new_program]}
    )

    diff = diff_program_registries(old_registry, new_registry)

    assert len(diff.fresh_targets) == 1
    assert diff.fresh_targets[0].entry_id == "fresh-google-host"
    assert diff.fresh_targets[0].value == "fresh.google.com"
    assert any(change.change == "added" and change.entry_type == "scope" for change in diff.changes)


def test_program_registry_diff_does_not_alert_removed_scope() -> None:
    old_registry = load_program_registry()
    old_program = old_registry.programs[0]
    new_program = old_program.model_copy(update={"scope": old_program.scope[1:]})
    new_registry = old_registry.model_copy(
        update={"version": "program-registry-2026-05-17", "programs": [new_program]}
    )

    diff = diff_program_registries(old_registry, new_registry)

    assert not diff.fresh_targets
    assert any(change.change == "removed" and change.entry_type == "scope" for change in diff.changes)
