from pathlib import Path
from typing import cast

import pytest

from vrp_hunt.agent import (
    BrowserAccessState,
    OwnedBrowserAccountConfig,
    OwnedBrowserCheckResult,
    OwnedBrowserScenario,
    OwnedBrowserScenarioError,
    OwnedBrowserScenarioStep,
    OwnedObjectCatalog,
    OwnedObjectCatalogItem,
    artifact_bundle_from_owned_browser_scenario,
    build_owned_browser_scenarios_from_catalog,
    expand_owned_browser_scenario_derived_urls,
    expand_owned_object_url_variants,
    load_owned_browser_scenario,
    load_owned_browser_scenario_result,
    load_owned_object_catalog,
    redact_object_url,
    run_owned_browser_scenario,
    write_generated_owned_browser_scenarios,
)


def _result(account_id: str, url: str, state: str) -> OwnedBrowserCheckResult:
    access_state = cast(BrowserAccessState, state)
    return OwnedBrowserCheckResult(
        account_id=account_id,
        checked_url=redact_object_url(url),
        current_url_host="docs.google.com",
        current_url_path_hash="abc123",
        state=access_state,
        confidence=0.9,
        matched_signals=[state],
    )


def test_scenario_requires_researcher_owned_confirmation() -> None:
    with pytest.raises(ValueError, match="researcher_owned=true"):
        OwnedBrowserScenario(
            scenario_id="missing-confirmation",
            accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
            steps=[
                OwnedBrowserScenarioStep(
                    name="check",
                    account_id="owned-b",
                    url="https://docs.google.com/document/d/owned/edit",
                    expected_state="access_denied",
                )
            ],
        )


def test_scenario_rejects_broad_or_unknown_account_steps() -> None:
    with pytest.raises(ValueError, match="broad Drive"):
        OwnedBrowserScenarioStep(
            name="broad",
            account_id="owned-b",
            url="https://drive.google.com/drive/my-drive",
            expected_state="access_denied",
        )

    with pytest.raises(ValueError, match="unknown accounts"):
        OwnedBrowserScenario(
            scenario_id="unknown-account",
            researcher_owned=True,
            accounts=[OwnedBrowserAccountConfig(account_id="owned-a", cdp_url="http://127.0.0.1:9222")],
            steps=[
                OwnedBrowserScenarioStep(
                    name="check",
                    account_id="owned-b",
                    url="https://docs.google.com/document/d/owned/edit",
                    expected_state="access_denied",
                )
            ],
        )


def test_run_scenario_records_mismatch_and_stops() -> None:
    scenario = OwnedBrowserScenario(
        scenario_id="private-doc",
        researcher_owned=True,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
        steps=[
            OwnedBrowserScenarioStep(
                name="owned-b-denied",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/edit",
                expected_state="access_denied",
            ),
            OwnedBrowserScenarioStep(
                name="not-reached",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/preview",
                expected_state="access_denied",
            ),
        ],
    )

    result = run_owned_browser_scenario(
        scenario,
        checker=lambda account, step: _result(account.account_id, step.url, "access_granted"),
    )

    assert result.completed_steps == 1
    assert result.mismatches == 1
    assert result.stopped
    assert result.results[0].checked_url
    assert "owned" not in result.results[0].checked_url


def test_run_scenario_can_continue_after_mismatches() -> None:
    scenario = OwnedBrowserScenario(
        scenario_id="private-doc",
        researcher_owned=True,
        stop_on_mismatch=False,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
        steps=[
            OwnedBrowserScenarioStep(
                name="first",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/edit",
                expected_state="access_denied",
            ),
            OwnedBrowserScenarioStep(
                name="second",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/preview",
                expected_state="access_granted",
            ),
        ],
    )

    states = {"first": "access_granted", "second": "access_granted"}
    result = run_owned_browser_scenario(
        scenario,
        checker=lambda account, step: _result(account.account_id, step.url, states[step.name]),
    )

    assert result.completed_steps == 2
    assert result.mismatches == 1
    assert not result.stopped
    assert [item.matched for item in result.results] == [False, True]


def test_load_owned_browser_scenario_from_yaml(tmp_path: Path) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "scenario_id: docs-private",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "steps:",
                "  - name: denied",
                "    account_id: owned-b",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_state: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    scenario = load_owned_browser_scenario(scenario_path)

    assert scenario.scenario_id == "docs-private"
    assert scenario.steps[0].expected_state == "access_denied"


def test_load_owned_browser_scenario_reports_validation_error(tmp_path: Path) -> None:
    scenario_path = tmp_path / "bad.yaml"
    scenario_path.write_text("scenario_id: bad\nresearcher_owned: false\n", encoding="utf-8")

    with pytest.raises(OwnedBrowserScenarioError, match="scenario validation failed"):
        load_owned_browser_scenario(scenario_path)


def test_expand_owned_object_url_variants_for_docs_and_drive() -> None:
    docs = expand_owned_object_url_variants("https://docs.google.com/document/d/owned/edit")
    drive = expand_owned_object_url_variants("https://drive.google.com/file/d/owned/view")

    assert "https://docs.google.com/document/d/owned/preview" in docs
    assert "https://drive.google.com/file/d/owned/preview" in drive
    assert all("/export" not in item for item in docs)
    assert len(docs) == len(set(docs))


def test_expand_scenario_derived_urls_preserves_expected_state() -> None:
    scenario = OwnedBrowserScenario(
        scenario_id="expand",
        researcher_owned=True,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
        steps=[
            OwnedBrowserScenarioStep(
                name="doc",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/edit",
                expected_state="access_denied",
            )
        ],
    )

    expanded = expand_owned_browser_scenario_derived_urls(scenario)

    assert len(expanded.steps) > 1
    assert all(step.expected_state == "access_denied" for step in expanded.steps)
    assert expanded.steps[0].name.startswith("doc")


def test_owned_object_catalog_builds_one_scenario_per_object() -> None:
    catalog = OwnedObjectCatalog(
        catalog_id="docs-baseline",
        researcher_owned=True,
        accounts=[
            OwnedBrowserAccountConfig(account_id="owned-a", cdp_url="http://127.0.0.1:9222"),
            OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223"),
        ],
        objects=[
            OwnedObjectCatalogItem(
                object_id="owned-a-private-doc",
                product="docs",
                owner_account_id="owned-a",
                url="https://docs.google.com/document/d/owned/edit",
                expected_states={
                    "owned-a": "access_granted",
                    "owned-b": "access_denied",
                },
            )
        ],
    )

    scenarios = build_owned_browser_scenarios_from_catalog(catalog)

    assert len(scenarios) == 1
    assert scenarios[0].scenario_id == "docs-baseline-owned-a-private-doc"
    assert [step.account_id for step in scenarios[0].steps] == ["owned-a", "owned-b"]
    assert [step.expected_state for step in scenarios[0].steps] == [
        "access_granted",
        "access_denied",
    ]


def test_owned_object_catalog_rejects_unknown_expected_account() -> None:
    with pytest.raises(ValueError, match="unknown expected-state accounts"):
        OwnedObjectCatalog(
            catalog_id="docs-baseline",
            researcher_owned=True,
            accounts=[
                OwnedBrowserAccountConfig(account_id="owned-a", cdp_url="http://127.0.0.1:9222")
            ],
            objects=[
                OwnedObjectCatalogItem(
                    object_id="owned-a-private-doc",
                    product="docs",
                    owner_account_id="owned-a",
                    url="https://docs.google.com/document/d/owned/edit",
                    expected_states={
                        "owned-a": "access_granted",
                        "owned-b": "access_denied",
                    },
                )
            ],
        )


def test_load_owned_object_catalog_from_yaml(tmp_path: Path) -> None:
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text(
        "\n".join(
            [
                "catalog_id: docs-baseline",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-a",
                "    cdp_url: http://127.0.0.1:9222",
                "objects:",
                "  - object_id: owned-a-private-doc",
                "    product: docs",
                "    owner_account_id: owned-a",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_states:",
                "      owned-a: access_granted",
            ]
        ),
        encoding="utf-8",
    )

    catalog = load_owned_object_catalog(catalog_path)

    assert catalog.catalog_id == "docs-baseline"
    assert catalog.objects[0].expected_states["owned-a"] == "access_granted"


def test_write_generated_owned_browser_scenarios_writes_index(tmp_path: Path) -> None:
    catalog = OwnedObjectCatalog(
        catalog_id="docs-baseline",
        researcher_owned=True,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-a", cdp_url="http://127.0.0.1:9222")],
        objects=[
            OwnedObjectCatalogItem(
                object_id="owned-a-private-doc",
                product="docs",
                owner_account_id="owned-a",
                url="https://docs.google.com/document/d/owned/edit",
                expected_states={"owned-a": "access_granted"},
            )
        ],
    )

    result = write_generated_owned_browser_scenarios(catalog, tmp_path / "generated")

    assert result.generated_count == 1
    assert result.scenarios[0].path.exists()
    assert (tmp_path / "generated" / "scenario-index.json").exists()
    assert "researcher_owned: true" in result.scenarios[0].path.read_text(encoding="utf-8")


def test_scenario_mismatch_converts_to_finding_artifact() -> None:
    scenario = OwnedBrowserScenario(
        scenario_id="docs-private",
        researcher_owned=True,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
        steps=[
            OwnedBrowserScenarioStep(
                name="owned-b-denied",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/edit",
                expected_state="access_denied",
            )
        ],
    )
    result = run_owned_browser_scenario(
        scenario,
        checker=lambda account, step: _result(account.account_id, step.url, "access_granted"),
    )

    bundle = artifact_bundle_from_owned_browser_scenario(
        scenario,
        result,
        researcher_accounts=["owned-a", "owned-b"],
        component="Docs private object",
    )

    assert len(bundle.artifacts) == 1
    assert bundle.artifacts[0].finding.bug_class == "idor"
    assert bundle.artifacts[0].finding.status == "needs_review"
    assert bundle.artifacts[0].report.target_info.component == "Docs private object"
    assert all(item.redacted for item in bundle.artifacts[0].finding.evidence)


def test_scenario_artifacts_skip_low_signal_mismatches() -> None:
    scenario = OwnedBrowserScenario(
        scenario_id="docs-private",
        researcher_owned=True,
        accounts=[OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")],
        steps=[
            OwnedBrowserScenarioStep(
                name="owned-b-denied",
                account_id="owned-b",
                url="https://docs.google.com/document/d/owned/edit",
                expected_state="access_denied",
            )
        ],
    )
    result = run_owned_browser_scenario(
        scenario,
        checker=lambda account, step: _result(account.account_id, step.url, "login_required"),
    )

    bundle = artifact_bundle_from_owned_browser_scenario(
        scenario,
        result,
        researcher_accounts=["owned-b"],
    )

    assert not bundle.artifacts
    assert "mismatch did not grant access" in bundle.skipped[0]


def test_load_owned_browser_scenario_result_from_json(tmp_path: Path) -> None:
    result_path = tmp_path / "scenario-result.json"
    result_path.write_text(
        run_owned_browser_scenario(
            OwnedBrowserScenario(
                scenario_id="docs-private",
                researcher_owned=True,
                accounts=[
                    OwnedBrowserAccountConfig(account_id="owned-b", cdp_url="http://127.0.0.1:9223")
                ],
                steps=[
                    OwnedBrowserScenarioStep(
                        name="owned-b-denied",
                        account_id="owned-b",
                        url="https://docs.google.com/document/d/owned/edit",
                        expected_state="access_denied",
                    )
                ],
            ),
            checker=lambda account, step: _result(account.account_id, step.url, "access_denied"),
        ).model_dump_json(),
        encoding="utf-8",
    )

    result = load_owned_browser_scenario_result(result_path)

    assert result.scenario_id == "docs-private"
    assert result.results[0].matched
