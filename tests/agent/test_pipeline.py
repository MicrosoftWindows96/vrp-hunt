from pathlib import Path

from vrp_hunt.agent import (
    DerivedHttpCheckResult,
    DerivedHttpObservation,
    OwnedBrowserAccountConfig,
    OwnedBrowserScenario,
    OwnedBrowserScenarioResult,
    OwnedBrowserScenarioStepResult,
    OwnedObjectCatalog,
    OwnedObjectCatalogItem,
    redact_object_url,
    run_owned_object_pipeline,
)


def _scenario_runner(scenario: OwnedBrowserScenario) -> OwnedBrowserScenarioResult:
    results: list[OwnedBrowserScenarioStepResult] = []
    mismatches = 0
    for step in scenario.steps:
        actual = "access_granted" if step.expected_state == "access_denied" else step.expected_state
        matched = actual == step.expected_state
        if not matched:
            mismatches += 1
        results.append(
            OwnedBrowserScenarioStepResult(
                step_name=step.name,
                account_id=step.account_id,
                checked_url=redact_object_url(step.url),
                current_url_host="docs.google.com",
                current_url_path_hash="abc123",
                expected_state=step.expected_state,
                actual_state=actual,
                matched=matched,
                confidence=0.9,
                matched_signals=[actual],
            )
        )
    return OwnedBrowserScenarioResult(
        scenario_id=scenario.scenario_id,
        completed_steps=len(results),
        mismatches=mismatches,
        errors=0,
        results=results,
    )


def test_owned_object_pipeline_runs_scenarios_derived_and_artifacts(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    catalog = OwnedObjectCatalog(
        catalog_id="docs-baseline",
        researcher_owned=True,
        accounts=[
            OwnedBrowserAccountConfig(
                account_id="owned-a",
                cdp_url="http://127.0.0.1:9222",
            ),
            OwnedBrowserAccountConfig(
                account_id="owned-b",
                cdp_url="http://127.0.0.1:9223",
                cookie_env="OWNED_B_COOKIE",
            ),
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
    seen_cookie: dict[str, str] = {}

    def derived_runner(**kwargs):  # type: ignore[no-untyped-def]
        seen_cookie["value"] = kwargs["cookie_header"]
        return DerivedHttpCheckResult(
            account_id=kwargs["account_id"],
            source_url=redact_object_url(kwargs["owned_object_url"]),
            expected_state=kwargs["expected_state"],
            target_count=1,
            observations=[
                DerivedHttpObservation(
                    target_name="export-pdf",
                    method="HEAD",
                    checked_url="https://docs.google.com/[path:def456]?keys=format",
                    status_code=200,
                    final_host="docs.google.com",
                    state="access_granted_metadata",
                    confidence=0.7,
                    response_body_stored=False,
                    response_body_bytes_read=0,
                )
            ],
            request_count=1,
            high_signal_mismatches=1,
        )

    monkeypatch.setenv("OWNED_B_COOKIE", "SID=secret")

    result = run_owned_object_pipeline(
        catalog,
        tmp_path / "pipeline",
        researcher_accounts=["owned-a", "owned-b"],
        expand_derived=False,
        scenario_runner=_scenario_runner,
        derived_runner=derived_runner,
        component="Docs private object",
    )

    assert seen_cookie["value"] == "SID=secret"
    assert result.generated_scenario_count == 1
    assert result.scenario_runs[0].artifact_count == 1
    assert result.derived_runs[0].artifact_count == 1
    assert result.total_artifacts == 2
    assert result.summary_path is not None
    assert result.summary_path.exists()
    assert "secret" not in result.summary_path.read_text(encoding="utf-8")
    assert (tmp_path / "pipeline" / "findings" / "scenario").exists()
    assert (tmp_path / "pipeline" / "findings" / "derived").exists()


def test_owned_object_pipeline_skips_derived_without_cookie_env(tmp_path: Path) -> None:
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

    result = run_owned_object_pipeline(
        catalog,
        tmp_path / "pipeline",
        researcher_accounts=["owned-a", "owned-b"],
        expand_derived=False,
        scenario_runner=_scenario_runner,
    )

    assert not result.derived_runs
    assert result.skipped_derived == ["owned-a-private-doc:owned-b: no cookie_env configured"]


def test_owned_object_pipeline_reads_missing_cookie_from_cdp_in_memory(tmp_path: Path) -> None:
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
    seen: dict[str, str] = {}

    def cdp_loader(*, cdp_url: str, owned_object_url: str) -> str:
        seen["cdp_url"] = cdp_url
        seen["owned_object_url"] = owned_object_url
        return "SID=secret"

    def derived_runner(**kwargs):  # type: ignore[no-untyped-def]
        seen["cookie_header"] = kwargs["cookie_header"]
        return DerivedHttpCheckResult(
            account_id=kwargs["account_id"],
            source_url=redact_object_url(kwargs["owned_object_url"]),
            expected_state=kwargs["expected_state"],
            target_count=1,
            observations=[
                DerivedHttpObservation(
                    target_name="export-pdf",
                    method="HEAD",
                    checked_url="https://docs.google.com/[path:def456]?keys=format",
                    status_code=403,
                    final_host="docs.google.com",
                    state="access_denied",
                    confidence=0.8,
                    response_body_stored=False,
                    response_body_bytes_read=0,
                )
            ],
            request_count=1,
            high_signal_mismatches=0,
        )

    result = run_owned_object_pipeline(
        catalog,
        tmp_path / "pipeline",
        researcher_accounts=["owned-a", "owned-b"],
        expand_derived=False,
        derive_cookies_from_cdp=True,
        scenario_runner=_scenario_runner,
        derived_runner=derived_runner,
        cdp_cookie_header_loader=cdp_loader,
    )

    assert seen == {
        "cdp_url": "http://127.0.0.1:9223",
        "owned_object_url": "https://docs.google.com/document/d/owned/edit",
        "cookie_header": "SID=secret",
    }
    assert result.derived_runs
    assert result.skipped_derived == []
    assert result.errors == []
    assert result.summary_path is not None
    assert "secret" not in result.summary_path.read_text(encoding="utf-8")
