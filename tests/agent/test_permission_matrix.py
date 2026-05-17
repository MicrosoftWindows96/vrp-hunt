from pathlib import Path

import pytest

from vrp_hunt.agent import (
    OwnedBrowserAccountConfig,
    OwnedObjectCatalog,
    OwnedObjectCatalogItem,
    OwnedObjectPipelineResult,
    OwnedPermissionMatrix,
    OwnedPermissionMatrixPhase,
    build_owned_permission_matrix_template,
    load_owned_permission_matrix,
    run_owned_permission_matrix,
    write_owned_permission_matrix_template,
)


def _catalog() -> OwnedObjectCatalog:
    return OwnedObjectCatalog(
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


def test_permission_matrix_requires_researcher_owned_confirmation() -> None:
    with pytest.raises(ValueError, match="researcher_owned=true"):
        OwnedPermissionMatrix(
            matrix_id="docs-share",
            phases=[
                OwnedPermissionMatrixPhase(
                    phase_id="private",
                    expected_states={
                        "owned-a-private-doc": {
                            "owned-a": "access_granted",
                            "owned-b": "access_denied",
                        }
                    },
                )
            ],
        )


def test_load_permission_matrix_from_yaml(tmp_path: Path) -> None:
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(
        "\n".join(
            [
                "matrix_id: docs-share",
                "researcher_owned: true",
                "phases:",
                "  - phase_id: private",
                "    expected_states:",
                "      owned-a-private-doc:",
                "        owned-a: access_granted",
                "        owned-b: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    matrix = load_owned_permission_matrix(matrix_path)

    assert matrix.matrix_id == "docs-share"
    assert matrix.phases[0].expected_states["owned-a-private-doc"]["owned-b"] == "access_denied"


def test_permission_matrix_template_builds_transition_phases() -> None:
    matrix = build_owned_permission_matrix_template(
        _catalog(),
        matrix_id="docs-share-cycle",
        grantee_accounts=["owned-b"],
    )

    phases = {phase.phase_id: phase for phase in matrix.phases}

    assert list(phases) == [
        "private-baseline",
        "shared-viewer",
        "revoked-after-share",
        "link-viewer-on",
        "link-viewer-off",
        "trashed-or-archived",
    ]
    assert phases["private-baseline"].expected_states["owned-a-private-doc"] == {
        "owned-a": "access_granted",
        "owned-b": "access_denied",
    }
    assert phases["shared-viewer"].expected_states["owned-a-private-doc"] == {
        "owned-a": "access_granted",
        "owned-b": "access_granted",
    }
    assert phases["link-viewer-on"].expected_states["owned-a-private-doc"] == {
        "owned-a": "access_granted",
        "owned-b": "access_granted",
    }


def test_write_permission_matrix_template_round_trips(tmp_path: Path) -> None:
    matrix_path = tmp_path / "matrix.yaml"

    written = write_owned_permission_matrix_template(
        _catalog(),
        matrix_path,
        matrix_id="docs-share-cycle",
        include_trash_phase=False,
    )
    loaded = load_owned_permission_matrix(matrix_path)

    assert written.matrix_id == "docs-share-cycle"
    assert loaded.matrix_id == "docs-share-cycle"
    assert [phase.phase_id for phase in loaded.phases] == [
        "private-baseline",
        "shared-viewer",
        "revoked-after-share",
        "link-viewer-on",
        "link-viewer-off",
    ]


def test_run_permission_matrix_builds_phase_catalogs(tmp_path: Path) -> None:
    matrix = OwnedPermissionMatrix(
        matrix_id="docs-share",
        researcher_owned=True,
        phases=[
            OwnedPermissionMatrixPhase(
                phase_id="private",
                expected_states={
                    "owned-a-private-doc": {
                        "owned-a": "access_granted",
                        "owned-b": "access_denied",
                    }
                },
            ),
            OwnedPermissionMatrixPhase(
                phase_id="shared-viewer",
                operator_setup=["Share the owned doc with owned-b as viewer."],
                expected_states={
                    "owned-a-private-doc": {
                        "owned-a": "access_granted",
                        "owned-b": "access_granted",
                    }
                },
            ),
        ],
    )
    seen_expected: list[dict[str, str]] = []

    def fake_pipeline(catalog, output_dir, **kwargs):  # type: ignore[no-untyped-def]
        seen_expected.append(catalog.objects[0].expected_states)
        return OwnedObjectPipelineResult(
            catalog_id=catalog.catalog_id,
            output_dir=output_dir,
            generated_scenario_count=1,
            total_artifacts=1 if "shared-viewer" in catalog.catalog_id else 0,
            summary_path=output_dir / "pipeline-summary.json",
        )

    result = run_owned_permission_matrix(
        _catalog(),
        matrix,
        tmp_path / "matrix-run",
        researcher_accounts=["owned-a", "owned-b"],
        pipeline_runner=fake_pipeline,
    )

    assert seen_expected == [
        {"owned-a": "access_granted", "owned-b": "access_denied"},
        {"owned-a": "access_granted", "owned-b": "access_granted"},
    ]
    assert result.total_artifacts == 1
    assert result.phase_runs[1].operator_setup == ["Share the owned doc with owned-b as viewer."]
    assert result.summary_path is not None
    assert result.summary_path.exists()


def test_run_permission_matrix_filters_selected_phase(tmp_path: Path) -> None:
    matrix = build_owned_permission_matrix_template(_catalog(), matrix_id="docs-share-cycle")
    seen: list[str] = []

    def fake_pipeline(catalog, output_dir, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(catalog.catalog_id)
        return OwnedObjectPipelineResult(
            catalog_id=catalog.catalog_id,
            output_dir=output_dir,
            generated_scenario_count=1,
            total_artifacts=0,
            summary_path=output_dir / "pipeline-summary.json",
        )

    result = run_owned_permission_matrix(
        _catalog(),
        matrix,
        tmp_path / "matrix-run",
        researcher_accounts=["owned-a", "owned-b"],
        phase_ids=["private-baseline"],
        pipeline_runner=fake_pipeline,
    )

    assert len(result.phase_runs) == 1
    assert result.phase_runs[0].phase_id == "private-baseline"
    assert seen == ["docs-baseline-docs-share-cycle-private-baseline"]


def test_run_permission_matrix_rejects_unknown_object(tmp_path: Path) -> None:
    matrix = OwnedPermissionMatrix(
        matrix_id="docs-share",
        researcher_owned=True,
        phases=[
            OwnedPermissionMatrixPhase(
                phase_id="private",
                expected_states={
                    "missing-doc": {
                        "owned-a": "access_granted",
                        "owned-b": "access_denied",
                    }
                },
            )
        ],
    )

    result = run_owned_permission_matrix(
        _catalog(),
        matrix,
        tmp_path / "matrix-run",
        researcher_accounts=["owned-a", "owned-b"],
        pipeline_runner=lambda *args, **kwargs: pytest.fail("pipeline should not run"),
    )

    assert not result.phase_runs[0].pipeline_summary_path
    assert "unknown objects" in result.errors[0]
