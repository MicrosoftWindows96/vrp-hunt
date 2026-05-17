"""Owned-object permission phase matrix orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import Field, ValidationError, model_validator

from vrp_hunt.agent.browser_check import BrowserAccessState
from vrp_hunt.agent.derived_http import DerivedHttpCheckError, DerivedHttpMethod
from vrp_hunt.agent.pipeline import (
    OwnedObjectPipelineError,
    OwnedObjectPipelineResult,
    run_owned_object_pipeline,
)
from vrp_hunt.agent.scenarios import OwnedBrowserScenarioError, OwnedObjectCatalog
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.reporting import Platform

MAX_PERMISSION_MATRIX_BYTES = 256_000
MAX_PERMISSION_MATRIX_PHASES = 50
DEFAULT_PERMISSION_PHASES = (
    "private-baseline",
    "shared-viewer",
    "revoked-after-share",
    "link-viewer-on",
    "link-viewer-off",
    "trashed-or-archived",
)


class OwnedPermissionMatrixError(ValueError):
    """Raised when a permission matrix cannot run safely."""


class OwnedPermissionMatrixPhase(StrictModel):
    """Expected owned-object access states after one permission state transition."""

    phase_id: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    operator_setup: list[str] = Field(default_factory=list, max_length=20)
    expected_states: dict[str, dict[str, BrowserAccessState]] = Field(min_length=1)


class OwnedPermissionMatrix(StrictModel):
    """A sequence of owned-object permission states to validate."""

    matrix_id: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    researcher_owned: bool = False
    third_party_data_allowed: bool = False
    phases: list[OwnedPermissionMatrixPhase] = Field(
        min_length=1,
        max_length=MAX_PERMISSION_MATRIX_PHASES,
    )

    @model_validator(mode="after")
    def enforce_matrix_contract(self) -> "OwnedPermissionMatrix":
        if not self.researcher_owned:
            raise ValueError("permission matrix must confirm researcher_owned=true")
        if self.third_party_data_allowed:
            raise ValueError("permission matrix must not allow third-party data")
        phase_ids = [phase.phase_id for phase in self.phases]
        if len(phase_ids) != len(set(phase_ids)):
            raise ValueError("permission matrix phase ids must be unique")
        return self


class OwnedPermissionMatrixPhaseRun(StrictModel):
    phase_id: str = Field(min_length=1)
    output_dir: Path
    phase_catalog_path: Path
    pipeline_summary_path: Path | None = None
    artifact_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    skipped_derived_count: int = Field(ge=0)
    operator_setup: list[str] = Field(default_factory=list)


class OwnedPermissionMatrixResult(StrictModel):
    matrix_id: str = Field(min_length=1)
    catalog_id: str = Field(min_length=1)
    output_dir: Path
    phase_runs: list[OwnedPermissionMatrixPhaseRun] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    total_artifacts: int = Field(ge=0)
    summary_path: Path | None = None


class OwnedObjectPipelineRunner(Protocol):
    def __call__(
        self,
        catalog: OwnedObjectCatalog,
        output_dir: Path,
        *,
        researcher_accounts: list[str],
        yolo: bool,
        expand_derived: bool,
        max_steps: int,
        run_derived: bool,
        derived_method: DerivedHttpMethod,
        derived_max_targets: int,
        derived_max_redirects: int,
        derived_timeout_seconds: float,
        derive_cookies_from_cdp: bool,
        product: str,
        component: str,
        platform: Platform,
        client: str,
        operating_system: str,
        observed_from: str,
    ) -> OwnedObjectPipelineResult:
        """Run one owned-object pipeline phase."""
        ...


def build_owned_permission_matrix_template(
    catalog: OwnedObjectCatalog,
    *,
    matrix_id: str | None = None,
    grantee_accounts: list[str] | None = None,
    include_trash_phase: bool = True,
) -> OwnedPermissionMatrix:
    """Build a safe owned-object sharing transition template from a catalog."""

    selected_grantees = _validated_grantee_accounts(catalog, grantee_accounts)
    phases = [
        OwnedPermissionMatrixPhase(
            phase_id="private-baseline",
            description="Objects are private or only directly accessible to the owner account.",
            operator_setup=[
                "Ensure each listed object is private and contains only researcher-owned test data."
            ],
            expected_states=_private_expected_states(catalog),
        ),
        OwnedPermissionMatrixPhase(
            phase_id="shared-viewer",
            description="Objects are directly shared with the selected owned test accounts as viewer.",
            operator_setup=[
                "Share each listed object with the selected owned grantee account(s) as viewer."
            ],
            expected_states=_direct_share_expected_states(catalog, selected_grantees),
        ),
        OwnedPermissionMatrixPhase(
            phase_id="revoked-after-share",
            description="Direct shares are revoked after the shared-viewer phase.",
            operator_setup=["Remove the direct viewer share from each selected owned grantee account."],
            expected_states=_private_expected_states(catalog),
        ),
        OwnedPermissionMatrixPhase(
            phase_id="link-viewer-on",
            description="Anyone-with-link viewer access is enabled for the owned object.",
            operator_setup=["Enable viewer access by link for each listed object."],
            expected_states=_link_share_expected_states(catalog),
        ),
        OwnedPermissionMatrixPhase(
            phase_id="link-viewer-off",
            description="Anyone-with-link viewer access is disabled after link-viewer-on.",
            operator_setup=["Disable viewer access by link for each listed object."],
            expected_states=_private_expected_states(catalog),
        ),
    ]
    if include_trash_phase:
        phases.append(
            OwnedPermissionMatrixPhase(
                phase_id="trashed-or-archived",
                description="Objects are moved to trash or archived while still owned by the owner account.",
                operator_setup=[
                    "Move each listed object to trash or archive, keeping ownership with the owner account."
                ],
                expected_states=_private_expected_states(catalog),
            )
        )
    return OwnedPermissionMatrix(
        matrix_id=matrix_id or f"{catalog.catalog_id}-permission-matrix",
        description="Generated owned-object permission transition matrix.",
        researcher_owned=True,
        third_party_data_allowed=False,
        phases=phases,
    )


def write_owned_permission_matrix_template(
    catalog: OwnedObjectCatalog,
    output_path: Path,
    *,
    matrix_id: str | None = None,
    grantee_accounts: list[str] | None = None,
    include_trash_phase: bool = True,
) -> OwnedPermissionMatrix:
    """Write a generated permission matrix template to YAML."""

    matrix = build_owned_permission_matrix_template(
        catalog,
        matrix_id=matrix_id,
        grantee_accounts=grantee_accounts,
        include_trash_phase=include_trash_phase,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(matrix.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )
    return matrix


def load_owned_permission_matrix(path: Path) -> OwnedPermissionMatrix:
    """Load an owned-object permission matrix from YAML or JSON."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise OwnedPermissionMatrixError(f"failed to read permission matrix file: {path}") from exc
    if len(data) > MAX_PERMISSION_MATRIX_BYTES:
        raise OwnedPermissionMatrixError(
            f"permission matrix file exceeds {MAX_PERMISSION_MATRIX_BYTES} bytes"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OwnedPermissionMatrixError("permission matrix file must be UTF-8") from exc
    try:
        parsed = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OwnedPermissionMatrixError("permission matrix file is malformed") from exc
    if not isinstance(parsed, dict):
        raise OwnedPermissionMatrixError("permission matrix root must be a mapping")
    try:
        return OwnedPermissionMatrix.model_validate(parsed)
    except ValidationError as exc:
        raise OwnedPermissionMatrixError("permission matrix validation failed") from exc


def run_owned_permission_matrix(
    catalog: OwnedObjectCatalog,
    matrix: OwnedPermissionMatrix,
    output_dir: Path,
    *,
    researcher_accounts: list[str],
    yolo: bool = False,
    expand_derived: bool = True,
    max_steps: int = 50,
    run_derived: bool = True,
    derived_method: DerivedHttpMethod = "HEAD",
    derived_max_targets: int = 25,
    derived_max_redirects: int = 2,
    derived_timeout_seconds: float = 10.0,
    derive_cookies_from_cdp: bool = False,
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "owned-permission-matrix",
    operating_system: str = "research workstation",
    observed_from: str = "owned-permission-matrix",
    phase_ids: list[str] | None = None,
    pipeline_runner: OwnedObjectPipelineRunner | None = None,
) -> OwnedPermissionMatrixResult:
    """Run the owned-object pipeline for each declared permission phase."""

    output_dir.mkdir(parents=True, exist_ok=True)
    active_pipeline_runner = pipeline_runner or run_owned_object_pipeline
    phase_runs: list[OwnedPermissionMatrixPhaseRun] = []
    errors: list[str] = []
    total_artifacts = 0
    phases = _selected_phases(matrix, phase_ids)

    for phase in phases:
        phase_dir = output_dir / "phases" / _slug(phase.phase_id)
        phase_dir.mkdir(parents=True, exist_ok=True)
        phase_catalog_path = phase_dir / "phase-catalog.yaml"
        try:
            phase_catalog = _catalog_for_phase(catalog, matrix, phase)
            phase_catalog_path.write_text(
                yaml.safe_dump(
                    phase_catalog.model_dump(mode="json", exclude_none=True),
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            pipeline_result = active_pipeline_runner(
                phase_catalog,
                phase_dir / "pipeline",
                researcher_accounts=researcher_accounts,
                yolo=yolo,
                expand_derived=expand_derived,
                max_steps=max_steps,
                run_derived=run_derived,
                derived_method=derived_method,
                derived_max_targets=derived_max_targets,
                derived_max_redirects=derived_max_redirects,
                derived_timeout_seconds=derived_timeout_seconds,
                derive_cookies_from_cdp=derive_cookies_from_cdp,
                product=product,
                component=component,
                platform=platform,
                client=client,
                operating_system=operating_system,
                observed_from=observed_from,
            )
        except (
            DerivedHttpCheckError,
            OwnedBrowserScenarioError,
            OwnedObjectPipelineError,
            OwnedPermissionMatrixError,
        ) as exc:
            message = f"{phase.phase_id}: {exc}"
            errors.append(message)
            phase_runs.append(
                OwnedPermissionMatrixPhaseRun(
                    phase_id=phase.phase_id,
                    output_dir=phase_dir,
                    phase_catalog_path=phase_catalog_path,
                    artifact_count=0,
                    error_count=1,
                    skipped_derived_count=0,
                    operator_setup=phase.operator_setup,
                )
            )
            continue

        total_artifacts += pipeline_result.total_artifacts
        errors.extend(f"{phase.phase_id}: {error}" for error in pipeline_result.errors)
        phase_runs.append(
            OwnedPermissionMatrixPhaseRun(
                phase_id=phase.phase_id,
                output_dir=phase_dir,
                phase_catalog_path=phase_catalog_path,
                pipeline_summary_path=pipeline_result.summary_path,
                artifact_count=pipeline_result.total_artifacts,
                error_count=len(pipeline_result.errors),
                skipped_derived_count=len(pipeline_result.skipped_derived),
                operator_setup=phase.operator_setup,
            )
        )

    result = OwnedPermissionMatrixResult(
        matrix_id=matrix.matrix_id,
        catalog_id=catalog.catalog_id,
        output_dir=output_dir,
        phase_runs=phase_runs,
        errors=errors,
        total_artifacts=total_artifacts,
        summary_path=output_dir / "matrix-summary.json",
    )
    (output_dir / "matrix-summary.json").write_text(
        result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def _catalog_for_phase(
    catalog: OwnedObjectCatalog,
    matrix: OwnedPermissionMatrix,
    phase: OwnedPermissionMatrixPhase,
) -> OwnedObjectCatalog:
    object_by_id = {item.object_id: item for item in catalog.objects}
    known_accounts = {account.account_id for account in catalog.accounts}
    unknown_objects = sorted(set(phase.expected_states).difference(object_by_id))
    if unknown_objects:
        raise OwnedPermissionMatrixError(
            f"phase {phase.phase_id} references unknown objects: {', '.join(unknown_objects)}"
        )

    unknown_accounts = sorted(
        {
            account_id
            for expected in phase.expected_states.values()
            for account_id in expected
            if account_id not in known_accounts
        }
    )
    if unknown_accounts:
        raise OwnedPermissionMatrixError(
            f"phase {phase.phase_id} references unknown accounts: {', '.join(unknown_accounts)}"
        )

    phase_items = []
    for item in catalog.objects:
        expected = phase.expected_states.get(item.object_id)
        if expected is None:
            continue
        if item.owner_account_id not in expected:
            raise OwnedPermissionMatrixError(
                f"phase {phase.phase_id} expected states for {item.object_id} "
                "must include the owner account"
            )
        phase_items.append(item.model_copy(update={"expected_states": expected}))
    if not phase_items:
        raise OwnedPermissionMatrixError(f"phase {phase.phase_id} has no runnable objects")

    return catalog.model_copy(
        update={
            "catalog_id": _phase_catalog_id(catalog.catalog_id, matrix.matrix_id, phase.phase_id),
            "description": phase.description or catalog.description,
            "objects": phase_items,
        }
    )


def _selected_phases(
    matrix: OwnedPermissionMatrix,
    phase_ids: list[str] | None,
) -> list[OwnedPermissionMatrixPhase]:
    if not phase_ids:
        return matrix.phases
    selected = set(phase_ids)
    phases = [phase for phase in matrix.phases if phase.phase_id in selected]
    missing = sorted(selected.difference({phase.phase_id for phase in phases}))
    if missing:
        raise OwnedPermissionMatrixError(
            f"permission matrix does not define requested phases: {', '.join(missing)}"
        )
    return phases


def _validated_grantee_accounts(
    catalog: OwnedObjectCatalog,
    grantee_accounts: list[str] | None,
) -> set[str]:
    known_accounts = {account.account_id for account in catalog.accounts}
    if grantee_accounts:
        selected = set(grantee_accounts)
        missing = sorted(selected.difference(known_accounts))
        if missing:
            raise OwnedPermissionMatrixError(f"unknown grantee accounts: {', '.join(missing)}")
        return selected
    owners = {item.owner_account_id for item in catalog.objects}
    return known_accounts.difference(owners)


def _private_expected_states(
    catalog: OwnedObjectCatalog,
) -> dict[str, dict[str, BrowserAccessState]]:
    account_ids = [account.account_id for account in catalog.accounts]
    return {
        item.object_id: {
            account_id: "access_granted" if account_id == item.owner_account_id else "access_denied"
            for account_id in account_ids
        }
        for item in catalog.objects
    }


def _direct_share_expected_states(
    catalog: OwnedObjectCatalog,
    grantee_accounts: set[str],
) -> dict[str, dict[str, BrowserAccessState]]:
    account_ids = [account.account_id for account in catalog.accounts]
    return {
        item.object_id: {
            account_id: (
                "access_granted"
                if account_id == item.owner_account_id or account_id in grantee_accounts
                else "access_denied"
            )
            for account_id in account_ids
        }
        for item in catalog.objects
    }


def _link_share_expected_states(
    catalog: OwnedObjectCatalog,
) -> dict[str, dict[str, BrowserAccessState]]:
    account_ids = [account.account_id for account in catalog.accounts]
    return {
        item.object_id: {account_id: "access_granted" for account_id in account_ids}
        for item in catalog.objects
    }


def _phase_catalog_id(catalog_id: str, matrix_id: str, phase_id: str) -> str:
    return _slug(f"{catalog_id}-{matrix_id}-{phase_id}")[:128]


def _slug(value: str) -> str:
    slug = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value)
    return slug.strip("-._") or "phase"
