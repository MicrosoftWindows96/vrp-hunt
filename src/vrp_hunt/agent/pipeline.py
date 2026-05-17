"""One-command owned-object pipeline orchestration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import Field

from vrp_hunt.agent.artifacts import AgentArtifactBundle
from vrp_hunt.agent.browser_check import BrowserAccessState
from vrp_hunt.agent.derived_http import (
    DerivedHttpCheckError,
    DerivedHttpCheckResult,
    DerivedHttpMethod,
    artifact_bundle_from_derived_http_check,
    cookie_header_from_cdp,
    cookie_header_from_env,
    run_derived_http_check,
)
from vrp_hunt.agent.scenarios import (
    MAX_SCENARIO_STEPS,
    OwnedBrowserAccountConfig,
    OwnedBrowserScenario,
    OwnedBrowserScenarioError,
    OwnedBrowserScenarioResult,
    OwnedObjectCatalog,
    artifact_bundle_from_owned_browser_scenario,
    build_owned_browser_scenarios_from_catalog,
    expand_owned_browser_scenario_derived_urls,
    write_generated_owned_browser_scenarios,
)
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.reporting import Platform, render_markdown_report


class OwnedObjectPipelineError(ValueError):
    """Raised when the owned-object pipeline cannot run safely."""


class PipelineScenarioRun(StrictModel):
    object_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    scenario_path: Path
    result_path: Path
    artifact_output_dir: Path
    completed_steps: int = Field(ge=0)
    mismatches: int = Field(ge=0)
    errors: int = Field(ge=0)
    stopped: bool = False
    artifact_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)


class PipelineDerivedRun(StrictModel):
    object_id: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    result_path: Path
    artifact_output_dir: Path
    request_count: int = Field(ge=0)
    high_signal_mismatches: int = Field(ge=0)
    errors: int = Field(ge=0)
    artifact_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)


class OwnedObjectPipelineResult(StrictModel):
    catalog_id: str = Field(min_length=1)
    output_dir: Path
    generated_scenario_count: int = Field(ge=0)
    scenario_runs: list[PipelineScenarioRun] = Field(default_factory=list)
    derived_runs: list[PipelineDerivedRun] = Field(default_factory=list)
    skipped_derived: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    total_artifacts: int = Field(ge=0)
    summary_path: Path | None = None


ScenarioRunner = Callable[[OwnedBrowserScenario], OwnedBrowserScenarioResult]


class DerivedHttpRunner(Protocol):
    def __call__(
        self,
        *,
        account_id: str,
        owned_object_url: str,
        expected_state: BrowserAccessState,
        cookie_header: str,
        confirm_owned_object: bool,
        method: DerivedHttpMethod,
        max_targets: int,
        timeout_seconds: float,
        max_redirects: int,
    ) -> DerivedHttpCheckResult:
        """Run one derived HTTP check."""
        ...


class CdpCookieHeaderLoader(Protocol):
    def __call__(self, *, cdp_url: str, owned_object_url: str) -> str:
        """Read a Cookie header from an already-authenticated local CDP browser."""
        ...


def run_owned_object_pipeline(
    catalog: OwnedObjectCatalog,
    output_dir: Path,
    *,
    researcher_accounts: list[str],
    yolo: bool = False,
    expand_derived: bool = True,
    max_steps: int = MAX_SCENARIO_STEPS,
    run_derived: bool = True,
    derived_method: DerivedHttpMethod = "HEAD",
    derived_max_targets: int = 25,
    derived_max_redirects: int = 2,
    derived_timeout_seconds: float = 10.0,
    derive_cookies_from_cdp: bool = False,
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "owned-object pipeline",
    operating_system: str = "research workstation",
    observed_from: str = "owned-object pipeline",
    scenario_runner: ScenarioRunner | None = None,
    derived_runner: DerivedHttpRunner | None = None,
    cdp_cookie_header_loader: CdpCookieHeaderLoader | None = None,
) -> OwnedObjectPipelineResult:
    """Run scenario, derived HTTP, and artifact conversion steps from one catalog."""

    if max_steps < 1:
        raise OwnedObjectPipelineError("max_steps must be at least 1")
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = write_generated_owned_browser_scenarios(catalog, output_dir / "scenarios")
    scenario_runs: list[PipelineScenarioRun] = []
    derived_runs: list[PipelineDerivedRun] = []
    skipped_derived: list[str] = []
    errors: list[str] = []
    total_artifacts = 0

    scenarios = build_owned_browser_scenarios_from_catalog(catalog)
    scenario_runner = scenario_runner or _default_scenario_runner
    derived_runner = derived_runner or run_derived_http_check
    cdp_cookie_header_loader = cdp_cookie_header_loader or cookie_header_from_cdp
    accounts_by_id = {account.account_id: account for account in catalog.accounts}

    for scenario, generated_record in zip(scenarios, generated.scenarios, strict=True):
        object_id = generated_record.object_id
        scenario_to_run = _prepare_pipeline_scenario(
            scenario,
            expand_derived=expand_derived,
            yolo=yolo,
            max_steps=max_steps,
        )
        run_dir = output_dir / "scenario-runs" / scenario_to_run.scenario_id
        run_dir.mkdir(parents=True, exist_ok=True)
        scenario_path = run_dir / "scenario.yaml"
        _write_scenario_yaml(scenario_to_run, scenario_path)
        try:
            scenario_result = scenario_runner(scenario_to_run)
        except (OwnedBrowserScenarioError, ValueError, OSError) as exc:
            errors.append(f"{scenario_to_run.scenario_id}: scenario run failed: {exc}")
            continue
        result_path = run_dir / "scenario-result.json"
        result_path.write_text(scenario_result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        scenario_bundle = artifact_bundle_from_owned_browser_scenario(
            scenario_to_run,
            scenario_result,
            researcher_accounts=researcher_accounts,
            product=product,
            component=component,
            platform=platform,
            client=client,
            operating_system=operating_system,
            observed_from=observed_from,
        )
        artifact_output_dir = output_dir / "findings" / "scenario" / scenario_to_run.scenario_id
        _write_artifact_bundle_files(artifact_output_dir, scenario_bundle)
        total_artifacts += len(scenario_bundle.artifacts)
        scenario_runs.append(
            PipelineScenarioRun(
                object_id=object_id,
                scenario_id=scenario_to_run.scenario_id,
                scenario_path=scenario_path,
                result_path=result_path,
                artifact_output_dir=artifact_output_dir,
                completed_steps=scenario_result.completed_steps,
                mismatches=scenario_result.mismatches,
                errors=scenario_result.errors,
                stopped=scenario_result.stopped,
                artifact_count=len(scenario_bundle.artifacts),
                skipped_count=len(scenario_bundle.skipped),
            )
        )

    if run_derived:
        for item in catalog.objects:
            for account_id, expected_state in item.expected_states.items():
                if expected_state != "access_denied":
                    continue
                account = accounts_by_id[account_id]
                try:
                    cookie_header, skip_reason = _resolve_derived_cookie_header(
                        account,
                        owned_object_url=item.url,
                        derive_cookies_from_cdp=derive_cookies_from_cdp,
                        cdp_cookie_header_loader=cdp_cookie_header_loader,
                    )
                    if skip_reason is not None:
                        skipped_derived.append(f"{item.object_id}:{account_id}: {skip_reason}")
                        continue
                    assert cookie_header is not None
                    derived_result = derived_runner(
                        account_id=account_id,
                        owned_object_url=item.url,
                        expected_state=expected_state,
                        cookie_header=cookie_header,
                        confirm_owned_object=True,
                        method=derived_method,
                        max_targets=derived_max_targets,
                        timeout_seconds=derived_timeout_seconds,
                        max_redirects=derived_max_redirects,
                    )
                    derived_run = _record_derived_pipeline_result(
                        derived_result,
                        item.object_id,
                        account_id,
                        output_dir=output_dir,
                        researcher_accounts=researcher_accounts,
                        product=product,
                        component=component,
                        platform=platform,
                        client=client,
                        operating_system=operating_system,
                        observed_from=observed_from,
                    )
                    total_artifacts += derived_run.artifact_count
                    derived_runs.append(derived_run)
                except DerivedHttpCheckError as exc:
                    errors.append(f"{item.object_id}:{account_id}: derived HTTP failed: {exc}")

    result = OwnedObjectPipelineResult(
        catalog_id=catalog.catalog_id,
        output_dir=output_dir,
        generated_scenario_count=generated.generated_count,
        scenario_runs=scenario_runs,
        derived_runs=derived_runs,
        skipped_derived=skipped_derived,
        errors=errors,
        total_artifacts=total_artifacts,
        summary_path=output_dir / "pipeline-summary.json",
    )
    (output_dir / "pipeline-summary.json").write_text(
        result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def _default_scenario_runner(scenario: OwnedBrowserScenario) -> OwnedBrowserScenarioResult:
    from vrp_hunt.agent.scenarios import run_owned_browser_scenario

    return run_owned_browser_scenario(scenario)


def _prepare_pipeline_scenario(
    scenario: OwnedBrowserScenario,
    *,
    expand_derived: bool,
    yolo: bool,
    max_steps: int,
) -> OwnedBrowserScenario:
    prepared = scenario
    if expand_derived:
        prepared = expand_owned_browser_scenario_derived_urls(prepared, max_steps=max_steps)
    elif len(prepared.steps) > max_steps:
        raise OwnedObjectPipelineError(f"scenario exceeds max_steps={max_steps}")
    if yolo:
        prepared = prepared.model_copy(update={"stop_on_mismatch": False})
    return prepared


def _resolve_derived_cookie_header(
    account: OwnedBrowserAccountConfig,
    *,
    owned_object_url: str,
    derive_cookies_from_cdp: bool,
    cdp_cookie_header_loader: CdpCookieHeaderLoader,
) -> tuple[str | None, str | None]:
    if account.cookie_env is not None:
        try:
            return cookie_header_from_env(account.cookie_env), None
        except DerivedHttpCheckError as exc:
            if not _is_missing_cookie_env(exc) or not derive_cookies_from_cdp or account.cdp_url is None:
                raise

    if not derive_cookies_from_cdp:
        return None, "no cookie_env configured"
    if account.cdp_url is None:
        return None, "no cookie_env configured and no cdp_url available for in-memory cookie derivation"
    return cdp_cookie_header_loader(cdp_url=account.cdp_url, owned_object_url=owned_object_url), None


def _is_missing_cookie_env(exc: DerivedHttpCheckError) -> bool:
    return str(exc).startswith("cookie env var is not set:")


def _record_derived_pipeline_result(
    derived_result: DerivedHttpCheckResult,
    object_id: str,
    account_id: str,
    *,
    output_dir: Path,
    researcher_accounts: list[str],
    product: str,
    component: str,
    platform: Platform,
    client: str,
    operating_system: str,
    observed_from: str,
) -> PipelineDerivedRun:
    run_dir = output_dir / "derived-runs" / _slug(object_id) / _slug(account_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "derived-http-result.json"
    result_path.write_text(derived_result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    bundle = artifact_bundle_from_derived_http_check(
        derived_result,
        researcher_accounts=researcher_accounts,
        product=product,
        component=component,
        platform=platform,
        client=client,
        operating_system=operating_system,
        observed_from=observed_from,
    )
    artifact_output_dir = output_dir / "findings" / "derived" / _slug(object_id) / _slug(account_id)
    _write_artifact_bundle_files(artifact_output_dir, bundle)
    return PipelineDerivedRun(
        object_id=object_id,
        account_id=account_id,
        result_path=result_path,
        artifact_output_dir=artifact_output_dir,
        request_count=derived_result.request_count,
        high_signal_mismatches=derived_result.high_signal_mismatches,
        errors=derived_result.errors,
        artifact_count=len(bundle.artifacts),
        skipped_count=len(bundle.skipped),
    )


def _write_scenario_yaml(scenario: OwnedBrowserScenario, path: Path) -> None:
    payload = scenario.model_dump(mode="json", exclude_none=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _write_artifact_bundle_files(output_dir: Path, bundle: AgentArtifactBundle) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "artifact-bundle.json").write_text(
        bundle.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    for artifact in bundle.artifacts:
        finding_id = artifact.finding.finding_id
        (output_dir / f"{finding_id}-finding.json").write_text(
            artifact.finding.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / f"{finding_id}-report.json").write_text(
            artifact.report.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / f"{finding_id}-report.md").write_text(
            render_markdown_report(artifact.report),
            encoding="utf-8",
        )


def _slug(value: str) -> str:
    slug = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value)
    return slug.strip("-._")[:80] or "item"
