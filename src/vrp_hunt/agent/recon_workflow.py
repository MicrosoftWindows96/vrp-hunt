"""Declarative YAML workflows for approved recon-depth runs."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from vrp_hunt.agent.recon_depth import (
    ReconDepthActionExecutor,
    ReconDepthError,
    ReconDepthProfile,
    ReconDepthResult,
    run_recon_depth,
)
from vrp_hunt.guardrails.models import StrictModel

MAX_RECON_WORKFLOW_BYTES = 256_000
ReconWorkflowStepKind = Literal["recon_depth"]


class ReconWorkflowError(ValueError):
    """Raised when a recon workflow cannot be loaded or run safely."""


class ReconWorkflowDefaults(StrictModel):
    profile: ReconDepthProfile = "balanced"
    max_hosts: int = Field(default=25, ge=1)
    max_urls: int = Field(default=25, ge=1)
    rate_limit_per_minute: int = Field(default=5, ge=1)
    katana_depth: int = Field(default=1, ge=1)
    katana_js_crawl: bool = False
    katana_known_files: str | None = None
    katana_crawl_duration_seconds: int = Field(default=30, ge=1)
    nuclei_templates: list[str] = Field(default_factory=list)
    nuclei_tags: list[str] = Field(default_factory=list)
    nuclei_severity: list[str] = Field(default_factory=list)
    nuclei_rate_limit_per_second: int = Field(default=1, ge=1)
    max_validation_actions: int = Field(default=20, ge=0)


class ReconWorkflowStep(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    kind: ReconWorkflowStepKind = "recon_depth"
    domain: str = Field(min_length=1, max_length=253)
    output_dir: Path | None = None
    enabled: bool = True
    profile: ReconDepthProfile | None = None
    max_hosts: int | None = Field(default=None, ge=1)
    max_urls: int | None = Field(default=None, ge=1)
    rate_limit_per_minute: int | None = Field(default=None, ge=1)
    katana_depth: int | None = Field(default=None, ge=1)
    katana_js_crawl: bool | None = None
    katana_known_files: str | None = None
    katana_crawl_duration_seconds: int | None = Field(default=None, ge=1)
    nuclei_templates: list[str] | None = None
    nuclei_tags: list[str] | None = None
    nuclei_severity: list[str] | None = None
    nuclei_rate_limit_per_second: int | None = Field(default=None, ge=1)
    max_validation_actions: int | None = Field(default=None, ge=0)

    @field_validator("output_dir", mode="before")
    @classmethod
    def parse_output_dir(cls, value: object) -> object:
        if isinstance(value, str):
            return Path(value)
        return value


class ReconWorkflow(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    output_dir: Path
    defaults: ReconWorkflowDefaults = Field(default_factory=ReconWorkflowDefaults)
    steps: list[ReconWorkflowStep] = Field(min_length=1)

    @field_validator("output_dir", mode="before")
    @classmethod
    def parse_output_dir(cls, value: object) -> object:
        if isinstance(value, str):
            return Path(value)
        return value

    @model_validator(mode="after")
    def step_ids_must_be_unique(self) -> "ReconWorkflow":
        step_ids = [step.id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("workflow step ids must be unique")
        return self


class ReconWorkflowStepRun(StrictModel):
    step_id: str = Field(min_length=1)
    kind: ReconWorkflowStepKind
    enabled: bool
    skipped: bool = False
    output_dir: Path | None = None
    result: ReconDepthResult | None = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ReconWorkflowResult(StrictModel):
    workflow_name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    output_dir: Path
    step_runs: list[ReconWorkflowStepRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    summary_path: Path | None = None


def load_recon_workflow(path: str | Path) -> ReconWorkflow:
    workflow_path = Path(path)
    try:
        data = workflow_path.read_bytes()
    except OSError as exc:
        raise ReconWorkflowError(f"failed to read recon workflow: {workflow_path}") from exc
    if len(data) > MAX_RECON_WORKFLOW_BYTES:
        raise ReconWorkflowError(f"recon workflow exceeds size limit: {workflow_path}")
    try:
        parsed = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ReconWorkflowError("recon workflow is malformed") from exc
    if not isinstance(parsed, dict):
        raise ReconWorkflowError("recon workflow root must be a mapping")
    try:
        return ReconWorkflow.model_validate(parsed)
    except ValidationError as exc:
        raise ReconWorkflowError("recon workflow validation failed") from exc


def run_recon_workflow(
    workflow: ReconWorkflow,
    *,
    action_executor: ReconDepthActionExecutor,
) -> ReconWorkflowResult:
    output_dir = workflow.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    step_runs: list[ReconWorkflowStepRun] = []
    warnings: list[str] = []
    errors: list[str] = []

    for step in workflow.steps:
        step_output_dir = _step_output_dir(workflow.output_dir, step)
        if not step.enabled:
            step_runs.append(
                ReconWorkflowStepRun(
                    step_id=step.id,
                    kind=step.kind,
                    enabled=False,
                    skipped=True,
                    output_dir=step_output_dir,
                    warnings=["step disabled"],
                )
            )
            continue
        try:
            result = _run_recon_depth_step(
                step,
                workflow.defaults,
                output_dir=step_output_dir,
                action_executor=action_executor,
            )
        except ReconDepthError as exc:
            message = f"{step.id}: {exc}"
            errors.append(message)
            step_runs.append(
                ReconWorkflowStepRun(
                    step_id=step.id,
                    kind=step.kind,
                    enabled=True,
                    output_dir=step_output_dir,
                    errors=[message],
                )
            )
            continue
        warnings.extend(f"{step.id}: {warning}" for warning in result.warnings)
        errors.extend(f"{step.id}: {error}" for error in result.errors)
        step_runs.append(
            ReconWorkflowStepRun(
                step_id=step.id,
                kind=step.kind,
                enabled=True,
                output_dir=step_output_dir,
                result=result,
                warnings=result.warnings,
                errors=result.errors,
            )
        )

    workflow_result = ReconWorkflowResult(
        workflow_name=workflow.name,
        version=workflow.version,
        output_dir=workflow.output_dir,
        step_runs=step_runs,
        warnings=warnings,
        errors=errors,
        summary_path=output_dir / "workflow-summary.json",
    )
    (output_dir / "workflow-summary.json").write_text(
        workflow_result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return workflow_result


def _run_recon_depth_step(
    step: ReconWorkflowStep,
    defaults: ReconWorkflowDefaults,
    *,
    output_dir: Path,
    action_executor: ReconDepthActionExecutor,
) -> ReconDepthResult:
    return run_recon_depth(
        domain=step.domain,
        output_dir=output_dir,
        profile=step.profile or defaults.profile,
        action_executor=action_executor,
        max_hosts=step.max_hosts or defaults.max_hosts,
        max_urls=step.max_urls or defaults.max_urls,
        rate_limit_per_minute=step.rate_limit_per_minute or defaults.rate_limit_per_minute,
        katana_depth=step.katana_depth or defaults.katana_depth,
        katana_js_crawl=_bool_setting(step.katana_js_crawl, defaults.katana_js_crawl),
        katana_known_files=step.katana_known_files or defaults.katana_known_files,
        katana_crawl_duration_seconds=(
            step.katana_crawl_duration_seconds or defaults.katana_crawl_duration_seconds
        ),
        nuclei_templates=step.nuclei_templates if step.nuclei_templates is not None else defaults.nuclei_templates,
        nuclei_tags=step.nuclei_tags if step.nuclei_tags is not None else defaults.nuclei_tags,
        nuclei_severity=step.nuclei_severity if step.nuclei_severity is not None else defaults.nuclei_severity,
        nuclei_rate_limit_per_second=(
            step.nuclei_rate_limit_per_second or defaults.nuclei_rate_limit_per_second
        ),
        max_validation_actions=step.max_validation_actions or defaults.max_validation_actions,
    )


def _step_output_dir(root_output_dir: Path, step: ReconWorkflowStep) -> Path:
    if step.output_dir is None:
        return root_output_dir / step.id
    if step.output_dir.is_absolute():
        return step.output_dir
    return root_output_dir / step.output_dir


def _bool_setting(value: bool | None, default: bool) -> bool:
    return default if value is None else value
