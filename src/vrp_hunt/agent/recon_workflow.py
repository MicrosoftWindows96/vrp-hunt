"""Declarative YAML workflows for approved recon-depth runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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
ReconWorkflowStepCondition = Literal["dependencies_succeeded", "dependencies_completed", "always"]
ReconWorkflowWorkerMode = Literal["local", "local_first", "distributed"]
NotificationPlatform = Literal["slack", "discord"]


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
    depends_on: list[str] = Field(default_factory=list)
    condition: ReconWorkflowStepCondition = "dependencies_succeeded"
    resume: bool = True
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
    def step_graph_must_be_valid(self) -> "ReconWorkflow":
        step_ids = [step.id for step in self.steps]
        known_ids = set(step_ids)
        if len(step_ids) != len(known_ids):
            raise ValueError("workflow step ids must be unique")
        for step in self.steps:
            unknown = sorted(set(step.depends_on) - known_ids)
            if unknown:
                raise ValueError(f"{step.id} depends on unknown steps: {', '.join(unknown)}")
            if step.id in step.depends_on:
                raise ValueError(f"{step.id} cannot depend on itself")
        _topological_steps(self.steps)
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


class ReconWorkflowDagNode(StrictModel):
    step_id: str = Field(min_length=1)
    depends_on: list[str] = Field(default_factory=list)
    condition: ReconWorkflowStepCondition
    enabled: bool
    level: int = Field(ge=0)


class ReconWorkflowDagPlan(StrictModel):
    workflow_name: str = Field(min_length=1)
    nodes: list[ReconWorkflowDagNode] = Field(default_factory=list)
    execution_order: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ReconWorkflowWorkerAssignment(StrictModel):
    worker_id: str = Field(min_length=1)
    step_ids: list[str] = Field(default_factory=list)


class ReconWorkflowWorkerPlan(StrictModel):
    mode: ReconWorkflowWorkerMode
    worker_count: int = Field(ge=1)
    local_first: bool = True
    assignments: list[ReconWorkflowWorkerAssignment] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ReconWorkflowSchedulePlan(StrictModel):
    interval_minutes: int = Field(ge=1)
    next_runs: list[datetime] = Field(default_factory=list)


class ReconWorkflowTimelineEntry(StrictModel):
    step_id: str = Field(min_length=1)
    previous_status: str = Field(min_length=1)
    current_status: str = Field(min_length=1)
    changed: bool


class ReconWorkflowTimeline(StrictModel):
    entries: list[ReconWorkflowTimelineEntry] = Field(default_factory=list)
    changed_steps: list[str] = Field(default_factory=list)


class ReconWorkflowApiRoute(StrictModel):
    method: str = Field(min_length=1)
    path: str = Field(min_length=1)
    description: str = Field(min_length=1)
    sends_traffic: bool = False


class ReconWorkflowNotification(StrictModel):
    platform: NotificationPlatform
    payload: dict[str, object]


class ReconWorkflowNotificationPlan(StrictModel):
    notifications: list[ReconWorkflowNotification] = Field(default_factory=list)


class ReconWorkflowOrchestrationPlan(StrictModel):
    dag: ReconWorkflowDagPlan
    workers: ReconWorkflowWorkerPlan
    schedule: ReconWorkflowSchedulePlan | None = None
    api_routes: list[ReconWorkflowApiRoute] = Field(default_factory=list)
    notification_platforms: list[NotificationPlatform] = Field(default_factory=list)


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


def build_recon_workflow_dag(workflow: ReconWorkflow) -> ReconWorkflowDagPlan:
    ordered = _topological_steps(workflow.steps)
    levels: dict[str, int] = {}
    nodes: list[ReconWorkflowDagNode] = []
    for step in ordered:
        level = 0
        if step.depends_on:
            level = max(levels[parent] for parent in step.depends_on) + 1
        levels[step.id] = level
        nodes.append(
            ReconWorkflowDagNode(
                step_id=step.id,
                depends_on=step.depends_on,
                condition=step.condition,
                enabled=step.enabled,
                level=level,
            )
        )
    return ReconWorkflowDagPlan(
        workflow_name=workflow.name,
        nodes=nodes,
        execution_order=[step.id for step in ordered],
    )


def build_recon_workflow_worker_plan(
    workflow: ReconWorkflow,
    *,
    worker_count: int = 1,
    mode: ReconWorkflowWorkerMode = "local_first",
) -> ReconWorkflowWorkerPlan:
    if worker_count < 1:
        raise ReconWorkflowError("worker_count must be at least 1")
    ordered_ids = build_recon_workflow_dag(workflow).execution_order
    assignments = [
        ReconWorkflowWorkerAssignment(worker_id=f"worker-{index + 1:02d}")
        for index in range(worker_count)
    ]
    for index, step_id in enumerate(ordered_ids):
        assignments[index % worker_count].step_ids.append(step_id)
    warnings = []
    if mode == "distributed":
        warnings.append("distributed mode is a planning contract; execution remains local-first")
    return ReconWorkflowWorkerPlan(
        mode=mode,
        worker_count=worker_count,
        local_first=mode != "distributed",
        assignments=assignments,
        warnings=warnings,
    )


def build_recon_workflow_schedule(
    *,
    interval_minutes: int,
    start_at: datetime | None = None,
    count: int = 3,
) -> ReconWorkflowSchedulePlan:
    if count < 1:
        raise ReconWorkflowError("schedule count must be at least 1")
    start = start_at or datetime.now(UTC)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return ReconWorkflowSchedulePlan(
        interval_minutes=interval_minutes,
        next_runs=[start + timedelta(minutes=interval_minutes * index) for index in range(count)],
    )


def build_recon_workflow_api_routes() -> list[ReconWorkflowApiRoute]:
    return [
        ReconWorkflowApiRoute(
            method="GET",
            path="/workflows",
            description="List workflow definitions and recent run summaries",
        ),
        ReconWorkflowApiRoute(
            method="POST",
            path="/workflows/{workflow_id}/plans",
            description="Create an offline DAG, worker, schedule, and notification plan",
        ),
        ReconWorkflowApiRoute(
            method="POST",
            path="/workflows/{workflow_id}/runs",
            description="Queue a guardrailed local-first workflow run",
            sends_traffic=True,
        ),
        ReconWorkflowApiRoute(
            method="GET",
            path="/workflows/{workflow_id}/runs/{run_id}",
            description="Read a saved workflow run summary",
        ),
    ]


def build_recon_workflow_orchestration_plan(
    workflow: ReconWorkflow,
    *,
    worker_count: int = 1,
    worker_mode: ReconWorkflowWorkerMode = "local_first",
    schedule_interval_minutes: int | None = None,
    notification_platforms: list[NotificationPlatform] | None = None,
) -> ReconWorkflowOrchestrationPlan:
    return ReconWorkflowOrchestrationPlan(
        dag=build_recon_workflow_dag(workflow),
        workers=build_recon_workflow_worker_plan(
            workflow,
            worker_count=worker_count,
            mode=worker_mode,
        ),
        schedule=(
            build_recon_workflow_schedule(interval_minutes=schedule_interval_minutes)
            if schedule_interval_minutes is not None
            else None
        ),
        api_routes=build_recon_workflow_api_routes(),
        notification_platforms=notification_platforms or [],
    )


def compare_recon_workflow_runs(
    previous: ReconWorkflowResult,
    current: ReconWorkflowResult,
) -> ReconWorkflowTimeline:
    previous_status = {run.step_id: _run_status(run) for run in previous.step_runs}
    current_status = {run.step_id: _run_status(run) for run in current.step_runs}
    entries: list[ReconWorkflowTimelineEntry] = []
    for step_id in sorted(set(previous_status) | set(current_status)):
        old = previous_status.get(step_id, "missing")
        new = current_status.get(step_id, "missing")
        entries.append(
            ReconWorkflowTimelineEntry(
                step_id=step_id,
                previous_status=old,
                current_status=new,
                changed=old != new,
            )
        )
    return ReconWorkflowTimeline(
        entries=entries,
        changed_steps=[entry.step_id for entry in entries if entry.changed],
    )


def build_recon_workflow_notifications(
    result: ReconWorkflowResult,
    *,
    platforms: list[NotificationPlatform],
) -> ReconWorkflowNotificationPlan:
    status = "failed" if result.errors else "completed"
    text = (
        f"{result.workflow_name} {status}: "
        f"{len(result.step_runs)} step(s), {len(result.errors)} error(s), {len(result.warnings)} warning(s)"
    )
    notifications: list[ReconWorkflowNotification] = []
    for platform in platforms:
        if platform == "slack":
            payload: dict[str, object] = {"text": text}
        else:
            payload = {"content": text}
        notifications.append(ReconWorkflowNotification(platform=platform, payload=payload))
    return ReconWorkflowNotificationPlan(notifications=notifications)


def load_recon_workflow_result(path: str | Path) -> ReconWorkflowResult:
    try:
        return ReconWorkflowResult.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ReconWorkflowError(f"failed to load workflow result: {path}") from exc


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

    succeeded: set[str] = set()
    completed: set[str] = set()
    for step in _topological_steps(workflow.steps):
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
        dependency_message = _dependency_skip_reason(step, succeeded=succeeded, completed=completed)
        if dependency_message:
            step_runs.append(
                ReconWorkflowStepRun(
                    step_id=step.id,
                    kind=step.kind,
                    enabled=True,
                    skipped=True,
                    output_dir=step_output_dir,
                    warnings=[dependency_message],
                )
            )
            continue
        resumed = _load_resumable_step_result(step_output_dir) if step.resume else None
        if resumed is not None:
            completed.add(step.id)
            if not resumed.errors:
                succeeded.add(step.id)
            step_runs.append(
                ReconWorkflowStepRun(
                    step_id=step.id,
                    kind=step.kind,
                    enabled=True,
                    skipped=True,
                    output_dir=step_output_dir,
                    result=resumed,
                    warnings=["resumed from recon-depth-summary.json"],
                    errors=resumed.errors,
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
        completed.add(step.id)
        if not result.errors:
            succeeded.add(step.id)
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


def _topological_steps(steps: list[ReconWorkflowStep]) -> list[ReconWorkflowStep]:
    by_id = {step.id: step for step in steps}
    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[ReconWorkflowStep] = []

    def visit(step_id: str) -> None:
        if step_id in visited:
            return
        if step_id in visiting:
            raise ValueError("workflow dependency graph contains a cycle")
        visiting.add(step_id)
        for dependency in by_id[step_id].depends_on:
            visit(dependency)
        visiting.remove(step_id)
        visited.add(step_id)
        ordered.append(by_id[step_id])

    for step in steps:
        visit(step.id)
    return ordered


def _dependency_skip_reason(
    step: ReconWorkflowStep,
    *,
    succeeded: set[str],
    completed: set[str],
) -> str:
    if step.condition == "always":
        return ""
    missing_completed = sorted(set(step.depends_on) - completed)
    if missing_completed:
        return f"waiting for dependencies: {', '.join(missing_completed)}"
    if step.condition == "dependencies_completed":
        return ""
    missing_success = sorted(set(step.depends_on) - succeeded)
    if missing_success:
        return f"dependencies did not succeed: {', '.join(missing_success)}"
    return ""


def _load_resumable_step_result(output_dir: Path) -> ReconDepthResult | None:
    summary_path = output_dir / "recon-depth-summary.json"
    if not summary_path.exists():
        return None
    try:
        return ReconDepthResult.model_validate_json(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, json.JSONDecodeError):
        return None


def _run_status(run: ReconWorkflowStepRun) -> str:
    if run.skipped and run.result is None:
        return "skipped"
    if run.errors:
        return "failed"
    if run.result is not None:
        return "completed"
    return "unknown"
