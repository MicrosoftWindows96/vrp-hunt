from pathlib import Path

import pytest

from vrp_hunt.agent import (
    AgentAction,
    AgentObservation,
    AgentRunResult,
    ReconWorkflowError,
    build_recon_workflow_dag,
    build_recon_workflow_notifications,
    build_recon_workflow_orchestration_plan,
    build_recon_workflow_schedule,
    compare_recon_workflow_runs,
    load_recon_workflow,
    run_recon_workflow,
)
from vrp_hunt.recon import Asset


def _executor(action: AgentAction) -> AgentRunResult:
    tool = action.metadata["tool"]
    if tool == "subfinder":
        assets = [Asset(kind="host", value="www.google.com", source="subfinder")]
    elif tool == "httpx":
        assets = [Asset(kind="url", value="https://www.google.com", source="httpx")]
    elif tool == "katana":
        assets = [Asset(kind="endpoint", value="https://www.google.com/profile", source="katana")]
    else:
        assets = []
    return AgentRunResult(
        observations=[
            AgentObservation(
                action_id=action.action_id,
                success=True,
                assets=assets,
                request_count=action.request_budget,
            )
        ],
        completed_actions=1,
    )


def test_recon_workflow_runs_enabled_steps(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{tmp_path / "workflow-output"}"
defaults:
  profile: "balanced"
  max_hosts: 5
  max_urls: 5
steps:
  - id: "google-balanced"
    kind: "recon_depth"
    domain: "google.com"
  - id: "disabled-step"
    kind: "recon_depth"
    domain: "youtube.com"
    enabled: false
""",
        encoding="utf-8",
    )

    workflow = load_recon_workflow(workflow_path)
    result = run_recon_workflow(workflow, action_executor=_executor)

    assert result.workflow_name == "google-recon"
    assert [step.step_id for step in result.step_runs] == ["google-balanced", "disabled-step"]
    assert result.step_runs[0].result is not None
    assert [phase.phase for phase in result.step_runs[0].result.phase_runs] == [
        "subfinder",
        "httpx",
        "katana",
    ]
    assert result.step_runs[1].skipped
    assert result.summary_path is not None
    assert result.summary_path.exists()


def test_recon_workflow_rejects_duplicate_step_ids(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{tmp_path / "workflow-output"}"
steps:
  - id: "duplicate"
    domain: "google.com"
  - id: "duplicate"
    domain: "youtube.com"
""",
        encoding="utf-8",
    )

    with pytest.raises(ReconWorkflowError):
        load_recon_workflow(workflow_path)


def test_recon_workflow_dag_dependencies_and_orchestration_plan(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{tmp_path / "workflow-output"}"
steps:
  - id: "seed"
    domain: "google.com"
  - id: "expand"
    domain: "google.com"
    depends_on: ["seed"]
""",
        encoding="utf-8",
    )

    workflow = load_recon_workflow(workflow_path)
    dag = build_recon_workflow_dag(workflow)
    plan = build_recon_workflow_orchestration_plan(
        workflow,
        worker_count=2,
        schedule_interval_minutes=60,
        notification_platforms=["slack", "discord"],
    )

    assert dag.execution_order == ["seed", "expand"]
    assert dag.nodes[1].level == 1
    assert plan.workers.assignments[0].step_ids == ["seed"]
    assert plan.workers.assignments[1].step_ids == ["expand"]
    assert plan.schedule is not None
    assert plan.api_routes[0].path == "/workflows"
    assert plan.notification_platforms == ["slack", "discord"]


def test_recon_workflow_resume_uses_saved_step_summary(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.yaml"
    output_dir = tmp_path / "workflow-output"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{output_dir}"
steps:
  - id: "cached"
    domain: "google.com"
""",
        encoding="utf-8",
    )
    workflow = load_recon_workflow(workflow_path)
    first = run_recon_workflow(workflow, action_executor=_executor)

    resumed = run_recon_workflow(workflow, action_executor=_executor)

    assert first.step_runs[0].result is not None
    assert resumed.step_runs[0].skipped
    assert resumed.step_runs[0].warnings == ["resumed from recon-depth-summary.json"]


def test_recon_workflow_timeline_schedule_and_notifications(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{tmp_path / "workflow-output"}"
steps:
  - id: "first"
    domain: "google.com"
  - id: "disabled"
    domain: "google.com"
    enabled: false
""",
        encoding="utf-8",
    )
    workflow = load_recon_workflow(workflow_path)
    current = run_recon_workflow(workflow, action_executor=_executor)
    previous = current.model_copy(update={"step_runs": current.step_runs[:1]})

    timeline = compare_recon_workflow_runs(previous, current)
    schedule = build_recon_workflow_schedule(interval_minutes=30, count=2)
    notifications = build_recon_workflow_notifications(current, platforms=["slack", "discord"])

    assert timeline.changed_steps == ["disabled"]
    assert len(schedule.next_runs) == 2
    assert notifications.notifications[0].payload["text"].startswith("google-recon")
    assert notifications.notifications[1].payload["content"].startswith("google-recon")
