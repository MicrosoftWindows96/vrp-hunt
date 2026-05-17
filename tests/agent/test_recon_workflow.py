from pathlib import Path

import pytest

from vrp_hunt.agent import (
    AgentAction,
    AgentObservation,
    AgentRunResult,
    ReconWorkflowError,
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
