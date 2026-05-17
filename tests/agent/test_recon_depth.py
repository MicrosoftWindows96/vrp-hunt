from pathlib import Path

import pytest

from vrp_hunt.agent import (
    AgentAction,
    AgentObservation,
    AgentRunResult,
    ReconDepthError,
    run_recon_depth,
)
from vrp_hunt.recon import Asset


def _executor(action: AgentAction) -> AgentRunResult:
    tool = action.metadata["tool"]
    if tool == "subfinder":
        assets = [
            Asset(kind="host", value="www.google.com", source="subfinder"),
            Asset(kind="host", value="evil.example", source="subfinder"),
        ]
    elif tool == "httpx":
        assets = [
            Asset(kind="url", value="https://www.google.com", source="httpx"),
            Asset(
                kind="host",
                value="www.google.com",
                source="httpx",
                parent="https://www.google.com",
            ),
        ]
    elif tool == "katana":
        assets = [
            Asset(kind="endpoint", value="https://www.google.com/account", source="katana"),
            Asset(kind="javascript", value="https://www.google.com/app.js", source="katana"),
        ]
    elif tool == "nuclei":
        assets = [
            Asset(
                kind="note",
                value="nuclei:safe-template:https://www.google.com",
                source="nuclei",
                parent="https://www.google.com",
                metadata={"template_id": "safe-template"},
            )
        ]
    else:
        assets = []
    return AgentRunResult(
        observations=[
            AgentObservation(
                action_id=action.action_id,
                success=True,
                assets=assets,
                request_count=action.request_budget,
                notes=[f"{tool} ok"],
            )
        ],
        completed_actions=1,
    )


def test_recon_depth_passive_runs_only_subfinder(tmp_path: Path) -> None:
    result = run_recon_depth(
        domain="google.com",
        output_dir=tmp_path / "depth",
        profile="passive",
        action_executor=_executor,
    )

    assert [phase.phase for phase in result.phase_runs] == ["subfinder"]
    assert result.total_assets == 1
    assert result.assets_path.exists()
    assert "evil.example" not in result.assets_path.read_text(encoding="utf-8")
    subfinder_run_text = (tmp_path / "depth" / "phases" / "subfinder" / "run.json").read_text(
        encoding="utf-8"
    )
    assert "evil.example" not in subfinder_run_text
    assert result.summary_path is not None
    assert result.summary_path.exists()


def test_recon_depth_deep_chains_tools_and_filters_scope(tmp_path: Path) -> None:
    result = run_recon_depth(
        domain="google.com",
        output_dir=tmp_path / "depth",
        profile="deep",
        action_executor=_executor,
        nuclei_templates=["safe/http/title.yaml"],
        max_hosts=10,
        max_urls=10,
    )

    assert [phase.phase for phase in result.phase_runs] == [
        "subfinder",
        "httpx",
        "katana",
        "nuclei",
    ]
    assert not result.errors
    assert not result.warnings
    assert "evil.example" not in (tmp_path / "depth" / "inputs" / "httpx-hosts.txt").read_text(
        encoding="utf-8"
    )
    assert (tmp_path / "depth" / "phases" / "nuclei" / "assets.jsonl").exists()


def test_recon_depth_owned_auth_writes_validation_plan(tmp_path: Path) -> None:
    result = run_recon_depth(
        domain="google.com",
        output_dir=tmp_path / "depth",
        profile="owned-auth",
        action_executor=_executor,
        nuclei_templates=[],
    )

    assert "nuclei phase skipped" in result.warnings[0]
    assert result.validation_plan_path is not None
    assert result.validation_plan_path.exists()
    assert result.approval_queue_path is not None
    assert result.approval_queue_path.exists()


def test_recon_depth_rejects_unsafe_limits(tmp_path: Path) -> None:
    with pytest.raises(ReconDepthError, match="rate_limit_per_minute"):
        run_recon_depth(
            domain="google.com",
            output_dir=tmp_path / "depth",
            profile="balanced",
            action_executor=_executor,
            rate_limit_per_minute=0,
        )
