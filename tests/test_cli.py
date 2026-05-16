import getpass
import json
from pathlib import Path

from vrp_hunt.cli import main


def test_agent_plan_cli_outputs_offline_plan(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-plan",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "offline",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["actions"][0]["action_type"] == "analyze_assets"


def test_agent_plan_cli_requires_remote_model_acknowledgement(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-plan",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--model-provider",
            "openai",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "allow-remote-model" in captured.err


def test_agent_run_cli_executes_safe_runner(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "offline",
            "--execute-safe",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["completed_actions"] >= 1
    assert output["observations"][0]["request_count"] == 0


def test_agent_run_cli_requires_explicit_risky_approval(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--max-live-requests",
            "3",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["blocked_actions"] >= 1
    assert "approval" in output["decisions"][0]["reason"]


def test_agent_run_cli_approval_uses_non_traffic_validation_runner(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--approve-risky",
            "--max-live-requests",
            "3",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["completed_actions"] >= 1
    assert output["observations"][0]["request_count"] == 0


def test_agent_run_cli_explicit_approval_by_index(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--approval-mode",
            "explicit",
            "--approve-action",
            "1",
            "--max-live-requests",
            "3",
        ]
    )

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == 0
    assert output["completed_actions"] >= 1
    assert "approved 1 risky action" in captured.err


def test_agent_run_cli_prompt_approval(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("builtins.input", lambda _: "APPROVE 1")

    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--approval-mode",
            "prompt",
            "--max-live-requests",
            "3",
        ]
    )

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == 0
    assert output["completed_actions"] >= 1
    assert "Risky actions require explicit approval" in captured.err


def test_agent_run_cli_bad_explicit_approval_returns_error(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--approval-mode",
            "explicit",
            "--approve-action",
            "999",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "approval gate error" in captured.err


def test_agent_auto_blocks_risky_actions_by_default(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-auto",
            "--asset",
            "url:https://accounts.google.com/profile",
        ]
    )

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == 0
    assert output["run"]["blocked_actions"] >= 1
    assert output["artifacts"]["artifacts"] == []
    assert "blocked by policy" in captured.err


def test_agent_auto_approval_emits_artifacts_and_files(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    output_dir = tmp_path / "auto-artifacts"

    exit_code = main(
        [
            "agent-auto",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--approval-mode",
            "explicit",
            "--approve-action",
            "1",
            "--researcher-account",
            "owned-a",
            "--researcher-account",
            "owned-b",
            "--component",
            "Accounts profile",
            "--artifact-output-dir",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == 0
    assert output["run"]["completed_actions"] == 1
    assert output["run"]["observations"][0]["request_count"] == 0
    assert output["artifacts"]["artifacts"][0]["finding"]["bug_class"] == "idor"
    assert output["artifacts"]["artifacts"][0]["report"]["target_info"]["component"] == "Accounts profile"
    assert "approved 1 risky action" in captured.err
    assert (output_dir / "plan.json").exists()
    assert (output_dir / "run.json").exists()
    assert json.loads((output_dir / "artifact-bundle.json").read_text(encoding="utf-8"))[
        "artifacts"
    ]


def test_recon_iterate_ranks_candidates_and_excludes_dead_httpx(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    run_json = tmp_path / "subfinder-run.json"
    run_json.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "assets": [
                            {"kind": "host", "value": "adssettings.google.com"},
                            {"kind": "host", "value": "login.script.google.com"},
                            {"kind": "host", "value": "foo.mx-verification.google.com"},
                            {"kind": "host", "value": "dead.account.google.com"},
                            {"kind": "host", "value": "old.account.google.com"},
                            {"kind": "host", "value": "corpnat-1.corp.google.com"},
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    httpx_dir = tmp_path / "httpx"
    httpx_dir.mkdir()
    (httpx_dir / "dead.json").write_text(
        json.dumps(
            {
                "decisions": [
                    {
                        "allowed": True,
                        "reason": "allowed",
                        "gate_decision": {
                            "normalized_target": "https://dead.account.google.com"
                        },
                    }
                ],
                "observations": [{"success": False, "assets": [], "request_count": 1}],
            }
        ),
        encoding="utf-8",
    )
    older_httpx_dir = tmp_path / "older-httpx"
    older_httpx_dir.mkdir()
    (older_httpx_dir / "old.json").write_text(
        json.dumps(
            {
                "decisions": [
                    {
                        "allowed": True,
                        "reason": "allowed",
                        "gate_decision": {"normalized_target": "old.account.google.com"},
                    }
                ],
                "observations": [{"success": False, "assets": [], "request_count": 1}],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "iteration"

    exit_code = main(
        [
            "recon-iterate",
            "--run-json",
            str(run_json),
            "--httpx-dir",
            str(httpx_dir),
            "--httpx-dir",
            str(older_httpx_dir),
            "--limit",
            "3",
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    candidate_hosts = [candidate["host"] for candidate in output["candidates"]]

    assert exit_code == 0
    assert candidate_hosts == ["adssettings.google.com", "login.script.google.com"]
    assert output["excluded_dead_hosts"] == ["dead.account.google.com", "old.account.google.com"]
    assert output["approval_queue"] == [
        "APPROVE LIVE HTTPX https://adssettings.google.com",
        "APPROVE LIVE HTTPX https://login.script.google.com",
    ]
    assert (output_dir / "ranked-targets.json").exists()
    assert (output_dir / "ranked-assets.jsonl").read_text(encoding="utf-8").count("\n") == 2
    assert (output_dir / "approval-queue.txt").read_text(encoding="utf-8").splitlines() == [
        "APPROVE LIVE HTTPX https://adssettings.google.com",
        "APPROVE LIVE HTTPX https://login.script.google.com",
    ]


def test_live_recon_cli_blocks_unauthorized_operator_before_tool_execution(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    policy_path = tmp_path / "operator_policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'authorized_operator_id: "owner"',
                f'authorized_local_user: "{getpass.getuser()}"',
                "allowed_tools:",
                '  - "subfinder"',
                "require_liability_ack: true",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "live-recon",
            "--tool",
            "subfinder",
            "--target",
            "google.com",
            "--operator-policy",
            str(policy_path),
            "--operator-id",
            "someone-else",
            "--accept-legal-liability",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["completed_actions"] == 1
    assert not output["observations"][0]["success"]
    assert "authorization failed" in output["observations"][0]["notes"][0]
