import getpass
import json
from pathlib import Path

import pytest

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


def test_agent_run_cli_yolo_is_approval_shortcut(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "agent-run",
            "--asset",
            "url:https://accounts.google.com/profile",
            "--mode",
            "testing",
            "--execute-safe",
            "--yolo",
            "--max-live-requests",
            "3",
        ]
    )

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == 0
    assert output["completed_actions"] >= 1
    assert output["blocked_actions"] == 0
    assert "approved" in captured.err


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


def test_owned_browser_check_rejects_without_owned_object_confirmation(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()

    exit_code = main(
        [
            "owned-browser-check",
            "--account-id",
            "owned-b",
            "--profile-dir",
            str(profile_dir),
            "--url",
            "https://drive.google.com/file/d/abc123/view",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--confirm-owned-object" in captured.err


def test_owned_browser_check_requires_profile_without_cdp(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(
        [
            "owned-browser-check",
            "--account-id",
            "owned-b",
            "--url",
            "https://drive.google.com/file/d/abc123/view",
            "--confirm-owned-object",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--profile-dir" in captured.err


def test_owned_browser_scenario_cli_rejects_unconfirmed_scenario(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "scenario_id: unsafe",
                "researcher_owned: false",
                "accounts:",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "steps:",
                "  - name: denied",
                "    account_id: owned-b",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_state: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(["owned-browser-scenario", "--scenario", str(scenario_path)])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "owned browser scenario error" in captured.err


def test_owned_browser_scenario_cli_expands_derived_urls_and_writes_result(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import OwnedBrowserCheckResult, redact_object_url

    scenario_path = tmp_path / "scenario.yaml"
    output_dir = tmp_path / "scenario-output"
    scenario_path.write_text(
        "\n".join(
            [
                "scenario_id: docs-private",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "steps:",
                "  - name: denied",
                "    account_id: owned-b",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_state: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    def fake_check(account, step):  # type: ignore[no-untyped-def]
        return OwnedBrowserCheckResult(
            account_id=account.account_id,
            checked_url=redact_object_url(step.url),
            current_url_host="docs.google.com",
            current_url_path_hash="abc123",
            state="access_denied",
            confidence=0.9,
        )

    monkeypatch.setattr("vrp_hunt.agent.scenarios._default_scenario_step_checker", fake_check)

    exit_code = main(
        [
            "owned-browser-scenario",
            "--scenario",
            str(scenario_path),
            "--expand-derived",
            "--yolo",
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["completed_steps"] > 1
    assert output["mismatches"] == 0
    assert (output_dir / "scenario-result.json").exists()


def test_scenario_generate_cli_writes_owned_object_scenarios(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    catalog_path = tmp_path / "catalog.yaml"
    output_dir = tmp_path / "generated"
    catalog_path.write_text(
        "\n".join(
            [
                "catalog_id: docs-baseline",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-a",
                "    cdp_url: http://127.0.0.1:9222",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "objects:",
                "  - object_id: owned-a-private-doc",
                "    product: docs",
                "    owner_account_id: owned-a",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_states:",
                "      owned-a: access_granted",
                "      owned-b: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scenario-generate",
            "--object-catalog",
            str(catalog_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["generated_count"] == 1
    assert (output_dir / "docs-baseline-owned-a-private-doc.yaml").exists()
    assert (output_dir / "scenario-index.json").exists()


def test_scenario_generate_cli_rejects_unconfirmed_catalog(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text("catalog_id: bad\nresearcher_owned: false\n", encoding="utf-8")

    exit_code = main(
        [
            "scenario-generate",
            "--object-catalog",
            str(catalog_path),
            "--output-dir",
            str(tmp_path / "generated"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "scenario generate error" in captured.err


def test_scenario_artifacts_cli_writes_finding_and_report(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    result_path = tmp_path / "scenario-result.json"
    output_dir = tmp_path / "artifacts"
    scenario_path.write_text(
        "\n".join(
            [
                "scenario_id: docs-private",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "steps:",
                "  - name: owned-b-denied",
                "    account_id: owned-b",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_state: access_denied",
            ]
        ),
        encoding="utf-8",
    )
    result_path.write_text(
        json.dumps(
            {
                "scenario_id": "docs-private",
                "completed_steps": 1,
                "mismatches": 1,
                "errors": 0,
                "stopped": True,
                "stop_reason": "scenario step failed expected access-state assertion",
                "results": [
                    {
                        "step_name": "owned-b-denied",
                        "account_id": "owned-b",
                        "checked_url": "https://docs.google.com/[path:abc123]",
                        "current_url_host": "docs.google.com",
                        "current_url_path_hash": "abc123",
                        "expected_state": "access_denied",
                        "actual_state": "access_granted",
                        "matched": False,
                        "confidence": 0.9,
                        "matched_signals": ["google docs"],
                        "request_count": 1,
                        "third_party_data_seen": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scenario-artifacts",
            "--scenario",
            str(scenario_path),
            "--scenario-result",
            str(result_path),
            "--researcher-account",
            "owned-a",
            "--researcher-account",
            "owned-b",
            "--component",
            "Docs private object",
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(output["artifacts"]["artifacts"]) == 1
    assert output["artifacts"]["artifacts"][0]["finding"]["bug_class"] == "idor"
    assert (output_dir / "artifact-bundle.json").exists()
    assert output["files"]["artifacts"][0]["markdown"].endswith("-report.md")
    assert Path(output["files"]["artifacts"][0]["markdown"]).exists()


def test_scenario_artifacts_cli_skips_matching_results(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    result_path = tmp_path / "scenario-result.json"
    output_dir = tmp_path / "artifacts"
    scenario_path.write_text(
        "\n".join(
            [
                "scenario_id: docs-private",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "steps:",
                "  - name: owned-b-denied",
                "    account_id: owned-b",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_state: access_denied",
            ]
        ),
        encoding="utf-8",
    )
    result_path.write_text(
        json.dumps(
            {
                "scenario_id": "docs-private",
                "completed_steps": 1,
                "mismatches": 0,
                "errors": 0,
                "results": [
                    {
                        "step_name": "owned-b-denied",
                        "account_id": "owned-b",
                        "expected_state": "access_denied",
                        "actual_state": "access_denied",
                        "matched": True,
                        "request_count": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scenario-artifacts",
            "--scenario",
            str(scenario_path),
            "--scenario-result",
            str(result_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["artifacts"]["artifacts"] == []
    assert "expected access state matched" in output["artifacts"]["skipped"][0]


def test_derived_http_check_cli_writes_result_and_preserves_cookie_boundary(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import DerivedHttpCheckResult, DerivedHttpObservation

    output_dir = tmp_path / "derived"
    seen: dict[str, str] = {}

    def fake_run(**kwargs):  # type: ignore[no-untyped-def]
        seen["cookie_header"] = kwargs["cookie_header"]
        return DerivedHttpCheckResult(
            account_id=kwargs["account_id"],
            source_url="https://docs.google.com/[path:abc123]",
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
                )
            ],
            request_count=1,
            high_signal_mismatches=1,
        )

    monkeypatch.setenv("OWNED_B_COOKIE", "SID=secret")
    monkeypatch.setattr("vrp_hunt.cli.run_derived_http_check", fake_run)

    exit_code = main(
        [
            "derived-http-check",
            "--account-id",
            "owned-b",
            "--url",
            "https://docs.google.com/document/d/owned/edit",
            "--cookie-env",
            "OWNED_B_COOKIE",
            "--expected-state",
            "access_denied",
            "--confirm-owned-object",
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert seen["cookie_header"] == "SID=secret"
    assert "secret" not in json.dumps(output)
    assert output["high_signal_mismatches"] == 1
    assert (output_dir / "derived-http-result.json").exists()


def test_derived_http_check_cli_requires_owned_confirmation(
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setenv("OWNED_B_COOKIE", "SID=secret")

    exit_code = main(
        [
            "derived-http-check",
            "--account-id",
            "owned-b",
            "--url",
            "https://docs.google.com/document/d/owned/edit",
            "--cookie-env",
            "OWNED_B_COOKIE",
            "--expected-state",
            "access_denied",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "confirm-owned-object" in captured.err


def test_derived_http_artifacts_cli_writes_finding_and_report(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    result_path = tmp_path / "derived-http-result.json"
    output_dir = tmp_path / "artifacts"
    result_path.write_text(
        json.dumps(
            {
                "account_id": "owned-b",
                "source_url": "https://docs.google.com/[path:abc123]",
                "expected_state": "access_denied",
                "target_count": 1,
                "request_count": 1,
                "high_signal_mismatches": 1,
                "errors": 0,
                "third_party_data_seen": False,
                "observations": [
                    {
                        "target_name": "export-pdf",
                        "method": "HEAD",
                        "checked_url": "https://docs.google.com/[path:def456]?keys=format",
                        "status_code": 200,
                        "final_host": "docs.google.com",
                        "final_path_hash": "def456",
                        "redirect_count": 0,
                        "response_headers": {"content-type": "application/pdf"},
                        "state": "access_granted_metadata",
                        "confidence": 0.7,
                        "matched_signals": ["content-type:application/pdf"],
                        "response_body_stored": False,
                        "response_body_bytes_read": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "derived-http-artifacts",
            "--derived-http-result",
            str(result_path),
            "--researcher-account",
            "owned-a",
            "--researcher-account",
            "owned-b",
            "--component",
            "Docs export endpoint",
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(output["artifacts"]["artifacts"]) == 1
    assert output["artifacts"]["artifacts"][0]["finding"]["bug_class"] == "idor"
    assert (output_dir / "artifact-bundle.json").exists()
    assert Path(output["files"]["artifacts"][0]["markdown"]).exists()


def test_derived_http_artifacts_cli_skips_body_reads(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    result_path = tmp_path / "derived-http-result.json"
    output_dir = tmp_path / "artifacts"
    result_path.write_text(
        json.dumps(
            {
                "account_id": "owned-b",
                "source_url": "https://docs.google.com/[path:abc123]",
                "expected_state": "access_denied",
                "target_count": 1,
                "observations": [
                    {
                        "target_name": "export-pdf",
                        "method": "GET",
                        "checked_url": "https://docs.google.com/[path:def456]?keys=format",
                        "status_code": 200,
                        "state": "access_granted_metadata",
                        "response_body_stored": False,
                        "response_body_bytes_read": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "derived-http-artifacts",
            "--derived-http-result",
            str(result_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["artifacts"]["artifacts"] == []
    assert "response body bytes were read" in output["artifacts"]["skipped"][0]


def test_owned_object_pipeline_cli_runs_catalog_pipeline(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import OwnedObjectPipelineResult

    catalog_path = tmp_path / "catalog.yaml"
    output_dir = tmp_path / "pipeline"
    catalog_path.write_text(
        "\n".join(
            [
                "catalog_id: docs-baseline",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-a",
                "    cdp_url: http://127.0.0.1:9222",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "    cookie_env: OWNED_B_COOKIE",
                "objects:",
                "  - object_id: owned-a-private-doc",
                "    product: docs",
                "    owner_account_id: owned-a",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_states:",
                "      owned-a: access_granted",
                "      owned-b: access_denied",
            ]
        ),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}

    def fake_pipeline(catalog, output_path, **kwargs):  # type: ignore[no-untyped-def]
        seen["catalog_id"] = catalog.catalog_id
        seen["output_path"] = output_path
        seen["yolo"] = kwargs["yolo"]
        seen["derive_cookies_from_cdp"] = kwargs["derive_cookies_from_cdp"]
        return OwnedObjectPipelineResult(
            catalog_id=catalog.catalog_id,
            output_dir=output_path,
            generated_scenario_count=1,
            total_artifacts=1,
            summary_path=output_path / "pipeline-summary.json",
        )

    monkeypatch.setattr("vrp_hunt.cli.run_owned_object_pipeline", fake_pipeline)

    exit_code = main(
        [
            "owned-object-pipeline",
            "--object-catalog",
            str(catalog_path),
            "--output-dir",
            str(output_dir),
            "--yolo",
            "--researcher-account",
            "owned-a",
            "--researcher-account",
            "owned-b",
            "--derive-cookies-from-cdp",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert seen["catalog_id"] == "docs-baseline"
    assert seen["output_path"] == output_dir
    assert seen["yolo"] is True
    assert seen["derive_cookies_from_cdp"] is True
    assert output["total_artifacts"] == 1


def test_owned_object_pipeline_cli_rejects_unconfirmed_catalog(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text("catalog_id: bad\nresearcher_owned: false\n", encoding="utf-8")

    exit_code = main(
        [
            "owned-object-pipeline",
            "--object-catalog",
            str(catalog_path),
            "--output-dir",
            str(tmp_path / "pipeline"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "owned object pipeline error" in captured.err


def test_owned_permission_matrix_cli_runs_matrix(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import OwnedPermissionMatrixResult

    catalog_path = tmp_path / "catalog.yaml"
    matrix_path = tmp_path / "matrix.yaml"
    output_dir = tmp_path / "matrix-run"
    catalog_path.write_text(
        "\n".join(
            [
                "catalog_id: docs-baseline",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-a",
                "    cdp_url: http://127.0.0.1:9222",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "objects:",
                "  - object_id: owned-a-private-doc",
                "    product: docs",
                "    owner_account_id: owned-a",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_states:",
                "      owned-a: access_granted",
                "      owned-b: access_denied",
            ]
        ),
        encoding="utf-8",
    )
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
    seen: dict[str, object] = {}

    def fake_matrix(catalog, matrix, output_path, **kwargs):  # type: ignore[no-untyped-def]
        seen["catalog_id"] = catalog.catalog_id
        seen["matrix_id"] = matrix.matrix_id
        seen["output_path"] = output_path
        seen["derive_cookies_from_cdp"] = kwargs["derive_cookies_from_cdp"]
        seen["phase_ids"] = kwargs["phase_ids"]
        return OwnedPermissionMatrixResult(
            matrix_id=matrix.matrix_id,
            catalog_id=catalog.catalog_id,
            output_dir=output_path,
            total_artifacts=0,
            summary_path=output_path / "matrix-summary.json",
        )

    monkeypatch.setattr("vrp_hunt.cli.run_owned_permission_matrix", fake_matrix)

    exit_code = main(
        [
            "owned-permission-matrix",
            "--object-catalog",
            str(catalog_path),
            "--matrix",
            str(matrix_path),
            "--output-dir",
            str(output_dir),
            "--derive-cookies-from-cdp",
            "--phase",
            "private",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen == {
        "catalog_id": "docs-baseline",
        "matrix_id": "docs-share",
        "output_path": output_dir,
        "derive_cookies_from_cdp": True,
        "phase_ids": ["private"],
    }
    assert output["matrix_id"] == "docs-share"


def test_owned_permission_matrix_template_cli_writes_yaml(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    catalog_path = tmp_path / "catalog.yaml"
    matrix_path = tmp_path / "generated-matrix.yaml"
    catalog_path.write_text(
        "\n".join(
            [
                "catalog_id: docs-baseline",
                "researcher_owned: true",
                "accounts:",
                "  - account_id: owned-a",
                "    cdp_url: http://127.0.0.1:9222",
                "  - account_id: owned-b",
                "    cdp_url: http://127.0.0.1:9223",
                "objects:",
                "  - object_id: owned-a-private-doc",
                "    product: docs",
                "    owner_account_id: owned-a",
                "    url: https://docs.google.com/document/d/owned/edit",
                "    expected_states:",
                "      owned-a: access_granted",
                "      owned-b: access_denied",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "owned-permission-matrix-template",
            "--object-catalog",
            str(catalog_path),
            "--output-path",
            str(matrix_path),
            "--matrix-id",
            "docs-share-cycle",
            "--grantee-account",
            "owned-b",
            "--no-trash-phase",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output == {
        "matrix_id": "docs-share-cycle",
        "phase_count": 5,
        "output_path": str(matrix_path),
    }
    assert "shared-viewer" in matrix_path.read_text(encoding="utf-8")


def test_mobile_hypotheses_cli_writes_report(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    decompiled = tmp_path / "jadx"
    decompiled.mkdir()
    (decompiled / "Client.java").write_text(
        'String auth = "https://accounts.google.com/o/oauth2/v2/auth";',
        encoding="utf-8",
    )
    output_dir = tmp_path / "mobile-report"

    exit_code = main(
        [
            "mobile-hypotheses",
            "--app-id",
            "com.google.example",
            "--artifact-path",
            str(decompiled),
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["hypotheses"][0]["title"] == "OAuth redirect and account-switching review"
    assert (output_dir / "mobile-static-report.json").exists()


def test_mobile_import_cli_writes_report_and_assets(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    mobsf_report = tmp_path / "mobsf.json"
    mobsf_report.write_text(
        json.dumps(
            {
                "package_name": "com.google.example",
                "urls": ["https://accounts.google.com/o/oauth2/v2/auth?client_id=owned"],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "mobile-import"

    exit_code = main(
        [
            "mobile-import",
            "--app-id",
            "com.google.example",
            "--mobsf-report",
            str(mobsf_report),
            "--output-dir",
            str(output_dir),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["import_count"] == 1
    assert output["hypotheses"][0]["title"] == "OAuth redirect and account-switching review"
    assert (output_dir / "mobile-import-report.json").exists()
    assert (output_dir / "assets.jsonl").exists()


def test_mobile_import_cli_requires_artifact(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["mobile-import", "--app-id", "com.google.example"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "at least one" in captured.err


def test_dashboard_cli_writes_static_html(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    assets_path = tmp_path / "assets.jsonl"
    assets_path.write_text(
        json.dumps(
            {
                "kind": "url",
                "value": "https://accounts.google.com/o/oauth2/v2/auth?client_id=owned",
                "source": "test",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    approvals_path = tmp_path / "approval-queue.txt"
    approvals_path.write_text("APPROVE LIVE HTTPX https://www.google.com\n", encoding="utf-8")
    output_path = tmp_path / "dashboard.html"

    exit_code = main(
        [
            "dashboard",
            "--asset-file",
            str(assets_path),
            "--approval-queue",
            str(approvals_path),
            "--output",
            str(output_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    html = output_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["assets"] == 1
    assert output["approvals"] == 1
    assert "<html" in html
    assert "client_id=owned" not in html
    assert "[query keys: client_id]" in html


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


def test_live_recon_cli_builds_katana_action(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import AgentRunResult

    policy_path = tmp_path / "operator_policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'authorized_operator_id: "owner"',
                f'authorized_local_user: "{getpass.getuser()}"',
                "allowed_tools:",
                '  - "katana"',
                "require_liability_ack: true",
            ]
        ),
        encoding="utf-8",
    )
    seen: dict[str, str] = {}

    def fake_run_plan(self, plan):  # type: ignore[no-untyped-def]
        action = plan.actions[0]
        seen["tool"] = action.metadata["tool"]
        seen["depth"] = action.metadata["depth"]
        seen["js_crawl"] = action.metadata["js_crawl"]
        return AgentRunResult(completed_actions=1)

    monkeypatch.setattr("vrp_hunt.cli.AutonomousAgent.run_plan", fake_run_plan)

    exit_code = main(
        [
            "live-recon",
            "--tool",
            "katana",
            "--target",
            "https://www.google.com",
            "--operator-policy",
            str(policy_path),
            "--operator-id",
            "owner",
            "--accept-legal-liability",
            "--max-live-requests",
            "5",
            "--depth",
            "1",
            "--js-crawl",
        ]
    )

    json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen == {"tool": "katana", "depth": "1", "js_crawl": "true"}


def test_live_recon_cli_requires_nuclei_template(capsys) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit, match="--template"):
        main(
            [
                "live-recon",
                "--tool",
                "nuclei",
                "--target",
                "https://www.google.com",
                "--operator-id",
                "owner",
                "--accept-legal-liability",
            ]
        )


def test_recon_depth_cli_runs_balanced_pipeline(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import AgentObservation, AgentRunResult
    from vrp_hunt.recon import Asset

    policy_path = tmp_path / "operator_policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'authorized_operator_id: "owner"',
                f'authorized_local_user: "{getpass.getuser()}"',
                "allowed_tools:",
                '  - "subfinder"',
                '  - "httpx"',
                '  - "katana"',
                "require_liability_ack: true",
            ]
        ),
        encoding="utf-8",
    )
    seen: list[str] = []

    def fake_run_plan(self, plan):  # type: ignore[no-untyped-def]
        action = plan.actions[0]
        tool = action.metadata["tool"]
        seen.append(tool)
        if tool == "subfinder":
            assets = [
                Asset(kind="host", value="www.google.com", source="subfinder"),
                Asset(kind="host", value="out.example", source="subfinder"),
            ]
        elif tool == "httpx":
            assets = [Asset(kind="url", value="https://www.google.com", source="httpx")]
        else:
            assets = [Asset(kind="endpoint", value="https://www.google.com/about", source=tool)]
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

    monkeypatch.setattr("vrp_hunt.cli.AutonomousAgent.run_plan", fake_run_plan)

    exit_code = main(
        [
            "recon-depth",
            "--domain",
            "google.com",
            "--output-dir",
            str(tmp_path / "depth"),
            "--operator-policy",
            str(policy_path),
            "--operator-id",
            "owner",
            "--accept-legal-liability",
            "--max-hosts",
            "5",
            "--max-urls",
            "5",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen == ["subfinder", "httpx", "katana"]
    assert [phase["phase"] for phase in output["phase_runs"]] == [
        "subfinder",
        "httpx",
        "katana",
    ]
    depth_assets = (tmp_path / "depth" / "assets.jsonl").read_text(encoding="utf-8")
    assert "out.example" not in depth_assets


def test_program_list_cli_outputs_registry(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["program-list"])

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["programs"][0]["id"] == "google-alphabet-vrp"


def test_program_match_cli_returns_in_scope(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["program-match", "--target", "https://accounts.google.com/"])

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["decision"] == "IN_SCOPE"
    assert output["matched_entry_id"] == "google-web"


def test_program_match_cli_returns_nonzero_for_out_of_scope(
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    exit_code = main(["program-match", "--target", "foo.appspot.com"])

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["decision"] == "OUT_OF_SCOPE"
    assert output["matched_entry_id"] == "appspot-customer-app"


def test_program_diff_cli_outputs_fresh_targets(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.programs import ProgramScopeEntry, load_program_registry

    old_registry = load_program_registry()
    old_program = old_registry.programs[0]
    fresh_entry = ProgramScopeEntry(
        id="fresh-google-host",
        kind="exact_host",
        value="fresh.google.com",
        reward_eligible=True,
        notes="Fresh scoped host.",
        source_reference="test",
    )
    new_program = old_program.model_copy(update={"scope": [*old_program.scope, fresh_entry]})
    new_registry = old_registry.model_copy(
        update={"version": "program-registry-2026-05-17", "programs": [new_program]}
    )
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(old_registry.model_dump_json(indent=2), encoding="utf-8")
    new_path.write_text(new_registry.model_dump_json(indent=2), encoding="utf-8")

    exit_code = main(
        [
            "program-diff",
            "--old-registry",
            str(old_path),
            "--new-registry",
            str(new_path),
            "--fresh-only",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["fresh_target_count"] == 1
    assert output["fresh_targets"][0]["entry_id"] == "fresh-google-host"


def test_program_ingest_cli_writes_registry(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    input_path = tmp_path / "h1.json"
    output_path = tmp_path / "registry.json"
    input_path.write_text(
        json.dumps(
            {
                "handle": "google",
                "name": "Google VRP",
                "structured_scopes": [
                    {
                        "asset_identifier": "*.google.com",
                        "asset_type": "WILDCARD",
                        "eligible_for_submission": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "program-ingest",
            "--input",
            str(input_path),
            "--source",
            "hackerone",
            "--captured-date",
            "2026-05-16",
            "--output",
            str(output_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    written = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output["source"] == "hackerone"
    assert output["scope_count"] == 1
    assert written["programs"][0]["scope"][0]["value"] == "google.com"


def test_submission_checklist_cli_writes_assistance_and_markdown_for_draft_report(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import (
        AgentAction,
        AgentObservation,
        finding_from_observation,
        report_draft_from_finding,
    )
    from vrp_hunt.recon import Asset

    action = AgentAction(
        action_type="idor_validation",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="idor_testing",
        description="Prepare owned-account IDOR validation.",
    )
    observation = AgentObservation(
        action_id=action.action_id,
        success=True,
        assets=[Asset(kind="url", value=action.target, source="burp")],
    )
    finding = finding_from_observation(action, observation)
    report = report_draft_from_finding(finding, researcher_accounts=["owned-a", "owned-b"])
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "submission-assistance.json"
    markdown_path = tmp_path / "report.md"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    exit_code = main(
        [
            "submission-checklist",
            "--report",
            str(report_path),
            "--output",
            str(output_path),
            "--markdown-output",
            str(markdown_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    written = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert not output["ready"]
    assert output["program_decisions"][0]["program_id"] == "google-alphabet-vrp"
    assert any(item["name"] == "program-scope" and item["passed"] for item in output["checklist"])
    assert not written["ready"]
    assert "Draft IDOR candidate" in markdown_path.read_text(encoding="utf-8")


def test_recon_workflow_cli_runs_yaml_workflow(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.agent import AgentObservation, AgentRunResult
    from vrp_hunt.recon import Asset

    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text(
        f"""
version: "recon-workflow-v1"
name: "google-recon"
output_dir: "{tmp_path / "workflow-output"}"
defaults:
  profile: "passive"
steps:
  - id: "google-passive"
    kind: "recon_depth"
    domain: "google.com"
""",
        encoding="utf-8",
    )
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
    seen: list[str] = []

    def fake_run_plan(self, plan):  # type: ignore[no-untyped-def]
        action = plan.actions[0]
        seen.append(action.metadata["tool"])
        return AgentRunResult(
            observations=[
                AgentObservation(
                    action_id=action.action_id,
                    success=True,
                    assets=[Asset(kind="host", value="www.google.com", source="subfinder")],
                    request_count=action.request_budget,
                )
            ],
            completed_actions=1,
        )

    monkeypatch.setattr("vrp_hunt.cli.AutonomousAgent.run_plan", fake_run_plan)

    exit_code = main(
        [
            "recon-workflow",
            "--workflow",
            str(workflow_path),
            "--operator-policy",
            str(policy_path),
            "--operator-id",
            "owner",
            "--accept-legal-liability",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen == ["subfinder"]
    assert output["step_runs"][0]["step_id"] == "google-passive"
    assert output["step_runs"][0]["result"]["profile"] == "passive"


def test_passive_sources_cli_reports_health(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    catalog_path = tmp_path / "sources.yaml"
    catalog_path.write_text(
        """
version: "test"
sources:
  - id: "github"
    name: "GitHub"
    categories: ["code"]
    required_env: ["GITHUB_TOKEN"]
    source_reference: "test"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_TOKEN", "secret-value")

    exit_code = main(["passive-sources", "--catalog", str(catalog_path)])

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["ready_sources"] == 1
    assert output["sources"][0]["configured_env"] == ["GITHUB_TOKEN"]
    assert "secret-value" not in json.dumps(output)


def test_passive_sources_env_template_cli_writes_template(tmp_path: Path) -> None:
    catalog_path = tmp_path / "sources.yaml"
    output_path = tmp_path / ".env.example"
    catalog_path.write_text(
        """
version: "test"
sources:
  - id: "shodan"
    name: "Shodan"
    categories: ["search"]
    required_env: ["SHODAN_API_KEY"]
    source_reference: "test"
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "passive-sources-env-template",
            "--catalog",
            str(catalog_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert "SHODAN_API_KEY=" in output_path.read_text(encoding="utf-8")


def test_asset_score_cli_scores_asset_file(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    from vrp_hunt.recon import Asset

    asset_file = tmp_path / "assets.jsonl"
    asset_file.write_text(
        Asset(kind="url", value="https://www.google.com", source="httpx").model_dump_json() + "\n",
        encoding="utf-8",
    )

    exit_code = main(["asset-score", "--asset-file", str(asset_file)])

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["total_assets"] == 1
    assert output["scores"][0]["asset"]["value"] == "https://www.google.com"
    assert output["scores"][0]["priority"] > 0


def test_asset_score_cli_writes_output(tmp_path: Path) -> None:
    output_path = tmp_path / "scores.json"

    exit_code = main(
        [
            "asset-score",
            "--asset",
            "host:www.google.com",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    output = json.loads(output_path.read_text(encoding="utf-8"))
    assert output["scores"][0]["asset"]["value"] == "www.google.com"


def test_wildcard_dns_filter_cli_writes_filtered_assets(tmp_path: Path) -> None:
    from vrp_hunt.recon import Asset

    asset_file = tmp_path / "assets.jsonl"
    output_path = tmp_path / "wildcard-report.json"
    filtered_path = tmp_path / "filtered-assets.jsonl"
    assets = [
        Asset(
            kind="host",
            value="www.google.com",
            source="dns",
            metadata={"addresses": "142.250.1.1"},
        ),
        Asset(
            kind="host",
            value="random-looking.google.com",
            source="dns",
            metadata={"addresses": "203.0.113.10"},
        ),
    ]
    asset_file.write_text(
        "\n".join(asset.model_dump_json() for asset in assets) + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "wildcard-dns-filter",
            "--asset-file",
            str(asset_file),
            "--probe",
            "probe-one.google.com=203.0.113.10",
            "--probe",
            "probe-two.google.com=203.0.113.10",
            "--output",
            str(output_path),
            "--assets-output",
            str(filtered_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output["patterns"][0]["domain"] == "google.com"
    assert output["eliminated_assets"][0]["value"] == "random-looking.google.com"
    assert "random-looking.google.com" not in filtered_path.read_text(encoding="utf-8")


def test_dns_record_plan_and_import_cli_write_outputs(tmp_path: Path) -> None:
    plan_path = tmp_path / "dns-plan.json"
    records_path = tmp_path / "dns-records.json"
    mx_path = tmp_path / "mx.txt"
    txt_path = tmp_path / "txt.txt"
    mx_path.write_text("10 smtp.google.com.\n", encoding="utf-8")
    txt_path.write_text('"v=spf1 include:_spf.google.com ~all"\n', encoding="utf-8")

    plan_exit = main(
        [
            "dns-record-plan",
            "--domain",
            "google.com",
            "--output",
            str(plan_path),
        ]
    )
    import_exit = main(
        [
            "dns-record-import",
            "--domain",
            "google.com",
            "--record",
            f"google.com:MX={mx_path}",
            "--record",
            f"google.com:TXT={txt_path}",
            "--output",
            str(records_path),
        ]
    )

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    records = json.loads(records_path.read_text(encoding="utf-8"))

    assert plan_exit == 0
    assert import_exit == 0
    assert ["dig", "+short", "TXT", "_dmarc.google.com"] in [
        query["command"] for query in plan["queries"]
    ]
    assert [record["record_type"] for record in records["records"]] == ["MX", "SPF"]


def test_cdn_waf_fingerprint_cli_writes_report_and_assets(tmp_path: Path) -> None:
    from vrp_hunt.recon import Asset, DnsRecord, DnsRecordCollection

    asset_file = tmp_path / "assets.jsonl"
    dns_path = tmp_path / "dns-records.json"
    output_path = tmp_path / "cdn-waf.json"
    assets_path = tmp_path / "cdn-waf-assets.jsonl"
    asset_file.write_text(
        Asset(
            kind="url",
            value="https://www.google.com/",
            source="httpx",
            metadata={"header:cf-ray": "abc", "webserver": "cloudflare"},
        ).model_dump_json()
        + "\n",
        encoding="utf-8",
    )
    dns_path.write_text(
        DnsRecordCollection(
            domain="google.com",
            records=[
                DnsRecord(
                    name="static.google.com",
                    record_type="CNAME",
                    value="d123.cloudfront.net",
                    source="fixture",
                )
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "cdn-waf-fingerprint",
            "--asset-file",
            str(asset_file),
            "--dns-records",
            str(dns_path),
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert {item["provider"] for item in output["fingerprints"]} == {
        "Cloudflare",
        "Amazon CloudFront",
    }
    assert "cdn-waf-fingerprint" in assets_path.read_text(encoding="utf-8")


def test_asn_netblock_import_cli_writes_report_and_assets(tmp_path: Path) -> None:
    output_path = tmp_path / "netblocks.json"
    assets_path = tmp_path / "netblock-assets.jsonl"

    exit_code = main(
        [
            "asn-netblock-import",
            "--record",
            "AS15169:Google LLC=8.8.8.8/24",
            "--record",
            "AS15169:Google LLC=2001:4860::/32",
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    assets_text = assets_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["total_asns"] == 1
    assert output["total_netblocks"] == 2
    assert output["records"][0]["cidr"] == "8.8.8.0/24"
    assert "asn-netblock:AS15169:8.8.8.0/24" in assets_text


def test_reverse_ct_import_cli_writes_scoped_hosts(tmp_path: Path) -> None:
    reverse_path = tmp_path / "reverse.json"
    ct_path = tmp_path / "ct.json"
    output_path = tmp_path / "reverse-ct.json"
    assets_path = tmp_path / "reverse-ct-assets.jsonl"
    reverse_path.write_text(
        json.dumps(
            [
                {
                    "ip": "203.0.113.10",
                    "hosts": ["www.google.com", "not-in-scope.example"],
                }
            ]
        ),
        encoding="utf-8",
    )
    ct_path.write_text(
        json.dumps([{"name_value": "*.mail.google.com\naccounts.google.com"}]),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "reverse-ct-import",
            "--reverse-ip",
            str(reverse_path),
            "--ct",
            str(ct_path),
            "--scope-domain",
            "google.com",
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    assets_text = assets_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["total_records"] == 3
    assert {asset["value"] for asset in output["assets"]} == {
        "accounts.google.com",
        "mail.google.com",
        "www.google.com",
    }
    assert "not-in-scope.example" not in assets_text


def test_subdomain_permute_cli_writes_capped_candidates(tmp_path: Path) -> None:
    output_path = tmp_path / "permutations.json"
    assets_path = tmp_path / "permutation-assets.jsonl"
    words_path = tmp_path / "words.txt"
    words_path.write_text("admin\nlogin\n", encoding="utf-8")

    exit_code = main(
        [
            "subdomain-permute",
            "--seed",
            "accounts.google.com",
            "--scope-domain",
            "google.com",
            "--word-file",
            str(words_path),
            "--max-candidates",
            "3",
            "--max-per-seed",
            "3",
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    assets_text = assets_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["total_candidates"] == 3
    assert output["truncated"]
    assert output["candidates"][0]["host"] == "admin.google.com"
    assert "subdomain-permutation" in assets_text


def test_recursive_passive_plan_cli_writes_followup_queue(tmp_path: Path) -> None:
    from vrp_hunt.recon import Asset

    asset_file = tmp_path / "hosts.jsonl"
    output_path = tmp_path / "recursive-passive.json"
    assets_path = tmp_path / "recursive-passive-assets.jsonl"
    asset_file.write_text(
        "\n".join(
            [
                Asset(kind="host", value="a.mail.google.com", source="fixture").model_dump_json(),
                Asset(kind="host", value="b.mail.google.com", source="fixture").model_dump_json(),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "recursive-passive-plan",
            "--asset-file",
            str(asset_file),
            "--seed-domain",
            "google.com",
            "--min-hosts-per-zone",
            "2",
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    assets_text = assets_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["candidates"][0]["zone"] == "mail.google.com"
    assert output["candidates"][0]["command"] == [
        "subfinder",
        "-d",
        "mail.google.com",
        "-oJ",
        "-silent",
    ]
    assert "recursive-passive-plan" in assets_text


def test_historical_url_import_cli_writes_scoped_assets(tmp_path: Path) -> None:
    wayback_path = tmp_path / "wayback.json"
    output_path = tmp_path / "historical-urls.json"
    assets_path = tmp_path / "historical-assets.jsonl"
    wayback_path.write_text(
        json.dumps(
            [
                ["timestamp", "original", "mimetype", "statuscode"],
                ["20260101000000", "https://accounts.google.com/profile?id=secret", "text/html", "200"],
                ["20260101000001", "https://evil.com/path", "text/html", "200"],
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "historical-url-import",
            "--wayback",
            str(wayback_path),
            "--scope-domain",
            "google.com",
            "--output",
            str(output_path),
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    assets_text = assets_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output["total_records"] == 1
    assert output["records"][0]["url"] == "https://accounts.google.com/profile"
    assert output["records"][0]["parameter_names"] == ["id"]
    assert "secret" not in assets_text
    assert "historical-url-import" in assets_text


def test_endpoint_mine_cli_mines_saved_document(
    tmp_path: Path,
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    page_path = tmp_path / "page.html"
    assets_path = tmp_path / "assets.jsonl"
    page_path.write_text(
        '<script src="/app.js?build=123"></script>fetch("/api/me?id=owned-a")',
        encoding="utf-8",
    )

    exit_code = main(
        [
            "endpoint-mine",
            "--document",
            f"https://www.google.com/={page_path}",
            "--scope-domain",
            "google.com",
            "--assets-output",
            str(assets_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    asset_lines = assets_path.read_text(encoding="utf-8").splitlines()

    assert exit_code == 0
    assert output["document_count"] == 1
    assert "https://www.google.com/app.js" in {asset["value"] for asset in output["assets"]}
    assert "https://www.google.com/api/me" in {asset["value"] for asset in output["assets"]}
    assert asset_lines


def test_endpoint_mine_cli_rejects_missing_documents(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["endpoint-mine"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "at least one --document" in captured.err


def test_owned_crawl_plan_cli_writes_assets_and_plan(tmp_path: Path) -> None:
    page_path = tmp_path / "owned.html"
    assets_path = tmp_path / "assets.jsonl"
    plan_path = tmp_path / "plan.json"
    page_path.write_text(
        """
        <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=owned">oauth</a>
        <form method="post" action="/document/d/owned/update">
          <input name="csrf_token" value="redacted">
        </form>
        """,
        encoding="utf-8",
    )

    exit_code = main(
        [
            "owned-crawl-plan",
            "--page",
            f"owned-a=https://docs.google.com/document/d/owned/edit={page_path}",
            "--scope-domain",
            "google.com",
            "--assets-output",
            str(assets_path),
            "--plan-output",
            str(plan_path),
        ]
    )

    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert assets_path.exists()
    assert {
        "oauth_validation",
        "csrf_validation",
    } <= {action["action_type"] for action in plan["actions"]}


def test_owned_crawl_plan_cli_rejects_missing_pages(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["owned-crawl-plan"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "at least one --page" in captured.err
