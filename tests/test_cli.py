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
