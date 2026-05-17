"""Command-line entry point for VRP Hunt."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from vrp_hunt.agent import (
    ActionBudget,
    ActionRunner,
    AgentAction,
    AgentArtifactBundle,
    AgentPlan,
    ApprovalGateError,
    ApprovalMode,
    ApprovedSubprocessRunner,
    AutonomyPolicy,
    AutonomousAgent,
    BrowserAccessState,
    BrowserCheckError,
    DerivedHttpCheckError,
    DerivedHttpMethod,
    LiveReconAuthorizationError,
    LiveReconRunner,
    ModelProviderError,
    ModelProviderName,
    OwnedBrowserScenarioError,
    OwnedObjectPipelineError,
    OwnedPermissionMatrixError,
    apply_approval_gate,
    artifact_bundle_from_agent_run,
    artifact_bundle_from_derived_http_check,
    artifact_bundle_from_owned_browser_scenario,
    build_agent_brain,
    build_agent_plan,
    cookie_header_from_env,
    build_offline_analysis_plan,
    build_recon_iteration_summary,
    expand_owned_browser_scenario_derived_urls,
    load_derived_http_check_result,
    load_operator_policy,
    load_owned_browser_scenario,
    load_owned_browser_scenario_result,
    load_owned_object_catalog,
    load_owned_permission_matrix,
    run_derived_http_check,
    run_owned_browser_check,
    run_owned_browser_check_cdp,
    run_owned_browser_scenario,
    run_owned_object_pipeline,
    run_owned_permission_matrix,
    write_generated_owned_browser_scenarios,
    write_owned_permission_matrix_template,
    write_recon_iteration_outputs,
)
from vrp_hunt.agent.runners import build_safe_offline_runner, build_safe_validation_runner
from vrp_hunt.mobile_recon import build_mobile_static_report
from vrp_hunt.recon import Asset
from vrp_hunt.reporting import Platform, render_markdown_report


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "agent-plan":
        return _agent_plan(args)
    if args.command == "agent-run":
        return _agent_run(args)
    if args.command == "agent-auto":
        return _agent_auto(args)
    if args.command == "recon-iterate":
        return _recon_iterate(args)
    if args.command == "owned-browser-check":
        return _owned_browser_check(args)
    if args.command == "owned-browser-scenario":
        return _owned_browser_scenario(args)
    if args.command == "scenario-generate":
        return _scenario_generate(args)
    if args.command == "scenario-artifacts":
        return _scenario_artifacts(args)
    if args.command == "derived-http-check":
        return _derived_http_check(args)
    if args.command == "derived-http-artifacts":
        return _derived_http_artifacts(args)
    if args.command == "owned-object-pipeline":
        return _owned_object_pipeline(args)
    if args.command == "owned-permission-matrix-template":
        return _owned_permission_matrix_template(args)
    if args.command == "owned-permission-matrix":
        return _owned_permission_matrix(args)
    if args.command == "mobile-hypotheses":
        return _mobile_hypotheses(args)
    if args.command == "live-recon":
        return _live_recon(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vrp-hunt")
    subparsers = parser.add_subparsers(dest="command")

    plan = subparsers.add_parser("agent-plan", help="Build an autonomous agent plan")
    _add_agent_inputs(plan)
    _add_model_inputs(plan)
    plan.add_argument("--mode", choices=("offline", "testing"), default="offline")
    plan.add_argument("--max-actions", type=int, default=10)

    run = subparsers.add_parser("agent-run", help="Run a safe autonomous agent plan")
    _add_agent_inputs(run)
    _add_model_inputs(run)
    run.add_argument("--mode", choices=("offline", "testing"), default="offline")
    run.add_argument("--max-actions", type=int, default=10)
    run.add_argument("--execute-safe", action="store_true", help="Execute safe non-traffic handlers")
    run.add_argument(
        "--approve-risky",
        action="store_true",
        help="Legacy shortcut: approve all approval-required actions for this run",
    )
    run.add_argument(
        "--approval-mode",
        choices=("block", "explicit", "prompt", "approve-all"),
        default="block",
        help="How the CLI approval gate handles risky actions",
    )
    run.add_argument(
        "--approve-action",
        action="append",
        default=[],
        help="Approve one risky action by 1-based index, action id, or 'all'",
    )
    run.add_argument(
        "--yolo",
        action="store_true",
        help="Approve all approval-required actions without disabling guardrails or budgets",
    )
    run.add_argument("--max-live-requests", type=int, default=0)

    auto = subparsers.add_parser(
        "agent-auto",
        help="Run an approval-gated safe pipeline and emit report artifacts",
    )
    _add_agent_inputs(auto)
    _add_model_inputs(auto)
    _add_approval_inputs(auto)
    _add_artifact_inputs(auto)
    auto.add_argument("--mode", choices=("offline", "testing"), default="testing")
    auto.add_argument("--max-actions", type=int, default=10)
    auto.add_argument("--max-live-requests", type=int, default=0)
    auto.add_argument(
        "--artifact-output-dir",
        type=Path,
        help="Optional directory for plan.json, run.json, and artifact-bundle.json",
    )

    iterate = subparsers.add_parser(
        "recon-iterate",
        help="Rank passive recon output and emit the next approval queue",
    )
    iterate.add_argument("--run-json", type=Path, required=True, help="live-recon JSON output to rank")
    iterate.add_argument(
        "--httpx-dir",
        type=Path,
        action="append",
        default=[],
        help="Optional directory of prior httpx live-recon JSON outputs to exclude failed hosts",
    )
    iterate.add_argument("--limit", type=int, default=10, help="Maximum approval candidates to emit")
    iterate.add_argument("--output-dir", type=Path, help="Directory for ranked-targets and approval queue files")

    browser_check = subparsers.add_parser(
        "owned-browser-check",
        help="Check one explicit owned-object URL in an authenticated test profile",
    )
    browser_check.add_argument("--account-id", required=True, help="Owned account alias, e.g. owned-b")
    browser_check.add_argument(
        "--profile-dir",
        type=Path,
        help="Persistent browser profile directory for the owned account",
    )
    browser_check.add_argument(
        "--cdp-url",
        help="Attach to an already-open local Chrome instance with remote debugging enabled",
    )
    browser_check.add_argument("--url", required=True, help="Exact owned Drive/Docs/Sites object URL")
    browser_check.add_argument(
        "--confirm-owned-object",
        action="store_true",
        help="Confirm the URL points only to a researcher-owned test object",
    )
    browser_check.add_argument("--headless", action="store_true", help="Run Chrome headless")
    browser_check.add_argument("--timeout-ms", type=int, default=15_000)
    browser_check.add_argument("--output-path", type=Path, help="Optional JSON output path")

    scenario = subparsers.add_parser(
        "owned-browser-scenario",
        help="Run a bounded owned-object browser access scenario",
    )
    scenario.add_argument("--scenario", type=Path, required=True, help="YAML or JSON scenario file")
    scenario.add_argument(
        "--expand-derived",
        action="store_true",
        help="Check derived view/edit/preview URLs for each exact owned-object URL",
    )
    scenario.add_argument("--max-steps", type=int, default=25)
    scenario.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through access-state mismatches without disabling owned-object checks",
    )
    scenario.add_argument("--output-dir", type=Path, help="Optional directory for scenario-result.json")

    scenario_generate = subparsers.add_parser(
        "scenario-generate",
        help="Generate owned-browser scenarios from an owned-object catalog",
    )
    scenario_generate.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and expected access states",
    )
    scenario_generate.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for generated scenario YAML files and scenario-index.json",
    )

    scenario_artifacts = subparsers.add_parser(
        "scenario-artifacts",
        help="Convert owned-browser scenario mismatches into draft finding artifacts",
    )
    scenario_artifacts.add_argument("--scenario", type=Path, required=True)
    scenario_artifacts.add_argument("--scenario-result", type=Path, required=True)
    scenario_artifacts.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for artifact-bundle.json, findings, reports, and Markdown drafts",
    )
    _add_artifact_inputs(scenario_artifacts)

    derived_http = subparsers.add_parser(
        "derived-http-check",
        help="Run metadata-only checks for derived owned-object HTTP resources",
    )
    derived_http.add_argument("--account-id", required=True, help="Owned test-account alias")
    derived_http.add_argument("--url", required=True, help="Exact owned Drive/Docs object URL")
    derived_http.add_argument(
        "--cookie-env",
        required=True,
        help="Env var containing the Cookie header value; value is never written to artifacts",
    )
    derived_http.add_argument(
        "--expected-state",
        choices=("access_denied", "access_granted", "login_required", "unknown"),
        required=True,
    )
    derived_http.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    derived_http.add_argument("--max-targets", type=int, default=25)
    derived_http.add_argument("--max-redirects", type=int, default=2)
    derived_http.add_argument("--timeout-seconds", type=float, default=10.0)
    derived_http.add_argument(
        "--confirm-owned-object",
        action="store_true",
        help="Confirm the URL points only to a researcher-owned non-sensitive test object",
    )
    derived_http.add_argument("--output-dir", type=Path, help="Optional directory for derived-http-result.json")

    derived_artifacts = subparsers.add_parser(
        "derived-http-artifacts",
        help="Convert derived HTTP metadata mismatches into draft finding artifacts",
    )
    derived_artifacts.add_argument("--derived-http-result", type=Path, required=True)
    derived_artifacts.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for artifact-bundle.json, findings, reports, and Markdown drafts",
    )
    _add_artifact_inputs(derived_artifacts)

    pipeline = subparsers.add_parser(
        "owned-object-pipeline",
        help="Run the owned-object scenario, derived HTTP, and artifact pipeline",
    )
    pipeline.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and expected access states",
    )
    pipeline.add_argument("--output-dir", type=Path, required=True)
    pipeline.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through scenario mismatches without disabling safety checks",
    )
    pipeline.add_argument("--max-steps", type=int, default=50)
    pipeline.add_argument(
        "--no-expand-derived",
        action="store_true",
        help="Do not expand browser scenarios to view/edit/preview variants",
    )
    pipeline.add_argument(
        "--skip-derived-http",
        action="store_true",
        help="Skip metadata-only derived HTTP checks",
    )
    pipeline.add_argument("--derived-method", choices=("HEAD", "GET"), default="HEAD")
    pipeline.add_argument("--derived-max-targets", type=int, default=25)
    pipeline.add_argument("--derived-max-redirects", type=int, default=2)
    pipeline.add_argument("--derived-timeout-seconds", type=float, default=10.0)
    pipeline.add_argument(
        "--derive-cookies-from-cdp",
        action="store_true",
        help=(
            "For derived HTTP checks, read cookies in memory from each account's local CDP "
            "browser when cookie_env is missing or unset"
        ),
    )
    _add_artifact_inputs(pipeline)

    matrix = subparsers.add_parser(
        "owned-permission-matrix",
        help="Run owned-object checks across declared permission phases",
    )
    matrix.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and test accounts",
    )
    matrix.add_argument(
        "--matrix",
        type=Path,
        required=True,
        help="YAML or JSON permission matrix with phase expected states",
    )
    matrix.add_argument("--output-dir", type=Path, required=True)
    matrix.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through scenario mismatches without disabling safety checks",
    )
    matrix.add_argument("--max-steps", type=int, default=50)
    matrix.add_argument(
        "--no-expand-derived",
        action="store_true",
        help="Do not expand browser scenarios to view/edit/preview variants",
    )
    matrix.add_argument(
        "--skip-derived-http",
        action="store_true",
        help="Skip metadata-only derived HTTP checks",
    )
    matrix.add_argument("--derived-method", choices=("HEAD", "GET"), default="HEAD")
    matrix.add_argument("--derived-max-targets", type=int, default=25)
    matrix.add_argument("--derived-max-redirects", type=int, default=2)
    matrix.add_argument("--derived-timeout-seconds", type=float, default=10.0)
    matrix.add_argument(
        "--phase",
        action="append",
        default=[],
        help="Run one phase id from the matrix; repeat to run multiple phases",
    )
    matrix.add_argument(
        "--derive-cookies-from-cdp",
        action="store_true",
        help=(
            "For derived HTTP checks, read cookies in memory from each account's local CDP "
            "browser when cookie_env is missing or unset"
        ),
    )
    _add_artifact_inputs(matrix)

    matrix_template = subparsers.add_parser(
        "owned-permission-matrix-template",
        help="Generate an owned-object permission transition matrix template",
    )
    matrix_template.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and test accounts",
    )
    matrix_template.add_argument(
        "--output-path",
        type=Path,
        required=True,
        help="YAML path for the generated permission matrix template",
    )
    matrix_template.add_argument("--matrix-id", help="Optional matrix id; defaults from catalog id")
    matrix_template.add_argument(
        "--grantee-account",
        action="append",
        default=[],
        help="Owned account to grant in direct-share phases; defaults to non-owner accounts",
    )
    matrix_template.add_argument(
        "--no-trash-phase",
        action="store_true",
        help="Do not include the trashed-or-archived phase",
    )

    mobile = subparsers.add_parser(
        "mobile-hypotheses",
        help="Rank passive hypotheses from JADX/decompiled mobile artifacts",
    )
    mobile.add_argument("--app-id", required=True, help="Mobile package id, e.g. com.google.android.gm")
    mobile.add_argument(
        "--artifact-path",
        type=Path,
        required=True,
        help="JADX output directory or local decompiled text artifact",
    )
    mobile.add_argument("--limit", type=int, default=10, help="Maximum hypotheses to emit")
    mobile.add_argument("--output-dir", type=Path, help="Optional directory for mobile-static-report.json")

    live = subparsers.add_parser("live-recon", help="Run one approved live recon tool")
    live.add_argument("--tool", choices=("subfinder", "httpx", "jadx"), required=True)
    live.add_argument("--target", required=True, help="Domain/host/URL, or mobile app id for jadx")
    live.add_argument("--artifact-path", help="APK path for jadx static analysis")
    live.add_argument("--output-dir", help="jadx output directory")
    live.add_argument("--publisher", help="Mobile app publisher for guardrail scope checks")
    live.add_argument("--rate-limit-per-minute", type=int, default=5)
    live.add_argument("--max-live-requests", type=int, default=1)
    live.add_argument("--operator-policy", type=Path, default=None)
    live.add_argument("--operator-id", default=os.getenv("VRP_HUNT_OPERATOR_ID"))
    live.add_argument(
        "--accept-legal-liability",
        action="store_true",
        help="Acknowledge that the configured operator is legally liable for this live run",
    )

    return parser


def _add_agent_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--asset",
        action="append",
        default=[],
        help="Asset as kind:value, for example url:https://accounts.google.com/profile",
    )
    parser.add_argument("--asset-file", type=Path, help="JSONL file containing Asset records")


def _add_model_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model-provider",
        choices=("heuristic", "openai"),
        default=_default_model_provider(),
        help="Hypothesis provider for ModelBrain; heuristic stays local",
    )
    parser.add_argument("--model", default=os.getenv("VRP_HUNT_OPENAI_MODEL"))
    parser.add_argument(
        "--model-base-url",
        default=os.getenv("VRP_HUNT_OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )
    parser.add_argument("--model-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--model-max-assets", type=int, default=50)
    parser.add_argument(
        "--allow-remote-model",
        action="store_true",
        help="Allow redacted recon asset summaries to be sent to the configured model provider",
    )


def _add_approval_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--approve-risky",
        action="store_true",
        help="Legacy shortcut: approve all approval-required actions for this run",
    )
    parser.add_argument(
        "--approval-mode",
        choices=("block", "explicit", "prompt", "approve-all"),
        default="block",
        help="How the CLI approval gate handles risky actions",
    )
    parser.add_argument(
        "--approve-action",
        action="append",
        default=[],
        help="Approve one risky action by 1-based index, action id, or 'all'",
    )
    parser.add_argument(
        "--yolo",
        action="store_true",
        help="Approve all approval-required actions without disabling guardrails or budgets",
    )


def _add_artifact_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--researcher-account",
        action="append",
        default=[],
        help="Owned test-account alias for generated report artifacts; never pass secrets",
    )
    parser.add_argument("--product", default="Google")
    parser.add_argument("--component", default="VRP target")
    parser.add_argument(
        "--platform",
        choices=("web", "api", "android", "ios", "browser_extension", "other"),
        default="web",
    )
    parser.add_argument("--client", default="Chrome stable with Burp proxy")
    parser.add_argument("--operating-system", default="research workstation")
    parser.add_argument("--observed-from", default="owned-account validation environment")


def _agent_plan(args: argparse.Namespace) -> int:
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    print(plan.model_dump_json(indent=2))
    return 0


def _agent_run(args: argparse.Namespace) -> int:
    policy = AutonomyPolicy(dry_run=not args.execute_safe)
    budget = ActionBudget(max_actions=args.max_actions, max_live_requests=args.max_live_requests)
    runner = _safe_runner_for_mode(args.mode) if args.execute_safe else None
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    try:
        plan = _apply_cli_approval_gate(plan, policy, args)
    except ApprovalGateError as exc:
        print(f"approval gate error: {exc}", file=sys.stderr)
        return 2
    result = AutonomousAgent(policy=policy, budget=budget, runner=runner).run_plan(plan)
    print(result.model_dump_json(indent=2))
    return 0 if not result.stopped else 1


def _agent_auto(args: argparse.Namespace) -> int:
    policy = AutonomyPolicy(dry_run=False)
    budget = ActionBudget(max_actions=args.max_actions, max_live_requests=args.max_live_requests)
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    try:
        gated_plan = _apply_cli_approval_gate(plan, policy, args)
    except ApprovalGateError as exc:
        print(f"approval gate error: {exc}", file=sys.stderr)
        return 2

    result = AutonomousAgent(
        policy=policy,
        budget=budget,
        runner=_safe_runner_for_mode(args.mode),
    ).run_plan(gated_plan)
    bundle = artifact_bundle_from_agent_run(
        gated_plan,
        result,
        researcher_accounts=_artifact_researcher_accounts(args),
        product=args.product,
        component=args.component,
        platform=cast(Platform, args.platform),
        client=args.client,
        operating_system=args.operating_system,
        observed_from=args.observed_from,
    )
    output = {
        "plan": gated_plan.model_dump(mode="json"),
        "run": result.model_dump(mode="json"),
        "artifacts": bundle.model_dump(mode="json"),
    }
    if args.artifact_output_dir is not None:
        _write_auto_artifacts(args.artifact_output_dir, output)
    print(json.dumps(output, indent=2))
    return 0 if not result.stopped else 1


def _recon_iterate(args: argparse.Namespace) -> int:
    if args.limit < 1:
        print("recon iterate error: --limit must be at least 1", file=sys.stderr)
        return 2
    try:
        summary = build_recon_iteration_summary(
            args.run_json,
            httpx_dirs=args.httpx_dir,
            limit=args.limit,
        )
        if args.output_dir is not None:
            write_recon_iteration_outputs(summary, args.output_dir)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"recon iterate error: {exc}", file=sys.stderr)
        return 2

    print(summary.model_dump_json(indent=2))
    return 0


def _owned_browser_check(args: argparse.Namespace) -> int:
    try:
        if args.cdp_url:
            result = run_owned_browser_check_cdp(
                account_id=args.account_id,
                cdp_url=args.cdp_url,
                url=args.url,
                confirm_owned_object=args.confirm_owned_object,
                timeout_ms=args.timeout_ms,
            )
        else:
            if args.profile_dir is None:
                raise BrowserCheckError("--profile-dir is required unless --cdp-url is used")
            result = run_owned_browser_check(
                account_id=args.account_id,
                profile_dir=args.profile_dir,
                url=args.url,
                confirm_owned_object=args.confirm_owned_object,
                headless=args.headless,
                timeout_ms=args.timeout_ms,
            )
    except BrowserCheckError as exc:
        print(f"owned browser check error: {exc}", file=sys.stderr)
        return 2
    output = result.model_dump_json(indent=2)
    if args.output_path is not None:
        args.output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output_path.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


def _owned_browser_scenario(args: argparse.Namespace) -> int:
    if args.max_steps < 1:
        print("owned browser scenario error: --max-steps must be at least 1", file=sys.stderr)
        return 2
    try:
        scenario = load_owned_browser_scenario(args.scenario)
        if args.expand_derived:
            scenario = expand_owned_browser_scenario_derived_urls(
                scenario,
                max_steps=args.max_steps,
            )
        elif len(scenario.steps) > args.max_steps:
            raise OwnedBrowserScenarioError(f"scenario exceeds --max-steps={args.max_steps}")
        if args.yolo:
            scenario = scenario.model_copy(update={"stop_on_mismatch": False})
        result = run_owned_browser_scenario(scenario)
    except OwnedBrowserScenarioError as exc:
        print(f"owned browser scenario error: {exc}", file=sys.stderr)
        return 2

    output = result.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "scenario-result.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if result.mismatches or result.errors or result.stopped else 0


def _scenario_generate(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        result = write_generated_owned_browser_scenarios(catalog, args.output_dir)
    except OwnedBrowserScenarioError as exc:
        print(f"scenario generate error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 0


def _scenario_artifacts(args: argparse.Namespace) -> int:
    try:
        scenario = load_owned_browser_scenario(args.scenario)
        result = load_owned_browser_scenario_result(args.scenario_result)
        bundle = artifact_bundle_from_owned_browser_scenario(
            scenario,
            result,
            researcher_accounts=_artifact_researcher_accounts(args),
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except OwnedBrowserScenarioError as exc:
        print(f"scenario artifacts error: {exc}", file=sys.stderr)
        return 2

    files = _write_scenario_artifacts(args.output_dir, bundle)
    output = {
        "artifacts": bundle.model_dump(mode="json"),
        "files": files,
    }
    print(json.dumps(output, indent=2))
    return 0


def _derived_http_check(args: argparse.Namespace) -> int:
    try:
        result = run_derived_http_check(
            account_id=args.account_id,
            owned_object_url=args.url,
            expected_state=cast(BrowserAccessState, args.expected_state),
            cookie_header=cookie_header_from_env(args.cookie_env),
            confirm_owned_object=args.confirm_owned_object,
            method=cast(DerivedHttpMethod, args.method),
            max_targets=args.max_targets,
            timeout_seconds=args.timeout_seconds,
            max_redirects=args.max_redirects,
        )
    except DerivedHttpCheckError as exc:
        print(f"derived http check error: {exc}", file=sys.stderr)
        return 2

    output = result.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "derived-http-result.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if result.high_signal_mismatches or result.errors else 0


def _derived_http_artifacts(args: argparse.Namespace) -> int:
    try:
        result = load_derived_http_check_result(args.derived_http_result)
        bundle = artifact_bundle_from_derived_http_check(
            result,
            researcher_accounts=_artifact_researcher_accounts(args),
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except DerivedHttpCheckError as exc:
        print(f"derived http artifacts error: {exc}", file=sys.stderr)
        return 2

    files = _write_scenario_artifacts(args.output_dir, bundle)
    output = {
        "artifacts": bundle.model_dump(mode="json"),
        "files": files,
    }
    print(json.dumps(output, indent=2))
    return 0


def _owned_object_pipeline(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        result = run_owned_object_pipeline(
            catalog,
            args.output_dir,
            researcher_accounts=_artifact_researcher_accounts(args),
            yolo=args.yolo,
            expand_derived=not args.no_expand_derived,
            max_steps=args.max_steps,
            run_derived=not args.skip_derived_http,
            derived_method=cast(DerivedHttpMethod, args.derived_method),
            derived_max_targets=args.derived_max_targets,
            derived_max_redirects=args.derived_max_redirects,
            derived_timeout_seconds=args.derived_timeout_seconds,
            derive_cookies_from_cdp=args.derive_cookies_from_cdp,
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except (OwnedBrowserScenarioError, OwnedObjectPipelineError, DerivedHttpCheckError) as exc:
        print(f"owned object pipeline error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 1 if result.errors or result.total_artifacts else 0


def _owned_permission_matrix(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        matrix = load_owned_permission_matrix(args.matrix)
        result = run_owned_permission_matrix(
            catalog,
            matrix,
            args.output_dir,
            researcher_accounts=_artifact_researcher_accounts(args),
            yolo=args.yolo,
            expand_derived=not args.no_expand_derived,
            max_steps=args.max_steps,
            run_derived=not args.skip_derived_http,
            derived_method=cast(DerivedHttpMethod, args.derived_method),
            derived_max_targets=args.derived_max_targets,
            derived_max_redirects=args.derived_max_redirects,
            derived_timeout_seconds=args.derived_timeout_seconds,
            derive_cookies_from_cdp=args.derive_cookies_from_cdp,
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
            phase_ids=args.phase,
        )
    except (OwnedBrowserScenarioError, OwnedPermissionMatrixError) as exc:
        print(f"owned permission matrix error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 1 if result.errors or result.total_artifacts else 0


def _owned_permission_matrix_template(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        matrix = write_owned_permission_matrix_template(
            catalog,
            args.output_path,
            matrix_id=args.matrix_id,
            grantee_accounts=args.grantee_account or None,
            include_trash_phase=not args.no_trash_phase,
        )
    except (OwnedBrowserScenarioError, OwnedPermissionMatrixError) as exc:
        print(f"owned permission matrix template error: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "matrix_id": matrix.matrix_id,
                "phase_count": len(matrix.phases),
                "output_path": str(args.output_path),
            },
            indent=2,
        )
    )
    return 0


def _mobile_hypotheses(args: argparse.Namespace) -> int:
    if args.limit < 1:
        print("mobile hypotheses error: --limit must be at least 1", file=sys.stderr)
        return 2
    if not args.artifact_path.exists():
        print(f"mobile hypotheses error: artifact path does not exist: {args.artifact_path}", file=sys.stderr)
        return 2
    report = build_mobile_static_report(
        app_id=args.app_id,
        artifact_path=args.artifact_path,
        limit=args.limit,
    )
    output = report.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "mobile-static-report.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


def _live_recon(args: argparse.Namespace) -> int:
    try:
        operator_policy = load_operator_policy(args.operator_policy) if args.operator_policy else load_operator_policy()
    except LiveReconAuthorizationError as exc:
        print(f"operator policy error: {exc}", file=sys.stderr)
        return 2

    action = _live_recon_action(args)
    runner = LiveReconRunner(
        ApprovedSubprocessRunner(
            operator_policy=operator_policy,
            operator_id=args.operator_id,
            legal_liability_accepted=args.accept_legal_liability,
        ),
        operator_policy=operator_policy,
        operator_id=args.operator_id,
        legal_liability_accepted=args.accept_legal_liability,
        default_httpx_rate_limit_per_minute=args.rate_limit_per_minute,
    )
    result = AutonomousAgent(
        policy=AutonomyPolicy(dry_run=False),
        budget=ActionBudget(max_actions=1, max_live_requests=args.max_live_requests),
        runner=runner,
    ).run_plan(AgentPlan(actions=[action]))
    print(result.model_dump_json(indent=2))
    if result.stopped or result.blocked_actions or any(not obs.success for obs in result.observations):
        return 1
    return 0


def _live_recon_action(args: argparse.Namespace) -> AgentAction:
    if args.tool == "subfinder":
        return AgentAction(
            action_type="passive_recon",
            target_kind="host",
            target=args.target,
            intended_action="passive_recon",
            description=f"Run approved passive subfinder recon for {args.target}.",
            metadata={"tool": "subfinder"},
        )
    if args.tool == "httpx":
        if args.target.startswith(("http://", "https://")):
            return AgentAction(
                action_type="low_volume_probe",
                target_kind="url",
                target=args.target,
                intended_action="recon",
                description=f"Run approved low-volume httpx probe for {args.target}.",
                sends_traffic=True,
                request_budget=1,
                metadata={
                    "tool": "httpx",
                    "rate_limit_per_minute": str(args.rate_limit_per_minute),
                },
            )
        return AgentAction(
            action_type="low_volume_probe",
            target_kind="host",
            target=args.target,
            intended_action="recon",
            description=f"Run approved low-volume httpx probe for {args.target}.",
            sends_traffic=True,
            request_budget=1,
            metadata={
                "tool": "httpx",
                "rate_limit_per_minute": str(args.rate_limit_per_minute),
            },
        )
    if args.artifact_path is None:
        raise SystemExit("--artifact-path is required for --tool jadx")
    if args.publisher is None:
        raise SystemExit("--publisher is required for --tool jadx")
    metadata = {
        "tool": "jadx",
        "artifact_path": args.artifact_path,
        "publisher": args.publisher,
    }
    if args.output_dir:
        metadata["output_dir"] = args.output_dir
    return AgentAction(
        action_type="passive_recon",
        target_kind="mobile_app",
        target=args.target,
        intended_action="passive_recon",
        description=f"Run approved jadx static analysis for {args.target}.",
        metadata=metadata,
    )


def _build_plan(args: argparse.Namespace) -> AgentPlan:
    assets = _load_assets(args.asset, args.asset_file)
    brain = build_agent_brain(
        provider=cast(ModelProviderName, args.model_provider),
        allow_remote_model=args.allow_remote_model,
        openai_model=args.model,
        openai_base_url=args.model_base_url,
        timeout_seconds=args.model_timeout_seconds,
        max_assets=args.model_max_assets,
    )
    if args.mode == "offline":
        return build_offline_analysis_plan(assets, brain=brain, max_actions=args.max_actions)
    return build_agent_plan(assets, brain=brain, max_actions=args.max_actions)


def _default_model_provider() -> str:
    value = os.getenv("VRP_HUNT_MODEL_PROVIDER", "heuristic").strip().lower()
    if value in {"heuristic", "openai"}:
        return value
    return "heuristic"


def _safe_runner_for_mode(mode: str) -> ActionRunner:
    if mode == "testing":
        return build_safe_validation_runner()
    return build_safe_offline_runner()


def _apply_cli_approval_gate(
    plan: AgentPlan,
    policy: AutonomyPolicy,
    args: argparse.Namespace,
) -> AgentPlan:
    mode = "approve-all" if args.approve_risky or args.yolo else args.approval_mode
    result = apply_approval_gate(
        plan,
        policy=policy,
        mode=cast(ApprovalMode, mode),
        approvals=args.approve_action,
        prompt=input,
        render=lambda text: print(text, file=sys.stderr),
    )
    if result.required_actions and mode == "block":
        print(
            "approval gate: risky actions were left unapproved and will be blocked by policy",
            file=sys.stderr,
        )
        print(
            "rerun with --approval-mode explicit --approve-action <index|id>, "
            "--approval-mode prompt, or --approve-risky",
            file=sys.stderr,
        )
    if result.approved_action_ids:
        print(
            f"approval gate: approved {len(result.approved_action_ids)} risky action(s)",
            file=sys.stderr,
        )
    return result.plan


def _artifact_researcher_accounts(args: argparse.Namespace) -> list[str]:
    return args.researcher_account or ["owned-test-account"]


def _write_auto_artifacts(output_dir: Path, output: Mapping[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for key, filename in {
        "plan": "plan.json",
        "run": "run.json",
        "artifacts": "artifact-bundle.json",
    }.items():
        (output_dir / filename).write_text(
            json.dumps(output[key], indent=2) + "\n",
            encoding="utf-8",
        )


def _write_scenario_artifacts(output_dir: Path, bundle: AgentArtifactBundle) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "artifact-bundle.json"
    bundle_path.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    written: list[dict[str, str]] = []
    for artifact in bundle.artifacts:
        finding_id = artifact.finding.finding_id
        finding_path = output_dir / f"{finding_id}-finding.json"
        report_path = output_dir / f"{finding_id}-report.json"
        markdown_path = output_dir / f"{finding_id}-report.md"
        finding_path.write_text(artifact.finding.model_dump_json(indent=2) + "\n", encoding="utf-8")
        report_path.write_text(artifact.report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        markdown_path.write_text(render_markdown_report(artifact.report), encoding="utf-8")
        written.append(
            {
                "finding_id": finding_id,
                "finding": str(finding_path),
                "report": str(report_path),
                "markdown": str(markdown_path),
            }
        )
    return {
        "artifact_bundle": str(bundle_path),
        "artifacts": written,
    }


def _load_assets(asset_specs: list[str], asset_file: Path | None) -> list[Asset]:
    assets = [_parse_asset_spec(spec) for spec in asset_specs]
    if asset_file is not None:
        for line in asset_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                assets.append(Asset.model_validate_json(line))
    if not assets:
        raise SystemExit("at least one --asset or --asset-file is required")
    return assets


def _parse_asset_spec(spec: str) -> Asset:
    kind, separator, value = spec.partition(":")
    if not separator or not kind or not value:
        raise SystemExit(f"invalid asset spec: {spec!r}; expected kind:value")
    return Asset.model_validate({"kind": kind, "value": value, "source": "cli"})


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
