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
    AgentPlan,
    ApprovalGateError,
    ApprovalMode,
    ApprovedSubprocessRunner,
    AutonomyPolicy,
    AutonomousAgent,
    LiveReconAuthorizationError,
    LiveReconRunner,
    ModelProviderError,
    ModelProviderName,
    apply_approval_gate,
    artifact_bundle_from_agent_run,
    build_agent_brain,
    build_agent_plan,
    build_offline_analysis_plan,
    build_recon_iteration_summary,
    load_operator_policy,
    write_recon_iteration_outputs,
)
from vrp_hunt.agent.runners import build_safe_offline_runner, build_safe_validation_runner
from vrp_hunt.recon import Asset
from vrp_hunt.reporting import Platform


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
    mode = "approve-all" if args.approve_risky else args.approval_mode
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
