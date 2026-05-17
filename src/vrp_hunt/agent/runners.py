"""Safe built-in action runners."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Protocol, Sequence

from vrp_hunt.agent.authorization import (
    APPROVED_LIVE_TOOLS,
    LiveReconAuthorizationError,
    LiveReconOperatorPolicy,
    authorize_live_recon,
    load_operator_policy,
)
from vrp_hunt.agent.executor import RegisteredActionRunner
from vrp_hunt.agent.models import AgentAction, AgentObservation
from vrp_hunt.playbooks import get_playbook
from vrp_hunt.playbooks.models import BugClass
from vrp_hunt.recon import Asset, NucleiCommandBuilder, NucleiTemplatePolicy
from vrp_hunt.web_recon import (
    CommandResult,
    build_httpx_command,
    build_katana_command,
    build_subfinder_command,
    parse_httpx_jsonl,
    parse_katana_jsonl,
    parse_nuclei_jsonl,
    parse_subfinder_jsonl,
)
from vrp_hunt.mobile_recon import build_jadx_command


class AsyncCommandRunner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        stdin: str | None = None,
    ) -> Coroutine[Any, Any, CommandResult]:
        """Run a command without shell expansion."""
        ...


class ApprovedSubprocessRunner:
    """Run approved recon commands without shell expansion."""

    allowed_tools = set(APPROVED_LIVE_TOOLS)

    def __init__(
        self,
        *,
        operator_policy: LiveReconOperatorPolicy | None = None,
        operator_id: str | None = None,
        legal_liability_accepted: bool = False,
        local_user: str | None = None,
        timeout_seconds: float = 300.0,
        max_output_bytes: int = 2_000_000,
    ) -> None:
        self.operator_policy = operator_policy or load_operator_policy()
        self.operator_id = operator_id
        self.legal_liability_accepted = legal_liability_accepted
        self.local_user = local_user
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        if not command:
            raise ValueError("unsupported command")
        authorize_live_recon(
            tool=command[0],
            operator_id=self.operator_id,
            legal_liability_accepted=self.legal_liability_accepted,
            policy=self.operator_policy,
            local_user=self.local_user,
        )

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(stdin.encode("utf-8") if stdin is not None else None),
            timeout=self.timeout_seconds,
        )
        stdout = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
        stderr = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
        return CommandResult(command=list(command), returncode=proc.returncode or 0, stdout=stdout, stderr=stderr)


class SafeOfflineRunner(RegisteredActionRunner):
    """Registered runner for non-traffic analysis actions only."""

    def __init__(self) -> None:
        super().__init__(
            {
                "analyze_assets": self._analyze_assets,
                "plan_test": self._plan_test,
                "passive_recon": self._passive_recon,
                "report_draft": self._report_draft,
            }
        )

    def run(self, action: AgentAction) -> AgentObservation:
        if action.sends_traffic:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=["safe offline runner refuses traffic-sending actions"],
            )
        return super().run(action)

    def _analyze_assets(self, action: AgentAction) -> AgentObservation:
        return AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=[
                f"offline asset analyzed: {action.target}",
                f"asset kind: {action.metadata.get('asset_kind', action.target_kind)}",
            ],
            assets=[
                Asset(
                    kind="note",
                    value=f"offline-analysis:{action.target}",
                    source="agent",
                    parent=action.target,
                    metadata={"action_id": action.action_id},
                )
            ],
        )

    def _plan_test(self, action: AgentAction) -> AgentObservation:
        bug_class = action.metadata.get("bug_class", "manual")
        return AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=[
                f"planned {bug_class} playbook review for {action.target}",
                "no live validation executed",
            ],
        )

    def _passive_recon(self, action: AgentAction) -> AgentObservation:
        return AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=[
                f"passive-only recon placeholder completed for {action.target}",
                "register a live handler separately for tool execution",
            ],
        )

    def _report_draft(self, action: AgentAction) -> AgentObservation:
        return AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=[f"report drafting precheck completed for {action.target}"],
        )


def build_safe_offline_runner() -> SafeOfflineRunner:
    return SafeOfflineRunner()


class SafeValidationRunner(RegisteredActionRunner):
    """Registered validation handlers that prepare safe manual checks only."""

    def __init__(self) -> None:
        super().__init__(
            {
                "idor_validation": self._prepare_idor_validation,
                "oauth_validation": self._prepare_oauth_validation,
                "xsleak_validation": self._prepare_xsleak_validation,
                "xss_validation": self._prepare_xss_validation,
                "csrf_validation": self._prepare_csrf_validation,
                "low_volume_probe": self._prepare_legacy_validation,
                "owned_account_authz": self._prepare_legacy_validation,
                "state_change_test": self._prepare_legacy_validation,
            }
        )

    def run(self, action: AgentAction) -> AgentObservation:
        if action.sends_traffic:
            action = action.model_copy(update={"sends_traffic": False, "request_budget": 0})
        return super().run(action)

    def _prepare_idor_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(
            action,
            "idor",
            [
                "prepare two owned test accounts with separate researcher-created objects",
                "compare only owned-account authorization boundaries",
                "stop immediately if any non-owned object or profile data appears",
            ],
        )

    def _prepare_oauth_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(
            action,
            "oauth",
            [
                "prepare owned OAuth client/account state only",
                "review redirect URI, scope, consent, and state handling without logging tokens",
                "do not replay token exchanges automatically",
            ],
        )

    def _prepare_xsleak_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(
            action,
            "xsleak",
            [
                "prepare attacker and victim roles with owned test accounts only",
                "record observable side-channel behavior without private content capture",
                "avoid timing loops or high-volume measurement",
            ],
        )

    def _prepare_xss_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(
            action,
            "xss",
            [
                "prepare a benign marker payload for owned-account rendering paths",
                "capture only redacted browser evidence from researcher-owned state",
                "do not attempt credential theft, persistence, or third-party interaction",
            ],
        )

    def _prepare_csrf_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(
            action,
            "csrf",
            [
                "prepare a meaningful owned-account state-change workflow",
                "keep replay manual, single-action, and reversible when possible",
                "do not validate logout-only CSRF or any disruptive state change",
            ],
        )

    def _prepare_legacy_validation(self, action: AgentAction) -> AgentObservation:
        return _safe_validation_observation(action, _bug_class_from_intended_action(action.intended_action))


def _safe_validation_observation(
    action: AgentAction,
    bug_class: BugClass,
    extra_notes: list[str] | None = None,
) -> AgentObservation:
    playbook = get_playbook(bug_class)
    return AgentObservation(
        action_id=action.action_id,
        success=True,
        notes=[
            f"prepared {playbook.title} validation for {action.target}",
            "safe handler registered for manual validation preparation only",
            "no validation traffic sent by safe validation runner",
            "use owned accounts only and stop if non-owned data appears",
            *(extra_notes or []),
        ],
        request_count=0,
    )


def build_safe_validation_runner() -> SafeValidationRunner:
    return SafeValidationRunner()


class LiveReconRunner(RegisteredActionRunner):
    """Opt-in runner for approved low-volume recon tools.

    Policy evaluation must happen before this runner is called. The runner still
    refuses unsupported tools and maps tool output into local assets.
    """

    def __init__(
        self,
        command_runner: AsyncCommandRunner,
        *,
        operator_policy: LiveReconOperatorPolicy | None = None,
        operator_id: str | None = None,
        legal_liability_accepted: bool = False,
        local_user: str | None = None,
        default_httpx_rate_limit_per_minute: int = 30,
        default_jadx_output_dir: Path = Path("data/mobile/jadx"),
    ) -> None:
        self.command_runner = command_runner
        self.operator_policy = operator_policy or load_operator_policy()
        self.operator_id = operator_id
        self.legal_liability_accepted = legal_liability_accepted
        self.local_user = local_user
        self.default_httpx_rate_limit_per_minute = default_httpx_rate_limit_per_minute
        self.default_jadx_output_dir = default_jadx_output_dir
        super().__init__(
            {
                "passive_recon": self._passive_recon,
                "low_volume_probe": self._low_volume_probe,
            }
        )

    def run(self, action: AgentAction) -> AgentObservation:
        tool = _tool_for_action(action)
        try:
            authorize_live_recon(
                tool=tool,
                operator_id=self.operator_id,
                legal_liability_accepted=self.legal_liability_accepted,
                policy=self.operator_policy,
                local_user=self.local_user,
            )
            return super().run(action)
        except LiveReconAuthorizationError as exc:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=[f"live recon authorization failed: {exc}"],
                request_count=0,
            )
        except Exception as exc:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=[f"live recon execution failed: {exc}"],
                request_count=0,
            )

    def _passive_recon(self, action: AgentAction) -> AgentObservation:
        tool = action.metadata.get("tool", "subfinder")
        if tool == "subfinder":
            result = _run_async(self.command_runner.run(build_subfinder_command(action.target)))
            return _subfinder_observation(action, result)
        if tool == "jadx":
            artifact_path = action.metadata.get("artifact_path", action.target)
            output_dir = Path(action.metadata.get("output_dir", str(self.default_jadx_output_dir)))
            result = _run_async(
                self.command_runner.run(build_jadx_command(artifact_path, output_dir))
            )
            return AgentObservation(
                action_id=action.action_id,
                success=result.returncode == 0,
                notes=[
                    f"jadx command completed for {artifact_path}",
                    f"output_dir={output_dir}",
                    *([result.stderr] if result.returncode != 0 and result.stderr else []),
                ],
                request_count=0,
            )
        return AgentObservation(
            action_id=action.action_id,
            success=False,
            notes=[f"unsupported passive recon tool: {tool}"],
        )

    def _low_volume_probe(self, action: AgentAction) -> AgentObservation:
        tool = action.metadata.get("tool", "httpx")
        if tool == "katana":
            return self._crawl_with_katana(action)
        if tool == "nuclei":
            return self._scan_with_nuclei(action)
        if tool != "httpx":
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=[f"unsupported low-volume probe tool: {tool}"],
            )
        targets_file = action.metadata.get("targets_file")
        cleanup_path: Path | None = None
        if targets_file is None:
            with NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                handle.write(f"{action.target}\n")
                targets_file = handle.name
            cleanup_path = Path(targets_file)
        try:
            rate_limit = int(
                action.metadata.get(
                    "rate_limit_per_minute",
                    str(self.default_httpx_rate_limit_per_minute),
                )
            )
            result = _run_async(
                self.command_runner.run(
                    build_httpx_command(targets_file, rate_limit_per_minute=rate_limit)
                )
            )
        finally:
            if cleanup_path is not None:
                cleanup_path.unlink(missing_ok=True)
        assets = parse_httpx_jsonl(result.stdout)
        notes = [f"httpx probe completed for {action.target}"]
        if result.returncode != 0:
            notes.append(f"httpx exit code={result.returncode}")
        if result.returncode != 0 and result.stderr:
            notes.append(result.stderr)
        return AgentObservation(
            action_id=action.action_id,
            success=result.returncode == 0 and bool(assets),
            notes=notes,
            assets=assets,
            request_count=max(1, min(action.request_budget, len(assets) or 1)),
        )

    def _crawl_with_katana(self, action: AgentAction) -> AgentObservation:
        targets_file = action.metadata.get("targets_file")
        cleanup_path = None
        if targets_file is None:
            targets_file, cleanup_path = _single_target_file(action.target)
        try:
            result = _run_async(
                self.command_runner.run(
                    build_katana_command(
                        targets_file,
                        depth=_int_metadata(action, "depth", 1),
                        rate_limit_per_minute=_int_metadata(
                            action,
                            "rate_limit_per_minute",
                            self.default_httpx_rate_limit_per_minute,
                        ),
                        field_scope=action.metadata.get("field_scope", "fqdn"),
                        js_crawl=action.metadata.get("js_crawl") == "true",
                        known_files=action.metadata.get("known_files"),
                        crawl_duration_seconds=_int_metadata(action, "crawl_duration_seconds", 30),
                    )
                )
            )
        finally:
            if cleanup_path is not None:
                cleanup_path.unlink(missing_ok=True)
        assets = parse_katana_jsonl(result.stdout) if result.returncode == 0 else []
        notes = [f"katana crawl completed for {action.target}"]
        if result.returncode != 0:
            notes.append(f"katana exit code={result.returncode}")
        if result.returncode != 0 and result.stderr:
            notes.append(result.stderr)
        return AgentObservation(
            action_id=action.action_id,
            success=result.returncode == 0,
            notes=notes,
            assets=assets,
            request_count=max(1, min(action.request_budget, len(assets) or 1)),
        )

    def _scan_with_nuclei(self, action: AgentAction) -> AgentObservation:
        templates = _list_metadata(action, "nuclei_templates")
        if not templates:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=["nuclei requires explicit templates"],
                request_count=0,
            )
        try:
            policy = NucleiTemplatePolicy(
                templates=templates,
                tags=_list_metadata(action, "nuclei_tags"),
                severity=_list_metadata(action, "nuclei_severity"),
                protocol_types=["http"],
            )
        except ValueError as exc:
            return AgentObservation(
                action_id=action.action_id,
                success=False,
                notes=[f"nuclei policy rejected scan: {exc}"],
                request_count=0,
            )
        targets_file = action.metadata.get("targets_file")
        cleanup_path = None
        if targets_file is None:
            targets_file, cleanup_path = _single_target_file(action.target)
        try:
            result = _run_async(
                self.command_runner.run(
                    NucleiCommandBuilder(policy=policy).build(
                        targets_file,
                        rate_limit=float(_int_metadata(action, "rate_limit_per_second", 1)),
                    )
                )
            )
        finally:
            if cleanup_path is not None:
                cleanup_path.unlink(missing_ok=True)
        assets = parse_nuclei_jsonl(result.stdout) if result.returncode == 0 else []
        notes = [f"nuclei scan completed for {action.target}"]
        if result.returncode != 0:
            notes.append(f"nuclei exit code={result.returncode}")
        if result.returncode != 0 and result.stderr:
            notes.append(result.stderr)
        return AgentObservation(
            action_id=action.action_id,
            success=result.returncode == 0,
            notes=notes,
            assets=assets,
            request_count=max(1, min(action.request_budget, len(assets) or 1)),
        )


def _run_async(coro: Coroutine[Any, Any, CommandResult]) -> CommandResult:
    return asyncio.run(coro)


def _single_target_file(target: str) -> tuple[str, Path]:
    with NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(f"{target}\n")
        return handle.name, Path(handle.name)


def _int_metadata(action: AgentAction, key: str, default: int) -> int:
    value = action.metadata.get(key)
    if value is None:
        return default
    return int(value)


def _list_metadata(action: AgentAction, key: str) -> list[str]:
    value = action.metadata.get(key, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _subfinder_observation(action: AgentAction, result: CommandResult) -> AgentObservation:
    assets = parse_subfinder_jsonl(result.stdout) if result.returncode == 0 else []
    notes = [f"subfinder passive recon completed for {action.target}"]
    if result.returncode != 0 and result.stderr:
        notes.append(result.stderr)
    return AgentObservation(
        action_id=action.action_id,
        success=result.returncode == 0,
        notes=notes,
        assets=assets,
        request_count=0,
    )


def _tool_for_action(action: AgentAction) -> str:
    if action.action_type == "low_volume_probe":
        return action.metadata.get("tool", "httpx")
    return action.metadata.get("tool", "subfinder")


def _bug_class_from_intended_action(intended_action: str) -> BugClass:
    if intended_action == "idor_testing":
        return "idor"
    if intended_action == "csrf_testing":
        return "csrf"
    if intended_action == "oauth_testing":
        return "oauth"
    if intended_action == "xsleak_testing":
        return "xsleak"
    if intended_action == "xss_testing":
        return "xss"
    return "server_side"
