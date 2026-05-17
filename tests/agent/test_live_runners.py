import asyncio
from typing import Sequence

import pytest

from vrp_hunt.agent import (
    AgentAction,
    ApprovedSubprocessRunner,
    LiveReconAuthorizationError,
    LiveReconOperatorPolicy,
    LiveReconRunner,
    build_safe_validation_runner,
)
from vrp_hunt.agent.runners import AsyncCommandRunner
from vrp_hunt.web_recon import CommandResult


class FakeCommandRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        self.commands.append(list(command))
        if command[0] == "subfinder":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout='{"host":"www.google.com","sources":["crtsh"]}\n',
            )
        if command[0] == "httpx":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout='{"url":"https://www.google.com","status_code":200,"webserver":"gfe"}\n',
            )
        if command[0] == "katana":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout='{"url":"https://www.google.com/account","source":"href"}\n',
            )
        if command[0] == "nuclei":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout=(
                    '{"template-id":"safe-template","matched-at":"https://www.google.com",'
                    '"info":{"severity":"info","name":"safe"}}\n'
                ),
            )
        if command[0] == "jadx":
            return CommandResult(command=list(command), returncode=0, stdout="")
        return CommandResult(command=list(command), returncode=1, stderr="unsupported")


class FailingHttpxCommandRunner:
    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        return CommandResult(command=list(command), returncode=1, stdout="", stderr="")


def operator_policy() -> LiveReconOperatorPolicy:
    return LiveReconOperatorPolicy(
        authorized_operator_id="owner",
        authorized_local_user="local-owner",
        allowed_tools=["subfinder", "httpx", "katana", "nuclei", "jadx"],
        require_liability_ack=True,
    )


def live_runner(
    command_runner: AsyncCommandRunner,
    *,
    operator_id: str = "owner",
    legal_liability_accepted: bool = True,
    local_user: str = "local-owner",
) -> LiveReconRunner:
    return LiveReconRunner(
        command_runner,
        operator_policy=operator_policy(),
        operator_id=operator_id,
        legal_liability_accepted=legal_liability_accepted,
        local_user=local_user,
    )


def test_live_runner_executes_subfinder_passive_recon() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="passive_recon",
        target_kind="host",
        target="google.com",
        intended_action="passive_recon",
        description="Passive subdomain recon.",
        metadata={"tool": "subfinder"},
    )

    observation = live_runner(command_runner).run(action)

    assert observation.success
    assert observation.request_count == 0
    assert observation.assets[0].value == "www.google.com"
    assert command_runner.commands[0] == ["subfinder", "-d", "google.com", "-oJ", "-silent"]


def test_live_runner_executes_httpx_with_rate_limit() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="host",
        target="www.google.com",
        intended_action="recon",
        description="Low-volume web probe.",
        sends_traffic=True,
        request_budget=1,
        metadata={"tool": "httpx", "rate_limit_per_minute": "5"},
    )

    observation = live_runner(command_runner).run(action)

    assert observation.success
    assert observation.request_count == 1
    assert observation.assets[0].value == "https://www.google.com"
    assert "-rlm" in command_runner.commands[0]
    assert "5" in command_runner.commands[0]


def test_live_runner_records_httpx_nonzero_exit_code() -> None:
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="host",
        target="www.google.com",
        intended_action="recon",
        description="Low-volume web probe.",
        sends_traffic=True,
        request_budget=1,
        metadata={"tool": "httpx", "rate_limit_per_minute": "5"},
    )

    observation = live_runner(FailingHttpxCommandRunner()).run(action)

    assert not observation.success
    assert observation.request_count == 1
    assert "httpx exit code=1" in observation.notes


def test_live_runner_executes_jadx_without_traffic() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="passive_recon",
        target_kind="mobile_app",
        target="app.apk",
        intended_action="passive_recon",
        description="Static Android decompile.",
        metadata={"tool": "jadx", "output_dir": "out/jadx"},
    )

    observation = live_runner(command_runner).run(action)

    assert observation.success
    assert observation.request_count == 0
    assert command_runner.commands[0] == ["jadx", "-d", "out/jadx", "app.apk"]


def test_live_runner_executes_katana_scoped_crawl() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target="https://www.google.com",
        intended_action="recon",
        description="Scoped crawl.",
        sends_traffic=True,
        request_budget=5,
        metadata={
            "tool": "katana",
            "rate_limit_per_minute": "5",
            "depth": "1",
            "field_scope": "fqdn",
        },
    )

    observation = live_runner(command_runner).run(action)

    assert observation.success
    assert observation.assets[0].kind == "endpoint"
    assert command_runner.commands[0][0] == "katana"
    assert "-sr" not in command_runner.commands[0]
    assert "-rlm" in command_runner.commands[0]


def test_live_runner_executes_nuclei_with_explicit_template() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target="https://www.google.com",
        intended_action="recon",
        description="Explicit template check.",
        sends_traffic=True,
        request_budget=3,
        metadata={
            "tool": "nuclei",
            "nuclei_templates": "safe/http/title.yaml",
            "nuclei_tags": "exposure",
            "nuclei_severity": "info",
            "rate_limit_per_second": "1",
        },
    )

    observation = live_runner(command_runner).run(action)

    assert observation.success
    assert observation.assets[0].metadata["template_id"] == "safe-template"
    assert command_runner.commands[0][0] == "nuclei"
    assert "safe/http/title.yaml" in command_runner.commands[0]
    assert "-j" in command_runner.commands[0]
    assert "-ni" in command_runner.commands[0]
    assert "-pt" in command_runner.commands[0]


def test_live_runner_rejects_nuclei_without_template() -> None:
    action = AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target="https://www.google.com",
        intended_action="recon",
        description="Template-less check.",
        sends_traffic=True,
        request_budget=1,
        metadata={"tool": "nuclei"},
    )

    observation = live_runner(FakeCommandRunner()).run(action)

    assert not observation.success
    assert "explicit templates" in observation.notes[0]


def test_live_runner_blocks_unauthorized_operator_before_command() -> None:
    command_runner = FakeCommandRunner()
    action = AgentAction(
        action_type="passive_recon",
        target_kind="host",
        target="google.com",
        intended_action="passive_recon",
        description="Passive subdomain recon.",
        metadata={"tool": "subfinder"},
    )

    observation = live_runner(command_runner, operator_id="someone-else").run(action)

    assert not observation.success
    assert "authorization failed" in observation.notes[0]
    assert command_runner.commands == []


def test_approved_subprocess_runner_blocks_unauthorized_operator_before_spawn() -> None:
    runner = ApprovedSubprocessRunner(
        operator_policy=operator_policy(),
        operator_id="someone-else",
        legal_liability_accepted=True,
        local_user="local-owner",
    )

    with pytest.raises(LiveReconAuthorizationError):
        asyncio.run(runner.run(["subfinder", "-d", "google.com"]))


def test_safe_validation_runner_registers_bug_class_handlers_without_traffic() -> None:
    action = AgentAction(
        action_type="owned_account_authz",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="idor_testing",
        description="Prepare owned-account authz validation.",
        sends_traffic=True,
        request_budget=1,
        requires_human_approval=True,
        human_approved=True,
    )

    observation = build_safe_validation_runner().run(action)

    assert observation.success
    assert observation.request_count == 0
    assert "IDOR" in observation.notes[0]
