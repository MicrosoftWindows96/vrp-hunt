import asyncio
from datetime import date
from pathlib import Path
from typing import Sequence

from vrp_hunt.guardrails import GuardrailGate, RateLimitPolicy
from vrp_hunt.recon import AssetStore, AsyncPoliteScheduler, HttpRequest, HttpResponse, ReconContext, ReconScope
from vrp_hunt.mobile_recon import MobileAppTarget, MobileReconAdapter, MobileReconConfig
from vrp_hunt.web_recon import CommandResult


def run(coro):
    return asyncio.run(coro)


async def fake_transport(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(status_code=200)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        self.commands.append(list(command))
        if command[0] == "frida":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout='{"payload":{"url":"https://www.google.com/mobile"}}\n',
            )
        return CommandResult(command=list(command), returncode=0)


def context(tmp_path: Path) -> ReconContext:
    scheduler = AsyncPoliteScheduler(
        gate=GuardrailGate(as_of_date=date(2026, 5, 16)),
        rate_policy=RateLimitPolicy(global_max_rps=1000, per_host_max_rps=1000),
        transport=fake_transport,
    )
    return ReconContext(scheduler=scheduler, store=AssetStore(tmp_path / "assets.jsonl"))


def test_mobile_adapter_static_analysis_from_local_text(tmp_path: Path) -> None:
    source = tmp_path / "decompiled"
    source.mkdir()
    (source / "Network.java").write_text(
        'String endpoint = "https://www.googleapis.com/oauth2/v1/userinfo"; apiKey = "AIza12345678901234567890";',
        encoding="utf-8",
    )
    target = MobileAppTarget(
        app_id="com.google.example",
        publisher="Google LLC",
        platform="android",
        artifact_path=source,
    )
    adapter = MobileReconAdapter(config=MobileReconConfig(targets=[target]))

    result = run(adapter.discover(ReconScope(seeds=["com.google.example"]), context(tmp_path)))
    values = {asset.value for asset in result.assets}

    assert "com.google.example" in values
    assert "https://www.googleapis.com/oauth2/v1/userinfo" in values
    assert "potential-secret-pattern:api_key" in values


def test_mobile_adapter_skips_unknown_publisher(tmp_path: Path) -> None:
    target = MobileAppTarget(app_id="com.evil.app", publisher="Unknown", platform="android")
    adapter = MobileReconAdapter(config=MobileReconConfig(targets=[target]))

    result = run(adapter.discover(ReconScope(seeds=["com.evil.app"]), context(tmp_path)))

    assert result.assets == []
    assert any("skipped app com.evil.app" in warning for warning in result.warnings)


def test_mobile_adapter_dynamic_observation_uses_runner(tmp_path: Path) -> None:
    runner = FakeRunner()
    target = MobileAppTarget(app_id="com.google.example", publisher="Google LLC", platform="android")
    adapter = MobileReconAdapter(
        config=MobileReconConfig(targets=[target], dynamic_enabled=True, runner=runner)
    )

    result = run(adapter.discover(ReconScope(seeds=["com.google.example"]), context(tmp_path)))

    assert any(command[0] == "frida" for command in runner.commands)
    assert "https://www.google.com/mobile" in {asset.value for asset in result.assets}
