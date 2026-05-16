import asyncio
from datetime import date
from pathlib import Path
from typing import Sequence

from vrp_hunt.guardrails import GuardrailGate, RateLimitPolicy
from vrp_hunt.recon import (
    AssetStore,
    AsyncPoliteScheduler,
    HttpRequest,
    HttpResponse,
    ReconContext,
    ReconScope,
)
from vrp_hunt.web_recon import CommandResult, WebReconAdapter, WebReconConfig


def run(coro):
    return asyncio.run(coro)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        self.commands.append(list(command))
        if command[0] == "subfinder":
            return CommandResult(
                command=list(command),
                returncode=0,
                stdout='{"host":"www.google.com","sources":["crtsh"]}\n'
                '{"host":"evil.com","sources":["crtsh"]}\n',
            )
        return CommandResult(command=list(command), returncode=0, stdout="mail.google.com\n")


class FakeTransport:
    def __init__(self) -> None:
        self.requests: list[HttpRequest] = []

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        return HttpResponse(
            status_code=200,
            headers={"server": "gfe"},
            text='<script src="/app.js"></script>fetch("/api/v1/profile?view=full")',
        )


def context(tmp_path: Path, transport: FakeTransport) -> ReconContext:
    scheduler = AsyncPoliteScheduler(
        gate=GuardrailGate(as_of_date=date(2026, 5, 16)),
        rate_policy=RateLimitPolicy(global_max_rps=1000, per_host_max_rps=1000),
        transport=transport,
    )
    return ReconContext(scheduler=scheduler, store=AssetStore(tmp_path / "assets.jsonl"))


def test_adapter_filters_out_of_scope_hosts_before_probe(tmp_path: Path) -> None:
    runner = FakeRunner()
    transport = FakeTransport()
    adapter = WebReconAdapter(runner=runner, config=WebReconConfig(max_live_hosts=10))

    result = run(adapter.discover(ReconScope(seeds=["google.com"]), context(tmp_path, transport)))

    values = {asset.value for asset in result.assets}
    assert "www.google.com" in values
    assert "mail.google.com" in values
    assert "evil.com" not in values
    assert any("skipped host evil.com" in warning for warning in result.warnings)
    assert all("evil.com" not in request.url for request in transport.requests)


def test_adapter_skips_blackout_active_acquisition_seed(tmp_path: Path) -> None:
    transport = FakeTransport()
    adapter = WebReconAdapter(
        config=WebReconConfig(
            passive_tools_enabled=False,
            acquisition_dates={"withgoogle.com": date(2026, 1, 1)},
        )
    )

    result = run(
        adapter.discover(ReconScope(seeds=["foo.withgoogle.com"]), context(tmp_path, transport))
    )

    assert result.assets == []
    assert transport.requests == []
    assert any("deny-acquisition-blackout" in warning for warning in result.warnings)
