import asyncio
from datetime import date
from pathlib import Path

from vrp_hunt.guardrails import GuardrailGate, RateLimitPolicy
from vrp_hunt.recon import (
    AdapterCapability,
    AdapterResult,
    Asset,
    AssetStore,
    AsyncPoliteScheduler,
    HttpRequest,
    HttpResponse,
    ReconContext,
    ReconEngine,
    ReconScope,
)


def run(coro):
    return asyncio.run(coro)


async def fake_transport(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(status_code=200)


class FakeAdapter:
    name = "fake"
    capabilities = [AdapterCapability(name="seed-hosts", asset_kinds=["host"])]

    async def discover(self, scope: ReconScope, context: ReconContext) -> AdapterResult:
        return AdapterResult(
            assets=[Asset(kind="host", value=scope.seeds[0], source=self.name)],
            warnings=["low confidence"],
        )


def test_recon_engine_stores_adapter_assets(tmp_path: Path) -> None:
    scheduler = AsyncPoliteScheduler(
        gate=GuardrailGate(as_of_date=date(2026, 5, 16)),
        rate_policy=RateLimitPolicy(global_max_rps=1000, per_host_max_rps=1000),
        transport=fake_transport,
    )
    store = AssetStore(tmp_path / "assets.jsonl")
    engine = ReconEngine(scheduler=scheduler, store=store)

    result = run(engine.run(ReconScope(seeds=["google.com"]), [FakeAdapter()]))

    assert result.assets[0].value == "google.com"
    assert result.warnings == ["fake: low confidence"]
    assert store.load().assets[0].value == "google.com"
