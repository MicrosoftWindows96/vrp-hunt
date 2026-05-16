"""Recon orchestration engine."""

from __future__ import annotations

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.adapters import ReconAdapter, ReconContext
from vrp_hunt.recon.models import AdapterResult, Asset, ReconScope
from vrp_hunt.recon.scheduler import AsyncPoliteScheduler
from vrp_hunt.recon.store import AssetStore


class ReconRunResult(StrictModel):
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ReconEngine:
    def __init__(self, *, scheduler: AsyncPoliteScheduler, store: AssetStore) -> None:
        self.scheduler = scheduler
        self.store = store

    async def run(self, scope: ReconScope, adapters: list[ReconAdapter]) -> ReconRunResult:
        all_assets: list[Asset] = []
        warnings: list[str] = []
        errors: list[str] = []
        context = ReconContext(scheduler=self.scheduler, store=self.store)

        for adapter in adapters:
            try:
                result = await adapter.discover(scope, context)
            except Exception as exc:
                result = AdapterResult(errors=[f"{adapter.name}: {exc}"])
            all_assets.extend(result.assets)
            warnings.extend(f"{adapter.name}: {warning}" for warning in result.warnings)
            errors.extend(f"{adapter.name}: {error}" for error in result.errors)

        inventory = self.store.save_all(all_assets)
        return ReconRunResult(assets=inventory.assets, warnings=warnings, errors=errors)
