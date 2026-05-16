"""Recon adapter contract."""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.models import AdapterCapability, AdapterResult, ReconScope
from vrp_hunt.recon.scheduler import AsyncPoliteScheduler
from vrp_hunt.recon.store import AssetStore


class ReconContext(StrictModel):
    scheduler: AsyncPoliteScheduler = Field(exclude=True)
    store: AssetStore = Field(exclude=True)
    metadata: dict[str, str] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True, "extra": "forbid"}


class ReconAdapter(Protocol):
    name: str
    capabilities: list[AdapterCapability]

    async def discover(self, scope: ReconScope, context: ReconContext) -> AdapterResult:
        """Discover assets for a scope without mutating shared state directly."""
