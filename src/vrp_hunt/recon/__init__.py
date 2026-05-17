"""Surface-agnostic recon core contracts and orchestration."""

from vrp_hunt.recon.adapters import ReconAdapter, ReconContext
from vrp_hunt.recon.engine import ReconEngine, ReconRunResult
from vrp_hunt.recon.models import (
    AdapterCapability,
    AdapterResult,
    Asset,
    AssetInventory,
    HttpRequest,
    HttpResponse,
    ReconScope,
)
from vrp_hunt.recon.passive_sources import (
    DEFAULT_PASSIVE_SOURCE_CATALOG_PATH,
    PassiveSourceCatalog,
    PassiveSourceCatalogError,
    PassiveSourceCategory,
    PassiveSourceConfig,
    PassiveSourceHealth,
    PassiveSourceHealthReport,
    PassiveSourceStatusValue,
    evaluate_passive_source_health,
    load_passive_source_catalog,
    passive_source_env_template,
)
from vrp_hunt.recon.scoring import (
    AssetScore,
    AssetScoreReport,
    AssetScoringProfile,
    score_asset,
    score_assets,
)
from vrp_hunt.recon.scheduler import AsyncPoliteScheduler, GateDeniedError
from vrp_hunt.recon.store import AssetStore
from vrp_hunt.recon.wrappers import HttpxTransport, NucleiCommandBuilder, NucleiTemplatePolicy

__all__ = [
    "AdapterCapability",
    "AdapterResult",
    "Asset",
    "AssetInventory",
    "AssetScore",
    "AssetScoreReport",
    "AssetScoringProfile",
    "AssetStore",
    "AsyncPoliteScheduler",
    "GateDeniedError",
    "HttpRequest",
    "HttpResponse",
    "HttpxTransport",
    "NucleiCommandBuilder",
    "NucleiTemplatePolicy",
    "DEFAULT_PASSIVE_SOURCE_CATALOG_PATH",
    "PassiveSourceCatalog",
    "PassiveSourceCatalogError",
    "PassiveSourceCategory",
    "PassiveSourceConfig",
    "PassiveSourceHealth",
    "PassiveSourceHealthReport",
    "PassiveSourceStatusValue",
    "ReconAdapter",
    "ReconContext",
    "ReconEngine",
    "ReconRunResult",
    "ReconScope",
    "evaluate_passive_source_health",
    "load_passive_source_catalog",
    "passive_source_env_template",
    "score_asset",
    "score_assets",
]
