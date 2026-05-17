"""Bug bounty program registry and scope matching."""

from vrp_hunt.programs.diff import diff_program_registries
from vrp_hunt.programs.loader import (
    DEFAULT_PROGRAM_REGISTRY_PATH,
    ProgramRegistryLoadError,
    load_program_registry,
)
from vrp_hunt.programs.ingestion import (
    ScopeIngestionError,
    ScopeIngestionOptions,
    ScopeIngestionReport,
    ScopeIngestionSource,
    ingest_scope_export,
)
from vrp_hunt.programs.matching import match_program_scope
from vrp_hunt.programs.models import (
    ProgramExclusion,
    ProgramProfile,
    ProgramRegistryChange,
    ProgramRegistryDiff,
    ProgramRegistry,
    ProgramScopeDecision,
    ProgramScopeDecisionValue,
    ProgramScopeEntry,
    RewardTier,
    SafeHarborPolicy,
    ScopeEntryKind,
)

__all__ = [
    "DEFAULT_PROGRAM_REGISTRY_PATH",
    "ProgramExclusion",
    "ProgramProfile",
    "ProgramRegistry",
    "ProgramRegistryChange",
    "ProgramRegistryDiff",
    "ProgramRegistryLoadError",
    "ProgramScopeDecision",
    "ProgramScopeDecisionValue",
    "ProgramScopeEntry",
    "RewardTier",
    "SafeHarborPolicy",
    "ScopeIngestionError",
    "ScopeIngestionOptions",
    "ScopeIngestionReport",
    "ScopeIngestionSource",
    "ScopeEntryKind",
    "diff_program_registries",
    "ingest_scope_export",
    "load_program_registry",
    "match_program_scope",
]
