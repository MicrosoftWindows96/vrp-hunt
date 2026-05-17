"""Bug bounty program registry and scope matching."""

from vrp_hunt.programs.diff import diff_program_registries
from vrp_hunt.programs.loader import (
    DEFAULT_PROGRAM_REGISTRY_PATH,
    ProgramRegistryLoadError,
    load_program_registry,
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
    "ScopeEntryKind",
    "diff_program_registries",
    "load_program_registry",
    "match_program_scope",
]
