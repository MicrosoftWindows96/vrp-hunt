"""Load and validate bug bounty program registries."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from vrp_hunt.programs.models import ProgramRegistry

MAX_PROGRAM_REGISTRY_BYTES = 512_000
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROGRAM_REGISTRY_PATH = REPO_ROOT / "config" / "program_registry.yaml"


class ProgramRegistryLoadError(ValueError):
    """Raised when a program registry cannot be loaded safely."""


def load_program_registry(path: str | Path = DEFAULT_PROGRAM_REGISTRY_PATH) -> ProgramRegistry:
    registry_path = Path(path)
    try:
        data = registry_path.read_bytes()
    except OSError as exc:
        raise ProgramRegistryLoadError(f"failed to read program registry: {registry_path}") from exc
    if len(data) > MAX_PROGRAM_REGISTRY_BYTES:
        raise ProgramRegistryLoadError(f"program registry exceeds size limit: {registry_path}")
    try:
        parsed: Any = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ProgramRegistryLoadError("program registry is malformed") from exc
    if not isinstance(parsed, dict):
        raise ProgramRegistryLoadError("program registry root must be a mapping")
    try:
        return ProgramRegistry.model_validate(parsed)
    except ValidationError as exc:
        raise ProgramRegistryLoadError("program registry validation failed") from exc
