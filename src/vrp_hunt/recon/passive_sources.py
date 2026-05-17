"""Passive recon source catalog and local readiness checks."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel

PassiveSourceCategory = Literal[
    "subdomain",
    "url",
    "certificate",
    "code",
    "search",
    "cloud",
    "email",
    "mobile",
    "technology",
]
PassiveSourceStatusValue = Literal["ready", "missing_env", "disabled"]
MAX_PASSIVE_SOURCE_CATALOG_BYTES = 256_000
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PASSIVE_SOURCE_CATALOG_PATH = REPO_ROOT / "config" / "passive_sources.yaml"


class PassiveSourceCatalogError(ValueError):
    """Raised when a passive source catalog cannot be loaded safely."""


class PassiveSourceConfig(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=1, max_length=256)
    categories: list[PassiveSourceCategory] = Field(min_length=1)
    enabled: bool = True
    required_env: list[str] = Field(default_factory=list)
    optional_env: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int | None = Field(default=None, ge=1)
    notes: str = Field(default="", max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)

    @field_validator("required_env", "optional_env", "tools")
    @classmethod
    def string_lists_must_be_unique(cls, value: list[str]) -> list[str]:
        stripped = [item.strip() for item in value]
        if any(not item for item in stripped):
            raise ValueError("list values cannot be blank")
        if len(stripped) != len(set(stripped)):
            raise ValueError("list values must be unique")
        return stripped

    @model_validator(mode="after")
    def env_names_must_not_overlap(self) -> "PassiveSourceConfig":
        overlap = set(self.required_env).intersection(self.optional_env)
        if overlap:
            raise ValueError(f"required and optional env overlap: {', '.join(sorted(overlap))}")
        return self


class PassiveSourceCatalog(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    sources: list[PassiveSourceConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def source_ids_must_be_unique(self) -> "PassiveSourceCatalog":
        source_ids = [source.id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("passive source ids must be unique")
        return self


class PassiveSourceHealth(StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    enabled: bool
    status: PassiveSourceStatusValue
    categories: list[PassiveSourceCategory]
    tools: list[str] = Field(default_factory=list)
    required_env: list[str] = Field(default_factory=list)
    configured_env: list[str] = Field(default_factory=list)
    missing_env: list[str] = Field(default_factory=list)
    optional_env: list[str] = Field(default_factory=list)
    configured_optional_env: list[str] = Field(default_factory=list)
    secret_values_redacted: bool = True
    reason: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)


class PassiveSourceHealthReport(StrictModel):
    version: str = Field(min_length=1)
    total_sources: int = Field(ge=0)
    enabled_sources: int = Field(ge=0)
    ready_sources: int = Field(ge=0)
    missing_env_sources: int = Field(ge=0)
    disabled_sources: int = Field(ge=0)
    sources: list[PassiveSourceHealth] = Field(default_factory=list)


def load_passive_source_catalog(
    path: str | Path = DEFAULT_PASSIVE_SOURCE_CATALOG_PATH,
) -> PassiveSourceCatalog:
    catalog_path = Path(path)
    try:
        data = catalog_path.read_bytes()
    except OSError as exc:
        raise PassiveSourceCatalogError(f"failed to read passive source catalog: {catalog_path}") from exc
    if len(data) > MAX_PASSIVE_SOURCE_CATALOG_BYTES:
        raise PassiveSourceCatalogError(f"passive source catalog exceeds size limit: {catalog_path}")
    try:
        parsed: Any = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PassiveSourceCatalogError("passive source catalog is malformed") from exc
    if not isinstance(parsed, dict):
        raise PassiveSourceCatalogError("passive source catalog root must be a mapping")
    try:
        return PassiveSourceCatalog.model_validate(parsed)
    except ValidationError as exc:
        raise PassiveSourceCatalogError("passive source catalog validation failed") from exc


def evaluate_passive_source_health(
    catalog: PassiveSourceCatalog,
    *,
    env: Mapping[str, str] | None = None,
    include_disabled: bool = True,
) -> PassiveSourceHealthReport:
    effective_env = env if env is not None else os.environ
    source_health = [
        _source_health(source, effective_env)
        for source in catalog.sources
        if include_disabled or source.enabled
    ]
    return PassiveSourceHealthReport(
        version=catalog.version,
        total_sources=len(source_health),
        enabled_sources=sum(1 for source in source_health if source.enabled),
        ready_sources=sum(1 for source in source_health if source.status == "ready"),
        missing_env_sources=sum(1 for source in source_health if source.status == "missing_env"),
        disabled_sources=sum(1 for source in source_health if source.status == "disabled"),
        sources=source_health,
    )


def passive_source_env_template(catalog: PassiveSourceCatalog) -> str:
    required = _unique_env_names(source.required_env for source in catalog.sources)
    optional = _unique_env_names(source.optional_env for source in catalog.sources)
    lines = [
        "# Passive recon source credentials",
        "# Values are intentionally blank; keep real secrets in your local shell or .env.",
    ]
    if required:
        lines.append("")
        lines.append("# Required for configured sources")
        lines.extend(f"{name}=" for name in required)
    if optional:
        lines.append("")
        lines.append("# Optional provider enhancements")
        lines.extend(f"{name}=" for name in optional)
    return "\n".join(lines) + "\n"


def _source_health(source: PassiveSourceConfig, env: Mapping[str, str]) -> PassiveSourceHealth:
    configured_required = [name for name in source.required_env if _env_present(env, name)]
    missing_required = [name for name in source.required_env if not _env_present(env, name)]
    configured_optional = [name for name in source.optional_env if _env_present(env, name)]

    if not source.enabled:
        status: PassiveSourceStatusValue = "disabled"
        reason = "source disabled in catalog"
    elif missing_required:
        status = "missing_env"
        reason = f"missing required env: {', '.join(missing_required)}"
    else:
        status = "ready"
        reason = "all required env configured" if source.required_env else "no credentials required"

    return PassiveSourceHealth(
        id=source.id,
        name=source.name,
        enabled=source.enabled,
        status=status,
        categories=source.categories,
        tools=source.tools,
        required_env=source.required_env,
        configured_env=configured_required,
        missing_env=missing_required,
        optional_env=source.optional_env,
        configured_optional_env=configured_optional,
        reason=reason,
        source_reference=source.source_reference,
    )


def _env_present(env: Mapping[str, str], name: str) -> bool:
    return bool(env.get(name, "").strip())


def _unique_env_names(groups: Iterable[Iterable[str]]) -> list[str]:
    names: list[str] = []
    for group in groups:
        for name in group:
            if name not in names:
                names.append(name)
    return names
