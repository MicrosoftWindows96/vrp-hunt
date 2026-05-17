"""Offline scope ingestion for bug bounty platform exports."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field, ValidationError

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.rate_limits import RateLimitPolicy
from vrp_hunt.programs.models import (
    ProgramExclusion,
    ProgramProfile,
    ProgramRegistry,
    ProgramScopeEntry,
    RewardTier,
    SafeHarborPolicy,
    ScopeEntryKind,
)

ScopeIngestionSource = Literal["auto", "hackerone", "bugcrowd", "intigriti", "public_json"]
MAX_SCOPE_IMPORT_BYTES = 2_000_000


class ScopeIngestionError(ValueError):
    """Raised when a platform scope export cannot be ingested safely."""


class ScopeIngestionReport(StrictModel):
    source: ScopeIngestionSource
    input_path: Path
    registry: ProgramRegistry
    program_count: int = Field(ge=0)
    scope_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


class ScopeIngestionOptions(StrictModel):
    source: ScopeIngestionSource = "auto"
    program_id: str | None = Field(default=None, min_length=1, max_length=128)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    platform: str | None = Field(default=None, min_length=1, max_length=128)
    policy_url: str | None = Field(default=None, min_length=1, max_length=1000)
    captured_date: date = Field(default_factory=date.today)
    version: str | None = Field(default=None, min_length=1, max_length=128)


def ingest_scope_export(path: Path, *, options: ScopeIngestionOptions | None = None) -> ScopeIngestionReport:
    ingestion_options = options or ScopeIngestionOptions()
    parsed = _load_export(path)
    source = _detect_source(parsed, ingestion_options.source)
    if source == "public_json":
        registry = _ingest_public_json(parsed, path=path, options=ingestion_options)
    else:
        registry = _ingest_platform_export(parsed, path=path, source=source, options=ingestion_options)
    scope_count = sum(len(program.scope) for program in registry.programs)
    exclusion_count = sum(len(program.exclusions) for program in registry.programs)
    return ScopeIngestionReport(
        source=source,
        input_path=path,
        registry=registry,
        program_count=len(registry.programs),
        scope_count=scope_count,
        exclusion_count=exclusion_count,
        warnings=_registry_warnings(registry),
    )


def _load_export(path: Path) -> object:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScopeIngestionError(f"failed to read scope export: {path}") from exc
    if len(data) > MAX_SCOPE_IMPORT_BYTES:
        raise ScopeIngestionError(f"scope export exceeds {MAX_SCOPE_IMPORT_BYTES} bytes: {path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScopeIngestionError("scope export must be UTF-8") from exc
    try:
        return json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ScopeIngestionError("scope export is malformed") from exc


def _detect_source(parsed: object, requested: ScopeIngestionSource) -> ScopeIngestionSource:
    if requested != "auto":
        return requested
    if isinstance(parsed, dict):
        platform = _string(parsed.get("platform")).lower()
        source = _string(parsed.get("source")).lower()
        keys = set(parsed)
        if "programs" in keys or "program" in keys and "scope" in keys:
            return "public_json"
        if "structured_scopes" in keys or "hackerone" in platform or "hackerone" in source:
            return "hackerone"
        if "target_groups" in keys or "targets" in keys or "bugcrowd" in platform or "bugcrowd" in source:
            return "bugcrowd"
        if "intigriti" in platform or "intigriti" in source or "domains" in keys and "out_of_scope" in keys:
            return "intigriti"
    return "public_json"


def _ingest_public_json(
    parsed: object,
    *,
    path: Path,
    options: ScopeIngestionOptions,
) -> ProgramRegistry:
    if not isinstance(parsed, dict):
        raise ScopeIngestionError("public JSON scope export root must be an object")
    try:
        return ProgramRegistry.model_validate(parsed)
    except ValidationError:
        pass
    programs = parsed.get("programs")
    if isinstance(programs, list):
        return ProgramRegistry(
            version=options.version or _version("public_json", options.captured_date),
            programs=[
                _profile_from_mapping(program, path=path, source="public_json", options=options)
                for program in programs
                if isinstance(program, dict)
            ],
        )
    return ProgramRegistry(
        version=options.version or _version("public_json", options.captured_date),
        programs=[_profile_from_mapping(parsed, path=path, source="public_json", options=options)],
    )


def _ingest_platform_export(
    parsed: object,
    *,
    path: Path,
    source: ScopeIngestionSource,
    options: ScopeIngestionOptions,
) -> ProgramRegistry:
    if not isinstance(parsed, dict):
        raise ScopeIngestionError(f"{source} scope export root must be an object")
    profile = _profile_from_mapping(parsed, path=path, source=source, options=options)
    return ProgramRegistry(
        version=options.version or _version(source, options.captured_date),
        programs=[profile],
    )


def _profile_from_mapping(
    mapping: dict[object, object],
    *,
    path: Path,
    source: ScopeIngestionSource,
    options: ScopeIngestionOptions,
) -> ProgramProfile:
    source_reference = f"{path}:{source}"
    program_id = options.program_id or _program_id(mapping, source)
    scope_entries, exclusions, warnings = _scope_entries_from_mapping(
        mapping,
        source=source,
        source_reference=source_reference,
    )
    if not scope_entries:
        raise ScopeIngestionError(f"scope export produced no supported in-scope targets: {path}")
    metadata = {
        "ingested_source": source,
        "ingested_path": str(path),
    }
    if warnings:
        metadata["ingestion_warnings"] = " | ".join(warnings[:20])
    return ProgramProfile(
        id=program_id,
        name=options.name or _program_name(mapping, program_id),
        platform=options.platform or _platform_name(source),
        policy_url=options.policy_url or _policy_url(mapping),
        captured_date=options.captured_date,
        safe_harbor=_safe_harbor(mapping, source_reference),
        rate_limit=RateLimitPolicy(),
        scope=scope_entries,
        exclusions=exclusions,
        reward_tiers=_reward_tiers(mapping),
        metadata=metadata,
    )


def _scope_entries_from_mapping(
    mapping: dict[object, object],
    *,
    source: ScopeIngestionSource,
    source_reference: str,
) -> tuple[list[ProgramScopeEntry], list[ProgramExclusion], list[str]]:
    raw_items = _raw_scope_items(mapping, source)
    scope: list[ProgramScopeEntry] = []
    exclusions: list[ProgramExclusion] = []
    warnings: list[str] = []
    seen_scope: set[tuple[str, str]] = set()
    seen_exclusions: set[tuple[str, str]] = set()
    for index, item in enumerate(raw_items, start=1):
        converted = _convert_scope_item(item, source=source, source_reference=source_reference)
        if converted is None:
            warnings.append(f"skipped unsupported target at index {index}")
            continue
        kind, value, reward_eligible, in_scope, notes = converted
        key = (kind, value.lower())
        if in_scope:
            if key in seen_scope:
                continue
            seen_scope.add(key)
            try:
                scope.append(
                    ProgramScopeEntry(
                        id=_entry_id("scope", kind, value, len(scope) + 1),
                        kind=kind,
                        value=value,
                        reward_eligible=reward_eligible,
                        notes=notes,
                        source_reference=source_reference,
                        metadata={"ingested_source": source},
                    )
                )
            except ValueError as exc:
                warnings.append(f"skipped invalid in-scope target at index {index}: {exc}")
        else:
            if key in seen_exclusions:
                continue
            seen_exclusions.add(key)
            try:
                exclusions.append(
                    ProgramExclusion(
                        id=_entry_id("exclude", kind, value, len(exclusions) + 1),
                        kind=kind,
                        value=value,
                        reason=notes or "Marked out of scope by source export.",
                        source_reference=source_reference,
                    )
                )
            except ValueError as exc:
                warnings.append(f"skipped invalid out-of-scope target at index {index}: {exc}")
    return scope, exclusions, warnings


def _raw_scope_items(
    mapping: dict[object, object],
    source: ScopeIngestionSource,
) -> list[dict[str, object]]:
    if source == "hackerone":
        return _hackerone_items(mapping)
    if source == "bugcrowd":
        return _sectioned_items(mapping, in_keys=("in_scope", "in-scope"), out_keys=("out_of_scope", "out-of-scope"))
    if source == "intigriti":
        return _sectioned_items(mapping, in_keys=("in_scope", "inScope", "domains"), out_keys=("out_of_scope", "outOfScope"))
    return _sectioned_items(mapping, in_keys=("scope", "in_scope"), out_keys=("exclusions", "out_of_scope"))


def _hackerone_items(mapping: dict[object, object]) -> list[dict[str, object]]:
    raw = mapping.get("structured_scopes")
    if raw is None and isinstance(mapping.get("data"), list):
        raw = mapping.get("data")
    items: list[dict[str, object]] = []
    for item in _mapping_items(raw):
        attributes = item.get("attributes")
        merged = dict(item)
        if isinstance(attributes, dict):
            merged.update({str(key): value for key, value in attributes.items()})
        items.append(merged)
    return items


def _sectioned_items(
    mapping: dict[object, object],
    *,
    in_keys: tuple[str, ...],
    out_keys: tuple[str, ...],
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for key in in_keys:
        for item in _mapping_items(mapping.get(key)):
            merged = dict(item)
            merged.setdefault("in_scope", True)
            items.append(merged)
    for key in out_keys:
        for item in _mapping_items(mapping.get(key)):
            merged = dict(item)
            merged["in_scope"] = False
            items.append(merged)
    targets = mapping.get("targets")
    if isinstance(targets, dict):
        items.extend(_sectioned_items(targets, in_keys=in_keys, out_keys=out_keys))
    groups = mapping.get("target_groups")
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, dict):
                group_items = group.get("targets") or group.get("scope")
                for item in _mapping_items(group_items):
                    merged = dict(item)
                    merged.setdefault("in_scope", group.get("in_scope", True))
                    items.append(merged)
    if not items:
        items.extend(_mapping_items(mapping.get("scope")))
    return items


def _mapping_items(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append({str(key): nested for key, nested in item.items()})
        elif isinstance(item, str):
            items.append({"target": item})
    return items


def _convert_scope_item(
    item: dict[str, object],
    *,
    source: ScopeIngestionSource,
    source_reference: str,
) -> tuple[ScopeEntryKind, str, bool, bool, str] | None:
    raw_value = _first_string(
        item,
        (
            "asset_identifier",
            "target",
            "uri",
            "endpoint",
            "value",
            "asset",
            "identifier",
            "domain",
            "url",
        ),
    )
    if raw_value is None:
        return None
    raw_kind = _first_string(item, ("asset_type", "type", "category", "target_type", "kind")) or ""
    kind_value = _scope_kind_and_value(raw_kind=raw_kind, raw_value=raw_value)
    if kind_value is None:
        return None
    kind, value = kind_value
    in_scope = _bool_item(item, ("eligible_for_submission", "in_scope", "inScope", "inScopeForSubmission"), True)
    reward_eligible = _bool_item(
        item,
        ("eligible_for_bounty", "bounty", "reward", "reward_eligible", "eligibleForBounty"),
        True,
    )
    notes = (
        _first_string(item, ("instruction", "description", "notes", "comment"))
        or f"Ingested from {source} export."
    )
    return kind, value, reward_eligible, in_scope, notes[:1000]


def _scope_kind_and_value(*, raw_kind: str, raw_value: str) -> tuple[ScopeEntryKind, str] | None:
    value = raw_value.strip()
    lowered_kind = raw_kind.lower()
    lowered_value = value.lower()
    if not value or lowered_value in {"none", "n/a", "*"}:
        return None
    if any(token in lowered_kind for token in ("android", "ios", "mobile", "play", "app")) and "." in value:
        return "mobile_app", value
    if value.startswith("*."):
        return "host_suffix", value.removeprefix("*.").strip(".").lower()
    if value.startswith(("http://", "https://")):
        return "exact_url", _normalized_url(value)
    if any(token in lowered_kind for token in ("wildcard", "subdomain")):
        return "host_suffix", value.strip(".").lower()
    if any(token in lowered_kind for token in ("url", "website", "domain", "host", "api")) or "." in value:
        return "domain", value.strip(".").lower()
    return None


def _normalized_url(value: str) -> str:
    parsed = urlsplit(value)
    path = parsed.path or "/"
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def _bool_item(item: dict[str, object], keys: tuple[str, ...], default: bool) -> bool:
    for key in keys:
        value = item.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "yes", "1", "eligible", "in_scope", "in-scope"}:
                return True
            if lowered in {"false", "no", "0", "ineligible", "out_scope", "out-of-scope"}:
                return False
    return default


def _program_id(mapping: dict[object, object], source: ScopeIngestionSource) -> str:
    raw = _first_string(mapping, ("handle", "code", "id", "program_id", "slug", "name")) or f"{source}-program"
    return _slug(raw, max_length=128)


def _program_name(mapping: dict[object, object], program_id: str) -> str:
    return _first_string(mapping, ("name", "program_name", "title")) or program_id


def _platform_name(source: ScopeIngestionSource) -> str:
    return {
        "hackerone": "HackerOne",
        "bugcrowd": "Bugcrowd",
        "intigriti": "Intigriti",
        "public_json": "Public JSON",
        "auto": "Auto",
    }[source]


def _policy_url(mapping: dict[object, object]) -> str:
    return (
        _first_string(mapping, ("policy_url", "url", "program_url", "policy"))
        or "https://example.invalid/policy"
    )


def _safe_harbor(mapping: dict[object, object], source_reference: str) -> SafeHarborPolicy:
    summary = _first_string(mapping, ("safe_harbor", "safe_harbour", "policy_summary"))
    if summary is None:
        summary = "Follow the source program rules, stay in scope, and avoid third-party data."
    return SafeHarborPolicy(
        summary=summary,
        source_reference=source_reference,
        researcher_requirements=[
            "Use only authorized targets from the ingested scope export.",
            "Do not access third-party data.",
            "Honor the source program policy and rate limits.",
        ],
    )


def _reward_tiers(mapping: dict[object, object]) -> list[RewardTier]:
    raw = mapping.get("reward_tiers") or mapping.get("rewards")
    tiers: list[RewardTier] = []
    for index, item in enumerate(_mapping_items(raw), start=1):
        label = _first_string(item, ("label", "name", "category")) or f"Reward tier {index}"
        min_usd = _float_item(item, ("min_usd", "minimum", "min"), 0.0)
        max_usd = _float_item(item, ("max_usd", "maximum", "max"), min_usd)
        tiers.append(
            RewardTier(
                id=_entry_id("reward", "domain", label, index),
                label=label,
                min_usd=min_usd,
                max_usd=max_usd,
                notes=_first_string(item, ("notes", "description")) or "",
            )
        )
    return tiers


def _registry_warnings(registry: ProgramRegistry) -> list[str]:
    warnings: list[str] = []
    for program in registry.programs:
        warning_text = program.metadata.get("ingestion_warnings")
        if warning_text:
            warnings.extend(warning_text.split(" | "))
    return warnings


def _float_item(item: dict[str, object], keys: tuple[str, ...], default: float) -> float:
    for key in keys:
        value = item.get(key)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.replace("$", "").replace(",", "").strip())
            except ValueError:
                continue
    return default


def _first_string(mapping: Mapping[Any, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _version(source: ScopeIngestionSource, captured: date) -> str:
    return f"{source}-scope-{captured.isoformat()}"


def _entry_id(prefix: str, kind: str, value: str, index: int) -> str:
    kind_slug = _slug(kind, max_length=32)
    slug = _slug(value, max_length=72)
    return f"{prefix}-{kind_slug}-{slug}-{index}"[:128].strip("-")


def _slug(value: str, *, max_length: int) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:max_length].strip("-") or "item"
