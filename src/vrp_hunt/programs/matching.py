"""Scope matching for bug bounty program registries."""

from __future__ import annotations

from urllib.parse import urlsplit

from vrp_hunt.guardrails.models import TargetKind
from vrp_hunt.guardrails.normalization import (
    NormalizationError,
    NormalizedHost,
    host_matches_domain,
    host_matches_suffix,
    normalize_host,
    normalize_mobile_app,
    normalize_url,
)
from vrp_hunt.programs.models import (
    ProgramExclusion,
    ProgramProfile,
    ProgramRegistry,
    ProgramScopeDecision,
    ProgramScopeEntry,
)


def match_program_scope(
    registry: ProgramRegistry,
    *,
    target: str,
    target_kind: TargetKind | None = None,
    publisher: str | None = None,
) -> ProgramScopeDecision:
    """Return the first program scope decision for a target."""

    inferred_kind = target_kind or _infer_target_kind(target)
    try:
        normalized_host = _normalized_host(target, inferred_kind)
        normalized_target = _normalized_target(target, inferred_kind, normalized_host)
    except NormalizationError as exc:
        return ProgramScopeDecision(
            decision="UNKNOWN",
            target_kind=inferred_kind,
            target=target,
            reason=f"target could not be normalized: {exc}",
        )

    for program in registry.programs:
        exclusion = _matching_exclusion(
            program.exclusions,
            target=target,
            target_kind=inferred_kind,
            normalized_host=normalized_host,
            normalized_target=normalized_target,
            publisher=publisher,
        )
        if exclusion is not None:
            return _decision_from_exclusion(
                program,
                exclusion,
                target=target,
                target_kind=inferred_kind,
                normalized_target=normalized_target,
            )

    for program in registry.programs:
        scope_entry = _matching_scope_entry(
            program.scope,
            target=target,
            target_kind=inferred_kind,
            normalized_host=normalized_host,
            normalized_target=normalized_target,
            publisher=publisher,
        )
        if scope_entry is not None:
            return _decision_from_scope_entry(
                program,
                scope_entry,
                target=target,
                target_kind=inferred_kind,
                normalized_target=normalized_target,
            )

    return ProgramScopeDecision(
        decision="UNKNOWN",
        target_kind=inferred_kind,
        target=target,
        normalized_target=normalized_target,
        reason="no program scope entry matched target",
    )


def _matching_exclusion(
    exclusions: list[ProgramExclusion],
    *,
    target: str,
    target_kind: TargetKind,
    normalized_host: NormalizedHost | None,
    normalized_target: str,
    publisher: str | None,
) -> ProgramExclusion | None:
    for exclusion in exclusions:
        if _entry_matches(
            exclusion,
            target=target,
            target_kind=target_kind,
            normalized_host=normalized_host,
            normalized_target=normalized_target,
            publisher=publisher,
        ):
            return exclusion
    return None


def _matching_scope_entry(
    entries: list[ProgramScopeEntry],
    *,
    target: str,
    target_kind: TargetKind,
    normalized_host: NormalizedHost | None,
    normalized_target: str,
    publisher: str | None,
) -> ProgramScopeEntry | None:
    for entry in entries:
        if _entry_matches(
            entry,
            target=target,
            target_kind=target_kind,
            normalized_host=normalized_host,
            normalized_target=normalized_target,
            publisher=publisher,
        ):
            return entry
    return None


def _entry_matches(
    entry: ProgramScopeEntry | ProgramExclusion,
    *,
    target: str,
    target_kind: TargetKind,
    normalized_host: NormalizedHost | None,
    normalized_target: str,
    publisher: str | None,
) -> bool:
    if entry.kind == "domain":
        return normalized_host is not None and host_matches_domain(normalized_host, entry.value)
    if entry.kind == "host_suffix":
        return normalized_host is not None and host_matches_suffix(normalized_host, entry.value)
    if entry.kind == "exact_host":
        return (
            normalized_host is not None
            and normalized_host.host == normalize_host(entry.value).host
        )
    if entry.kind == "exact_url":
        return target_kind == "url" and _canonical_url(target) == _canonical_url(entry.value)
    if entry.kind == "mobile_app":
        return (
            target_kind == "mobile_app"
            and normalized_target == normalize_mobile_app(entry.value)
        )
    if entry.kind == "mobile_publisher":
        return target_kind == "mobile_app" and (publisher or "").strip() == entry.value
    return False


def _decision_from_exclusion(
    program: ProgramProfile,
    exclusion: ProgramExclusion,
    *,
    target: str,
    target_kind: TargetKind,
    normalized_target: str,
) -> ProgramScopeDecision:
    return ProgramScopeDecision(
        decision="OUT_OF_SCOPE",
        target_kind=target_kind,
        target=target,
        normalized_target=normalized_target,
        program_id=program.id,
        program_name=program.name,
        matched_entry_id=exclusion.id,
        reason=exclusion.reason,
        source_reference=exclusion.source_reference,
    )


def _decision_from_scope_entry(
    program: ProgramProfile,
    entry: ProgramScopeEntry,
    *,
    target: str,
    target_kind: TargetKind,
    normalized_target: str,
) -> ProgramScopeDecision:
    return ProgramScopeDecision(
        decision="IN_SCOPE",
        target_kind=target_kind,
        target=target,
        normalized_target=normalized_target,
        program_id=program.id,
        program_name=program.name,
        matched_entry_id=entry.id,
        reward_eligible=entry.reward_eligible,
        safe_harbor_summary=program.safe_harbor.summary,
        rate_limit=program.rate_limit,
        reason=entry.notes or "target matched program scope",
        source_reference=entry.source_reference,
    )


def _infer_target_kind(target: str) -> TargetKind:
    stripped = target.strip()
    if "://" in stripped:
        return "url"
    return "host"


def _normalized_host(target: str, target_kind: TargetKind) -> NormalizedHost | None:
    if target_kind == "url":
        return normalize_url(target)
    if target_kind == "host":
        return normalize_host(target)
    return None


def _normalized_target(
    target: str,
    target_kind: TargetKind,
    normalized_host: NormalizedHost | None,
) -> str:
    if target_kind in {"host", "url"}:
        assert normalized_host is not None
        return normalized_host.host
    return normalize_mobile_app(target)


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    normalized_host = normalize_url(value).host
    scheme = parsed.scheme.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{normalized_host}{path}{query}"
