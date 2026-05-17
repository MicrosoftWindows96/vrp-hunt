"""Offline screenshot clustering and visual diffing."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

ScreenshotSnapshotRole = Literal["current", "previous"]
ScreenshotDiffType = Literal["new", "removed", "changed"]


class ScreenshotManifestDocument(StrictModel):
    role: ScreenshotSnapshotRole = "current"
    evidence: str = Field(min_length=1)
    text: str = ""


class ScreenshotObservation(StrictModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    role: ScreenshotSnapshotRole = "current"
    screenshot_path: str | None = None
    visual_hash: str | None = None
    content_hash: str | None = None
    title: str | None = None
    status_code: str | None = None
    width: int | None = Field(default=None, ge=0)
    height: int | None = Field(default=None, ge=0)
    observed_at: str | None = None
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("screenshot URL must be absolute http(s)")
        return sanitized.url

    @field_validator("visual_hash", "content_hash")
    @classmethod
    def normalize_hash(cls, value: str | None) -> str | None:
        return value.strip().lower() if isinstance(value, str) and value.strip() else None

    @field_validator("parameter_names")
    @classmethod
    def clean_parameter_names(cls, value: list[str]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for item in value:
            name = item.strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names


class ScreenshotCluster(StrictModel):
    cluster_id: str = Field(min_length=1)
    representative_hash: str | None = None
    observation_count: int = Field(ge=0)
    urls: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    titles: list[str] = Field(default_factory=list)
    screenshot_paths: list[str] = Field(default_factory=list)


class ScreenshotDiff(StrictModel):
    url: str = Field(min_length=1)
    diff_type: ScreenshotDiffType
    previous_hash: str | None = None
    current_hash: str | None = None
    previous_title: str | None = None
    current_title: str | None = None
    previous_status_code: str | None = None
    current_status_code: str | None = None

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("diff URL must be absolute http(s)")
        return sanitized.url


class ScreenshotAnalysisReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_observations: int = Field(ge=0)
    total_clusters: int = Field(ge=0)
    total_diffs: int = Field(ge=0)
    observations: list[ScreenshotObservation] = Field(default_factory=list)
    clusters: list[ScreenshotCluster] = Field(default_factory=list)
    diffs: list[ScreenshotDiff] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def analyze_screenshot_manifests(
    documents: list[ScreenshotManifestDocument],
    *,
    scope_domains: list[str],
) -> ScreenshotAnalysisReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    observations: list[ScreenshotObservation] = []
    warnings: list[str] = []
    total_inputs = 0
    for document in documents:
        items = _items_from_text(document.text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            observation, item_warning = _observation_from_item(
                item,
                document=document,
                index=index,
                scope_domains=normalized_scope,
            )
            if observation is not None:
                observations.append(observation)
            if item_warning is not None:
                warnings.append(item_warning)

    deduped_observations = _dedupe_observations(observations)
    current_observations = [item for item in deduped_observations if item.role == "current"]
    clusters = _clusters_for_observations(current_observations)
    diffs = _diff_observations(deduped_observations)
    assets = screenshot_analysis_assets(current_observations, clusters, diffs)
    return ScreenshotAnalysisReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_observations=len(deduped_observations),
        total_clusters=len(clusters),
        total_diffs=len(diffs),
        observations=deduped_observations,
        clusters=clusters,
        diffs=diffs,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def load_screenshot_manifest_documents(
    *,
    current_files: list[Path] | None = None,
    previous_files: list[Path] | None = None,
) -> list[ScreenshotManifestDocument]:
    documents: list[ScreenshotManifestDocument] = []
    for path in current_files or []:
        documents.append(
            ScreenshotManifestDocument(role="current", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    for path in previous_files or []:
        documents.append(
            ScreenshotManifestDocument(role="previous", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    return documents


def screenshot_analysis_assets(
    observations: list[ScreenshotObservation],
    clusters: list[ScreenshotCluster],
    diffs: list[ScreenshotDiff],
) -> list[Asset]:
    assets: list[Asset] = []
    for observation in observations:
        metadata = _observation_metadata(observation)
        assets.append(
            Asset(
                kind="url",
                value=observation.url,
                source="screenshot-analysis",
                parent=observation.host,
                metadata=metadata,
            )
        )
    for cluster in clusters:
        assets.append(
            Asset(
                kind="note",
                value=f"screenshot-cluster:{cluster.cluster_id}",
                source="screenshot-cluster",
                metadata={
                    "observation_count": str(cluster.observation_count),
                    "representative_hash": cluster.representative_hash or "",
                    "hosts": ",".join(cluster.hosts),
                    "urls": ",".join(cluster.urls[:10]),
                },
            )
        )
    for diff in diffs:
        assets.append(
            Asset(
                kind="note",
                value=f"screenshot-diff:{diff.url}",
                source="screenshot-diff",
                parent=diff.url,
                metadata={
                    "diff_type": diff.diff_type,
                    "previous_hash": diff.previous_hash or "",
                    "current_hash": diff.current_hash or "",
                    "previous_status_code": diff.previous_status_code or "",
                    "current_status_code": diff.current_status_code or "",
                },
            )
        )
    return _dedupe_assets(assets)


def _observation_from_item(
    item: object,
    *,
    document: ScreenshotManifestDocument,
    index: int,
    scope_domains: list[str],
) -> tuple[ScreenshotObservation | None, str | None]:
    if not isinstance(item, dict):
        return None, f"{document.evidence}:{index}: skipped non-object record"
    raw_url = _first_string(item, ("url", "final_url", "input", "target", "page_url"))
    if raw_url is None:
        return None, f"{document.evidence}:{index}: missing url"
    sanitized = _sanitize_url(raw_url)
    if sanitized is None:
        return None, f"{document.evidence}:{index}: invalid url"
    host = urlsplit(sanitized.url).hostname or ""
    if not _host_allowed(host, scope_domains):
        return None, f"{document.evidence}:{index}: skipped third-party host {host}"
    visual_hash = _first_string(
        item,
        (
            "visual_hash",
            "screenshot_hash",
            "image_hash",
            "perceptual_hash",
            "phash",
            "sha256",
            "hash",
        ),
    )
    content_hash = _first_string(item, ("content_hash", "body_hash", "dom_hash", "html_hash"))
    if visual_hash is None and content_hash is None:
        return None, f"{document.evidence}:{index}: missing visual or content hash"
    return (
        ScreenshotObservation(
            url=sanitized.url,
            host=host,
            evidence=document.evidence,
            role=document.role,
            screenshot_path=_first_string(item, ("screenshot_path", "screenshot", "image_path", "path")),
            visual_hash=visual_hash,
            content_hash=content_hash,
            title=_first_string(item, ("title", "page_title")),
            status_code=_string_or_none(item.get("status_code") or item.get("status")),
            width=_int_or_none(item.get("width")),
            height=_int_or_none(item.get("height")),
            observed_at=_first_string(item, ("observed_at", "timestamp", "captured_at", "time")),
            parameter_names=sanitized.parameter_names,
        ),
        None,
    )


def _clusters_for_observations(observations: list[ScreenshotObservation]) -> list[ScreenshotCluster]:
    grouped: dict[str, list[ScreenshotObservation]] = {}
    for observation in observations:
        key = observation.visual_hash or observation.content_hash or observation.url
        grouped.setdefault(key, []).append(observation)
    clusters: list[ScreenshotCluster] = []
    for index, key in enumerate(sorted(grouped), start=1):
        members = sorted(grouped[key], key=lambda item: item.url)
        clusters.append(
            ScreenshotCluster(
                cluster_id=f"cluster-{index:04d}",
                representative_hash=key if key != members[0].url else None,
                observation_count=len(members),
                urls=_unique_sorted(item.url for item in members),
                hosts=_unique_sorted(item.host for item in members),
                titles=_unique_sorted(item.title for item in members if item.title),
                screenshot_paths=_unique_sorted(item.screenshot_path for item in members if item.screenshot_path),
            )
        )
    return clusters


def _diff_observations(observations: list[ScreenshotObservation]) -> list[ScreenshotDiff]:
    current_by_url = {item.url: item for item in observations if item.role == "current"}
    previous_by_url = {item.url: item for item in observations if item.role == "previous"}
    diffs: list[ScreenshotDiff] = []
    for url in sorted(set(current_by_url) | set(previous_by_url)):
        current = current_by_url.get(url)
        previous = previous_by_url.get(url)
        if current is None and previous is not None:
            diffs.append(_diff_from(previous=previous, current=None, diff_type="removed"))
        elif current is not None and previous is None:
            diffs.append(_diff_from(previous=None, current=current, diff_type="new"))
        elif current is not None and previous is not None and _changed(previous, current):
            diffs.append(_diff_from(previous=previous, current=current, diff_type="changed"))
    return diffs


def _diff_from(
    *,
    previous: ScreenshotObservation | None,
    current: ScreenshotObservation | None,
    diff_type: ScreenshotDiffType,
) -> ScreenshotDiff:
    url = current.url if current is not None else previous.url if previous is not None else ""
    return ScreenshotDiff(
        url=url,
        diff_type=diff_type,
        previous_hash=_comparison_hash(previous),
        current_hash=_comparison_hash(current),
        previous_title=previous.title if previous is not None else None,
        current_title=current.title if current is not None else None,
        previous_status_code=previous.status_code if previous is not None else None,
        current_status_code=current.status_code if current is not None else None,
    )


def _changed(previous: ScreenshotObservation, current: ScreenshotObservation) -> bool:
    return (
        _comparison_hash(previous) != _comparison_hash(current)
        or previous.title != current.title
        or previous.status_code != current.status_code
    )


def _comparison_hash(observation: ScreenshotObservation | None) -> str | None:
    if observation is None:
        return None
    return observation.visual_hash or observation.content_hash


def _observation_metadata(observation: ScreenshotObservation) -> dict[str, str]:
    metadata = {
        "host": observation.host,
        "evidence": observation.evidence,
    }
    optional = {
        "screenshot_path": observation.screenshot_path,
        "visual_hash": observation.visual_hash,
        "content_hash": observation.content_hash,
        "title": observation.title,
        "status_code": observation.status_code,
        "observed_at": observation.observed_at,
    }
    for key, value in optional.items():
        if value:
            metadata[key] = value
    if observation.width is not None:
        metadata["width"] = str(observation.width)
    if observation.height is not None:
        metadata["height"] = str(observation.height)
    if observation.parameter_names:
        metadata["parameter_names"] = ",".join(observation.parameter_names)
        metadata["query_values_redacted"] = "true"
    return metadata


def _items_from_text(text: str) -> list[object]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        items: list[object] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("screenshots", "results", "items", "data", "pages"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return []


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
    )


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        host = _normalize_host(candidate)
        if host is None:
            continue
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one scope domain is required")
    return normalized


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _first_string(item: dict[object, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _unique_sorted(values: Iterable[object]) -> list[str]:
    return sorted({str(value) for value in values if value})


def _dedupe_observations(observations: list[ScreenshotObservation]) -> list[ScreenshotObservation]:
    by_key = {(observation.role, observation.url): observation for observation in observations}
    return sorted(by_key.values(), key=lambda observation: (observation.role, observation.url))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
