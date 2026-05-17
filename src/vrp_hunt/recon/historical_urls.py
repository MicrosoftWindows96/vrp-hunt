"""Offline historical URL ingestion from passive archives."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset, AssetKind

HistoricalUrlSource = Literal["wayback", "urlscan", "common_crawl"]

STATIC_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".map",
    ".mp3",
    ".mp4",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".wasm",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
JAVASCRIPT_EXTENSIONS = {".js", ".mjs"}


class HistoricalUrlRecord(StrictModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    path: str = Field(min_length=1)
    source: HistoricalUrlSource
    evidence: str = Field(min_length=1)
    observed_at: str | None = None
    status_code: str | None = None
    content_type: str | None = None
    digest: str | None = None
    parameter_names: list[str] = Field(default_factory=list)

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


class HistoricalUrlIngestionReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_records: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    records: list[HistoricalUrlRecord] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def ingest_historical_url_files(
    *,
    wayback_files: list[Path] | None = None,
    urlscan_files: list[Path] | None = None,
    common_crawl_files: list[Path] | None = None,
    scope_domains: list[str],
) -> HistoricalUrlIngestionReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    records: list[HistoricalUrlRecord] = []
    warnings: list[str] = []
    total_inputs = 0
    source_paths: tuple[tuple[HistoricalUrlSource, list[Path]], ...] = (
        ("wayback", wayback_files or []),
        ("urlscan", urlscan_files or []),
        ("common_crawl", common_crawl_files or []),
    )
    for source, paths in source_paths:
        for path in paths:
            loaded, load_warnings, input_count = load_historical_url_records(
                path,
                source=source,
                scope_domains=normalized_scope,
            )
            records.extend(loaded)
            warnings.extend(load_warnings)
            total_inputs += input_count

    deduped_records = _dedupe_records(records)
    assets = historical_url_assets(deduped_records)
    return HistoricalUrlIngestionReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_records=len(deduped_records),
        total_assets=len(assets),
        records=deduped_records,
        assets=assets,
        warnings=warnings,
    )


def load_historical_url_records(
    path: Path,
    *,
    source: HistoricalUrlSource,
    scope_domains: list[str],
) -> tuple[list[HistoricalUrlRecord], list[str], int]:
    text = path.read_text(encoding="utf-8")
    items = _items_for_source(text, source)
    records: list[HistoricalUrlRecord] = []
    warnings: list[str] = []
    for index, item in enumerate(items, start=1):
        raw_urls = _urls_from_item(item, source=source)
        for raw in raw_urls:
            parsed = _record_from_raw_url(
                raw.url,
                source=source,
                evidence=str(path),
                scope_domains=scope_domains,
                observed_at=raw.observed_at,
                status_code=raw.status_code,
                content_type=raw.content_type,
                digest=raw.digest,
            )
            if parsed is not None:
                records.append(parsed)
        if not raw_urls:
            warnings.append(f"{path}:{index}: no URL field found")
    return records, warnings, len(items)


def historical_url_assets(records: list[HistoricalUrlRecord]) -> list[Asset]:
    assets: list[Asset] = []
    for record in records:
        metadata = {
            "historical_source": record.source,
            "evidence": record.evidence,
        }
        if record.observed_at:
            metadata["observed_at"] = record.observed_at
        if record.status_code:
            metadata["status_code"] = record.status_code
        if record.content_type:
            metadata["content_type"] = record.content_type
        if record.digest:
            metadata["digest"] = record.digest
        if record.parameter_names:
            metadata["parameter_names"] = ",".join(record.parameter_names)
            metadata["query_values_redacted"] = "true"
        assets.append(
            Asset(
                kind=_asset_kind(record.url),
                value=record.url,
                source="historical-url-import",
                parent=record.host,
                metadata=metadata,
            )
        )
    return assets


class _RawHistoricalUrl(StrictModel):
    url: str
    observed_at: str | None = None
    status_code: str | None = None
    content_type: str | None = None
    digest: str | None = None


def _items_for_source(text: str, source: HistoricalUrlSource) -> list[object]:
    stripped = text.strip()
    if not stripped:
        return []
    parsed = _parse_json_export(stripped)
    if parsed is None:
        return [line.strip() for line in text.splitlines() if line.strip()]
    if source == "wayback" and _looks_like_cdx_rows(parsed):
        return _cdx_rows_to_items(parsed)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("results", "records", "data", "items", "pages"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return []


def _parse_json_export(text: str) -> object | None:
    try:
        return cast(object, json.loads(text))
    except json.JSONDecodeError:
        items: list[object] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                return None
        return items


def _looks_like_cdx_rows(parsed: object) -> bool:
    return (
        isinstance(parsed, list)
        and len(parsed) > 1
        and isinstance(parsed[0], list)
        and all(isinstance(item, str) for item in parsed[0])
    )


def _cdx_rows_to_items(parsed: object) -> list[object]:
    if not isinstance(parsed, list):
        return []
    rows = [row for row in parsed if isinstance(row, list)]
    if not rows:
        return []
    headers = [str(item) for item in rows[0]]
    items: list[object] = []
    for row in rows[1:]:
        values = [str(item) for item in row]
        items.append(dict(zip(headers, values, strict=False)))
    return items


def _urls_from_item(item: object, *, source: HistoricalUrlSource) -> list[_RawHistoricalUrl]:
    if isinstance(item, str):
        return [_RawHistoricalUrl(url=item)]
    if not isinstance(item, dict):
        return []
    if source == "urlscan":
        return _urlscan_urls(item)
    urls: list[_RawHistoricalUrl] = []
    for key in ("url", "original", "original_url", "request_url", "page_url"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            urls.append(_raw_from_mapping(value, item))
    if not urls:
        urls.extend(_urls_from_list_fields(item, ("urls", "url_list", "captures")))
    return urls


def _urlscan_urls(item: dict[object, object]) -> list[_RawHistoricalUrl]:
    urls: list[_RawHistoricalUrl] = []
    for key in ("url", "result"):
        value = item.get(key)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            urls.append(_raw_from_mapping(value, item))
    for nested_key in ("page", "task", "data"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            for key in ("url", "requestURL", "documentURL"):
                value = nested.get(key)
                if isinstance(value, str) and value.strip():
                    urls.append(_raw_from_mapping(value, item))
    urls.extend(_urls_from_list_fields(item, ("urls", "requests")))
    return urls


def _urls_from_list_fields(
    item: dict[object, object],
    keys: tuple[str, ...],
) -> list[_RawHistoricalUrl]:
    urls: list[_RawHistoricalUrl] = []
    for key in keys:
        value = item.get(key)
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, str) and entry.strip():
                    urls.append(_raw_from_mapping(entry, item))
                elif isinstance(entry, dict):
                    urls.extend(_urls_from_item(entry, source="common_crawl"))
    return urls


def _raw_from_mapping(url: str, mapping: dict[object, object]) -> _RawHistoricalUrl:
    return _RawHistoricalUrl(
        url=url,
        observed_at=_first_string(mapping, ("timestamp", "date", "time", "indexed_at", "task_time")),
        status_code=_first_string(mapping, ("status", "statuscode", "status_code", "response_status")),
        content_type=_first_string(mapping, ("mime", "mimetype", "content_type", "mime_type")),
        digest=_first_string(mapping, ("digest", "hash", "sha256")),
    )


def _record_from_raw_url(
    raw_url: str,
    *,
    source: HistoricalUrlSource,
    evidence: str,
    scope_domains: list[str],
    observed_at: str | None,
    status_code: str | None,
    content_type: str | None,
    digest: str | None,
) -> HistoricalUrlRecord | None:
    sanitized = _sanitize_url(raw_url)
    if sanitized is None:
        return None
    host = urlsplit(sanitized.url).hostname or ""
    scope_domain = _matching_scope_domain(host, scope_domains)
    if scope_domain is None:
        return None
    return HistoricalUrlRecord(
        url=sanitized.url,
        host=host,
        path=urlsplit(sanitized.url).path or "/",
        source=source,
        evidence=evidence,
        observed_at=observed_at,
        status_code=status_code,
        content_type=content_type,
        digest=digest,
        parameter_names=sanitized.parameter_names,
    )


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return None
    path = parsed.path or "/"
    host = parsed.hostname.lower()
    try:
        normalize_host(host)
    except NormalizationError:
        return None
    parameter_names = sorted(
        {
            item.split("=", 1)[0].strip()
            for item in parsed.query.split("&")
            if item.strip() and item.split("=", 1)[0].strip()
        }
    )
    port = f":{parsed.port}" if parsed.port is not None else ""
    url = urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", ""))
    return _SanitizedUrl(url=url, parameter_names=parameter_names)


def _asset_kind(url: str) -> AssetKind:
    path = urlsplit(url).path.lower()
    extension = _extension(path)
    if extension in JAVASCRIPT_EXTENSIONS:
        return "javascript"
    if path and path != "/" and extension not in STATIC_EXTENSIONS:
        return "endpoint"
    return "url"


def _extension(path: str) -> str:
    filename = path.rsplit("/", 1)[-1]
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def _first_string(mapping: dict[object, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int):
            return str(value)
    return None


def _matching_scope_domain(host: str, scope_domains: list[str]) -> str | None:
    for domain in scope_domains:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if not candidate:
            continue
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        try:
            host = normalize_host(candidate).host
        except NormalizationError as exc:
            raise ValueError(f"invalid scope domain: {value!r}") from exc
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one scope domain is required")
    return normalized


def _dedupe_records(records: list[HistoricalUrlRecord]) -> list[HistoricalUrlRecord]:
    by_key: dict[tuple[str, HistoricalUrlSource], HistoricalUrlRecord] = {}
    for record in records:
        key = (record.url, record.source)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = record
        elif not existing.parameter_names and record.parameter_names:
            by_key[key] = record
    return sorted(by_key.values(), key=lambda record: (record.url, record.source))
