"""Offline technology fingerprinting from saved HTTP metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

TechnologyMetadataSource = Literal["httpx", "wappalyzer"]
TechnologyEvidenceType = Literal["declared-technology", "http-header", "cdn", "webserver"]


class TechnologyMetadataDocument(StrictModel):
    source: TechnologyMetadataSource
    evidence: str = Field(min_length=1)
    text: str = ""


class TechnologyFingerprint(StrictModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    name: str = Field(min_length=1)
    metadata_source: TechnologyMetadataSource
    evidence_type: TechnologyEvidenceType
    evidence: str = Field(min_length=1)
    version: str | None = None
    confidence: str | None = None
    categories: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("fingerprint URL must be absolute http(s)")
        return sanitized.url

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return value.strip()

    @field_validator("categories", "parameter_names")
    @classmethod
    def clean_string_list(cls, value: list[str]) -> list[str]:
        items: list[str] = []
        seen: set[str] = set()
        for item in value:
            candidate = item.strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                items.append(candidate)
        return items


class TechnologyFingerprintReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_fingerprints: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    fingerprints: list[TechnologyFingerprint] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def fingerprint_technology_metadata(
    documents: list[TechnologyMetadataDocument],
    *,
    scope_domains: list[str],
) -> TechnologyFingerprintReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    fingerprints: list[TechnologyFingerprint] = []
    warnings: list[str] = []
    total_inputs = 0
    for document in documents:
        items = _items_from_text(document.text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            parsed, item_warnings = _fingerprints_from_item(
                item,
                document=document,
                index=index,
                scope_domains=normalized_scope,
            )
            fingerprints.extend(parsed)
            warnings.extend(item_warnings)
    deduped_fingerprints = _dedupe_fingerprints(fingerprints)
    assets = technology_fingerprint_assets(deduped_fingerprints)
    return TechnologyFingerprintReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_fingerprints=len(deduped_fingerprints),
        total_assets=len(assets),
        fingerprints=deduped_fingerprints,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def load_technology_metadata_documents(
    *,
    httpx_files: list[Path] | None = None,
    wappalyzer_files: list[Path] | None = None,
) -> list[TechnologyMetadataDocument]:
    documents: list[TechnologyMetadataDocument] = []
    for path in httpx_files or []:
        documents.append(
            TechnologyMetadataDocument(source="httpx", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    for path in wappalyzer_files or []:
        documents.append(
            TechnologyMetadataDocument(source="wappalyzer", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    return documents


def technology_fingerprint_assets(fingerprints: list[TechnologyFingerprint]) -> list[Asset]:
    assets: list[Asset] = []
    for fingerprint in fingerprints:
        metadata = {
            "metadata_source": fingerprint.metadata_source,
            "evidence_type": fingerprint.evidence_type,
            "evidence": fingerprint.evidence,
            "host": fingerprint.host,
        }
        if fingerprint.version:
            metadata["version"] = fingerprint.version
        if fingerprint.confidence:
            metadata["confidence"] = fingerprint.confidence
        if fingerprint.categories:
            metadata["categories"] = ",".join(fingerprint.categories)
        if fingerprint.parameter_names:
            metadata["parameter_names"] = ",".join(fingerprint.parameter_names)
            metadata["query_values_redacted"] = "true"
        assets.append(
            Asset(
                kind="technology",
                value=fingerprint.name,
                source="technology-fingerprint",
                parent=fingerprint.url,
                metadata=metadata,
            )
        )
    return _dedupe_assets(assets)


def _fingerprints_from_item(
    item: object,
    *,
    document: TechnologyMetadataDocument,
    index: int,
    scope_domains: list[str],
) -> tuple[list[TechnologyFingerprint], list[str]]:
    if not isinstance(item, dict):
        return [], [f"{document.evidence}:{index}: skipped non-object record"]
    raw_url = _first_string(item, ("url", "final_url", "target", "site"))
    if raw_url is None:
        return [], [f"{document.evidence}:{index}: missing url"]
    sanitized = _sanitize_url(raw_url)
    if sanitized is None:
        return [], [f"{document.evidence}:{index}: invalid url"]
    host = urlsplit(sanitized.url).hostname or ""
    if not _host_allowed(host, scope_domains):
        return [], [f"{document.evidence}:{index}: skipped third-party host {host}"]
    if document.source == "wappalyzer":
        return _wappalyzer_fingerprints(item, document=document, url=sanitized.url, host=host), []
    return _httpx_fingerprints(
        item,
        document=document,
        url=sanitized.url,
        host=host,
        parameter_names=sanitized.parameter_names,
    ), []


def _httpx_fingerprints(
    item: dict[object, object],
    *,
    document: TechnologyMetadataDocument,
    url: str,
    host: str,
    parameter_names: list[str],
) -> list[TechnologyFingerprint]:
    fingerprints: list[TechnologyFingerprint] = []
    technologies = item.get("technologies") or item.get("tech")
    fingerprints.extend(
        _technology_entries(
            technologies,
            document=document,
            url=url,
            host=host,
            evidence_type="declared-technology",
            parameter_names=parameter_names,
        )
    )
    headers = item.get("headers") or item.get("header")
    if isinstance(headers, dict):
        fingerprints.extend(_header_fingerprints(headers, document=document, url=url, host=host))
    for key, evidence_type in (("webserver", "webserver"), ("server", "http-header"), ("cdn_name", "cdn")):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            fingerprints.append(
                TechnologyFingerprint(
                    url=url,
                    host=host,
                    name=value,
                    metadata_source=document.source,
                    evidence_type=cast(TechnologyEvidenceType, evidence_type),
                    evidence=f"{document.evidence}:{key}",
                    parameter_names=parameter_names,
                )
            )
    return fingerprints


def _wappalyzer_fingerprints(
    item: dict[object, object],
    *,
    document: TechnologyMetadataDocument,
    url: str,
    host: str,
) -> list[TechnologyFingerprint]:
    entries = item.get("technologies") or item.get("applications")
    fingerprints = _technology_entries(
        entries,
        document=document,
        url=url,
        host=host,
        evidence_type="declared-technology",
        parameter_names=[],
    )
    apps = item.get("apps")
    if isinstance(apps, dict):
        for name, details in apps.items():
            detail_map = details if isinstance(details, dict) else {}
            fingerprints.append(
                TechnologyFingerprint(
                    url=url,
                    host=host,
                    name=str(name),
                    metadata_source=document.source,
                    evidence_type="declared-technology",
                    evidence=document.evidence,
                    version=_string_or_none(detail_map.get("version")),
                    confidence=_string_or_none(detail_map.get("confidence")),
                    categories=_category_names(detail_map.get("categories")),
                )
            )
    return fingerprints


def _technology_entries(
    entries: object,
    *,
    document: TechnologyMetadataDocument,
    url: str,
    host: str,
    evidence_type: TechnologyEvidenceType,
    parameter_names: list[str],
) -> list[TechnologyFingerprint]:
    fingerprints: list[TechnologyFingerprint] = []
    if not isinstance(entries, list):
        return fingerprints
    for entry in entries:
        if isinstance(entry, str) and entry.strip():
            fingerprints.append(
                TechnologyFingerprint(
                    url=url,
                    host=host,
                    name=entry,
                    metadata_source=document.source,
                    evidence_type=evidence_type,
                    evidence=document.evidence,
                    parameter_names=parameter_names,
                )
            )
        elif isinstance(entry, dict):
            name = _first_string(entry, ("name", "technology", "slug"))
            if name is None:
                continue
            fingerprints.append(
                TechnologyFingerprint(
                    url=url,
                    host=host,
                    name=name,
                    metadata_source=document.source,
                    evidence_type=evidence_type,
                    evidence=document.evidence,
                    version=_string_or_none(entry.get("version")),
                    confidence=_string_or_none(entry.get("confidence")),
                    categories=_category_names(entry.get("categories")),
                    parameter_names=parameter_names,
                )
            )
    return fingerprints


def _header_fingerprints(
    headers: dict[object, object],
    *,
    document: TechnologyMetadataDocument,
    url: str,
    host: str,
) -> list[TechnologyFingerprint]:
    fingerprints: list[TechnologyFingerprint] = []
    for header_name, value in headers.items():
        normalized_name = str(header_name).strip().lower()
        if normalized_name not in {"server", "x-powered-by", "x-generator", "via"}:
            continue
        if value is None or not str(value).strip():
            continue
        fingerprints.append(
            TechnologyFingerprint(
                url=url,
                host=host,
                name=str(value).strip(),
                metadata_source=document.source,
                evidence_type="http-header",
                evidence=f"{document.evidence}:header:{normalized_name}",
            )
        )
    return fingerprints


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
        for key in ("results", "items", "data", "pages"):
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


def _category_names(value: object) -> list[str]:
    names: list[str] = []
    if isinstance(value, list):
        for category in value:
            if isinstance(category, str):
                names.append(category)
            elif isinstance(category, dict):
                name = _first_string(category, ("name", "slug", "id"))
                if name:
                    names.append(name)
    return names


def _dedupe_fingerprints(fingerprints: list[TechnologyFingerprint]) -> list[TechnologyFingerprint]:
    by_key = {
        (
            fingerprint.url,
            fingerprint.name.lower(),
            fingerprint.metadata_source,
            fingerprint.evidence_type,
            fingerprint.version or "",
        ): fingerprint
        for fingerprint in fingerprints
    }
    return sorted(by_key.values(), key=lambda fingerprint: (fingerprint.url, fingerprint.name.lower()))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
