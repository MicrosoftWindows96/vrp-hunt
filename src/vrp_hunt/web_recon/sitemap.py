"""Offline sitemap.xml parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset, AssetKind

SitemapEntryType = Literal["url", "sitemap"]

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


class SitemapEntry(StrictModel):
    url: str = Field(min_length=1)
    entry_type: SitemapEntryType
    source_sitemap: str = Field(min_length=1)
    lastmod: str | None = None
    changefreq: str | None = None
    priority: str | None = None
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("url", "source_sitemap")
    @classmethod
    def normalize_urls(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("sitemap entry URL must be absolute http(s)")
        return sanitized.url

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


class SitemapParseReport(StrictModel):
    sitemap_url: str = Field(min_length=1)
    scope_domains: list[str] = Field(min_length=1)
    total_entries: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    entries: list[SitemapEntry] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("sitemap_url")
    @classmethod
    def normalize_sitemap_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("sitemap URL must be absolute http(s)")
        return sanitized.url


class SitemapImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    total_entries: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[SitemapParseReport] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def parse_sitemap_xml(
    sitemap_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
) -> SitemapParseReport:
    normalized_url = SitemapParseReport(
        sitemap_url=sitemap_url,
        scope_domains=_effective_scope_domains(sitemap_url, scope_domains),
        total_entries=0,
        total_assets=0,
    ).sitemap_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    warnings: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid sitemap XML: {exc}") from exc

    root_name = _local_name(root.tag)
    if root_name == "urlset":
        entries, entry_warnings = _urlset_entries(root, normalized_url, normalized_scope)
    elif root_name == "sitemapindex":
        entries, entry_warnings = _sitemap_index_entries(root, normalized_url, normalized_scope)
    else:
        entries = []
        entry_warnings = [f"unsupported sitemap root {root_name!r}"]
    warnings.extend(entry_warnings)
    assets = sitemap_assets(entries)
    return SitemapParseReport(
        sitemap_url=normalized_url,
        scope_domains=normalized_scope,
        total_entries=len(entries),
        total_assets=len(assets),
        entries=entries,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def build_sitemap_import_bundle(reports: list[SitemapParseReport]) -> SitemapImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return SitemapImportBundle(
        report_count=len(reports),
        total_entries=sum(report.total_entries for report in reports),
        total_assets=len(assets),
        reports=reports,
        assets=assets,
        warnings=warnings,
    )


def sitemap_assets(entries: list[SitemapEntry]) -> list[Asset]:
    assets: list[Asset] = []
    for entry in entries:
        metadata = {
            "sitemap_entry_type": entry.entry_type,
            "source_sitemap": entry.source_sitemap,
        }
        if entry.lastmod:
            metadata["lastmod"] = entry.lastmod
        if entry.changefreq:
            metadata["changefreq"] = entry.changefreq
        if entry.priority:
            metadata["priority"] = entry.priority
        if entry.parameter_names:
            metadata["parameter_names"] = ",".join(entry.parameter_names)
            metadata["query_values_redacted"] = "true"
        assets.append(
            Asset(
                kind="url" if entry.entry_type == "sitemap" else _asset_kind(entry.url),
                value=entry.url,
                source="sitemap-import",
                parent=entry.source_sitemap,
                metadata=metadata,
            )
        )
    return _dedupe_assets(assets)


def _urlset_entries(
    root: ET.Element[str],
    source_sitemap: str,
    scope_domains: list[str],
) -> tuple[list[SitemapEntry], list[str]]:
    entries: list[SitemapEntry] = []
    warnings: list[str] = []
    for index, url_element in enumerate(_children(root, "url"), start=1):
        loc = _child_text(url_element, "loc")
        if loc is None:
            warnings.append(f"url entry {index}: missing loc")
            continue
        entry = _entry_from_loc(
            loc,
            entry_type="url",
            source_sitemap=source_sitemap,
            scope_domains=scope_domains,
            metadata_parent=url_element,
        )
        if isinstance(entry, str):
            warnings.append(f"url entry {index}: {entry}")
        elif entry is not None:
            entries.append(entry)
    return _dedupe_entries(entries), warnings


def _sitemap_index_entries(
    root: ET.Element[str],
    source_sitemap: str,
    scope_domains: list[str],
) -> tuple[list[SitemapEntry], list[str]]:
    entries: list[SitemapEntry] = []
    warnings: list[str] = []
    for index, sitemap_element in enumerate(_children(root, "sitemap"), start=1):
        loc = _child_text(sitemap_element, "loc")
        if loc is None:
            warnings.append(f"sitemap entry {index}: missing loc")
            continue
        entry = _entry_from_loc(
            loc,
            entry_type="sitemap",
            source_sitemap=source_sitemap,
            scope_domains=scope_domains,
            metadata_parent=sitemap_element,
        )
        if isinstance(entry, str):
            warnings.append(f"sitemap entry {index}: {entry}")
        elif entry is not None:
            entries.append(entry)
    return _dedupe_entries(entries), warnings


def _entry_from_loc(
    loc: str,
    *,
    entry_type: SitemapEntryType,
    source_sitemap: str,
    scope_domains: list[str],
    metadata_parent: ET.Element[str],
) -> SitemapEntry | str | None:
    sanitized = _sanitize_url(loc)
    if sanitized is None:
        return "invalid absolute http(s) URL"
    host = urlsplit(sanitized.url).hostname or ""
    if not _host_allowed(host, scope_domains):
        return f"skipped third-party host {host}"
    return SitemapEntry(
        url=sanitized.url,
        entry_type=entry_type,
        source_sitemap=source_sitemap,
        lastmod=_child_text(metadata_parent, "lastmod"),
        changefreq=_child_text(metadata_parent, "changefreq"),
        priority=_child_text(metadata_parent, "priority"),
        parameter_names=sanitized.parameter_names,
    )


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        host = normalize_host(parsed.hostname.lower()).host
    except NormalizationError:
        return None
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    port = f":{parsed.port}" if parsed.port is not None else ""
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
    )


def _effective_scope_domains(sitemap_url: str, scope_domains: list[str] | None) -> list[str]:
    normalized = _normalize_scope_domains(scope_domains or [])
    if normalized:
        return normalized
    sanitized = _sanitize_url(sitemap_url)
    if sanitized is None:
        raise ValueError("sitemap URL must be absolute http(s)")
    host = urlsplit(sanitized.url).hostname
    return [host] if host else []


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        if not candidate:
            continue
        try:
            host = normalize_host(candidate).host
        except NormalizationError as exc:
            raise ValueError(f"invalid scope domain: {value!r}") from exc
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return normalized


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _children(element: ET.Element[str], local_name: str) -> list[ET.Element[str]]:
    return [child for child in list(element) if _local_name(child.tag) == local_name]


def _child_text(element: ET.Element[str], local_name: str) -> str | None:
    for child in list(element):
        if _local_name(child.tag) == local_name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


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


def _dedupe_entries(entries: list[SitemapEntry]) -> list[SitemapEntry]:
    by_key = {(entry.url, entry.entry_type): entry for entry in entries}
    return sorted(by_key.values(), key=lambda entry: (entry.entry_type, entry.url))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
