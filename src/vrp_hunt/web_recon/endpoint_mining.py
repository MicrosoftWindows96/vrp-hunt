"""Offline JavaScript and API endpoint mining pipeline."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset
from vrp_hunt.web_recon.extractors import (
    extract_endpoint_paths,
    extract_javascript_urls,
    extract_parameter_names,
    extract_secret_notes,
)

ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>`{}\\]+", re.IGNORECASE)
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


class WebContentDocument(StrictModel):
    url: str = Field(min_length=1, max_length=4096)
    body: str = ""
    source: str = Field(default="offline-document", min_length=1, max_length=128)
    content_type: str | None = Field(default=None, max_length=128)

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("document url must be absolute http(s)")
        return _sanitize_url(value)


class EndpointMiningConfig(StrictModel):
    scope_domains: list[str] = Field(default_factory=list)
    include_third_party: bool = False
    include_secret_notes: bool = True

    @field_validator("scope_domains")
    @classmethod
    def normalize_scope_domains(cls, value: list[str]) -> list[str]:
        domains: set[str] = set()
        for raw_domain in value:
            candidate = raw_domain.strip().lower()
            if not candidate:
                continue
            if "://" in candidate:
                parsed = urlsplit(candidate)
                candidate = parsed.hostname or ""
            candidate = candidate.strip(".")
            if candidate:
                domains.add(candidate)
        return sorted(domains)


class EndpointMiningReport(StrictModel):
    generated_at: datetime
    document_count: int = Field(ge=0)
    document_urls: list[str] = Field(default_factory=list)
    total_assets: int = Field(ge=0)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def mine_javascript_and_api_endpoints(
    documents: list[WebContentDocument],
    *,
    config: EndpointMiningConfig | None = None,
    now: datetime | None = None,
) -> EndpointMiningReport:
    """Mine saved web content into scoped, redacted recon assets."""

    mining_config = config or EndpointMiningConfig()
    warnings: set[str] = set()
    assets: list[Asset] = []
    for document in documents:
        assets.extend(_mine_document(document, mining_config, warnings))
    deduped_assets = _dedupe_assets(assets)
    generated_at = now or datetime.now(UTC)
    return EndpointMiningReport(
        generated_at=generated_at,
        document_count=len(documents),
        document_urls=[document.url for document in documents],
        total_assets=len(deduped_assets),
        assets=deduped_assets,
        warnings=sorted(warnings),
    )


def _mine_document(
    document: WebContentDocument,
    config: EndpointMiningConfig,
    warnings: set[str],
) -> list[Asset]:
    assets: list[Asset] = []
    parent = _sanitize_url(document.url)

    for js_url in extract_javascript_urls(document.body, document.url):
        normalized = _sanitize_url(js_url)
        if _url_allowed(normalized, config, warnings):
            assets.append(
                Asset(
                    kind="javascript",
                    value=normalized,
                    source="endpoint-mine-script-src",
                    parent=parent,
                    metadata=_metadata_for_url(js_url, document),
                )
            )

    for absolute_url in _extract_absolute_urls(document.body):
        normalized = _sanitize_url(absolute_url)
        if not _url_allowed(normalized, config, warnings):
            continue
        if _is_javascript_url(normalized):
            assets.append(
                Asset(
                    kind="javascript",
                    value=normalized,
                    source="endpoint-mine-absolute-url",
                    parent=parent,
                    metadata=_metadata_for_url(absolute_url, document),
                )
            )
        elif _is_endpoint_url(normalized):
            assets.append(
                Asset(
                    kind="endpoint",
                    value=normalized,
                    source="endpoint-mine-absolute-url",
                    parent=parent,
                    metadata=_metadata_for_url(absolute_url, document),
                )
            )

    for endpoint_path in extract_endpoint_paths(document.body):
        if _looks_like_absolute_url_fragment(endpoint_path):
            continue
        absolute_url = urljoin(document.url, endpoint_path)
        normalized = _sanitize_url(absolute_url)
        if _url_allowed(normalized, config, warnings) and _is_endpoint_url(normalized):
            assets.append(
                Asset(
                    kind="endpoint",
                    value=normalized,
                    source="endpoint-mine-path",
                    parent=parent,
                    metadata=_metadata_for_url(absolute_url, document) | {"path": endpoint_path},
                )
            )

    for parameter_name in extract_parameter_names(document.url, document.body):
        assets.append(
            Asset(
                kind="parameter",
                value=parameter_name,
                source="endpoint-mine-parameter",
                parent=parent,
                metadata={"document_source": document.source},
            )
        )

    if config.include_secret_notes:
        assets.extend(extract_secret_notes(document.body, parent=parent, source="endpoint-mine-secret-scan"))

    return assets


def _extract_absolute_urls(text: str) -> list[str]:
    urls = {match.group(0).rstrip(").,;]") for match in ABSOLUTE_URL_RE.finditer(text)}
    return sorted(url for url in urls if urlsplit(url).hostname)


def _url_allowed(url: str, config: EndpointMiningConfig, warnings: set[str]) -> bool:
    if config.include_third_party or not config.scope_domains:
        return True
    host = urlsplit(url).hostname
    if host is not None and any(_host_in_domain(host, domain) for domain in config.scope_domains):
        return True
    if host:
        warnings.add(f"skipped third-party host {host}")
    return False


def _metadata_for_url(raw_url: str, document: WebContentDocument) -> dict[str, str]:
    metadata = {
        "document_url": document.url,
        "document_source": document.source,
    }
    parameter_names = extract_parameter_names(raw_url)
    if parameter_names:
        metadata["parameter_names"] = ",".join(parameter_names)
        metadata["query_values_redacted"] = "true"
    if document.content_type:
        metadata["content_type"] = document.content_type
    return metadata


def _sanitize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _is_javascript_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(extension) for extension in JAVASCRIPT_EXTENSIONS)


def _is_endpoint_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    if not path or path == "/":
        return False
    extension = _extension(path)
    return extension not in STATIC_EXTENSIONS and extension not in JAVASCRIPT_EXTENSIONS


def _looks_like_absolute_url_fragment(path: str) -> bool:
    first_segment = path.lstrip("/").split("/", 1)[0]
    return "." in first_segment


def _extension(path: str) -> str:
    last_segment = path.rsplit("/", 1)[-1]
    if "." not in last_segment:
        return ""
    return "." + last_segment.rsplit(".", 1)[-1]


def _host_in_domain(host: str, domain: str) -> bool:
    normalized_host = host.lower().strip(".")
    normalized_domain = domain.lower().strip(".")
    return normalized_host == normalized_domain or normalized_host.endswith(f".{normalized_domain}")


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_key: dict[tuple[str, str, str], Asset] = {}
    for asset in assets:
        key = (asset.kind, asset.value, asset.parent or "")
        by_key.setdefault(key, asset)
    return list(by_key.values())
